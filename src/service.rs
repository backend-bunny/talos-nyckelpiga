//! The `sidero.kms.KMSService` implementation.
//!
//! Every call is checked against the allowlist *before* any OpenBao request,
//! then mapped to transit on the node's own key. Each call emits one audit
//! event (target `audit`) with node UUID, label, peer, result and latency.
//! Request data, plaintexts and ciphertexts are never logged.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Semaphore;
use tonic::{Code, Request, Response, Status};
use zeroize::Zeroizing;

use crate::allowlist::{Node, Refusal, SharedAllowlist};
use crate::bao::{Bao, BaoError, MAX_DATA_LEN};
use crate::metrics::Metrics;
use crate::proto::kms_service_server::KmsService;
use crate::proto::{Request as KmsRequest, Response as KmsResponse};
use crate::tls::PeerAddr;

/// Bound transit work globally, across all gRPC connections. Excess requests
/// fail immediately instead of building a queue of plaintext-bearing futures.
const MAX_ACTIVE_REQUESTS: usize = 32;
/// 4 KiB data + a 36-byte UUID + protobuf tags/lengths and a little headroom.
pub(crate) const MAX_MESSAGE_LEN: usize = MAX_DATA_LEN + 64;

/// Talos seals a 32-byte random key (internal/pkg/encryption/keys/kms.go).
/// Other sizes are accepted (the protocol doesn't fix one) up to MAX_DATA_LEN.
pub struct KmsServer {
    allowlist: Arc<SharedAllowlist>,
    bao: Arc<Bao>,
    metrics: Arc<Metrics>,
    requests: Semaphore,
}

#[derive(Clone, Copy)]
enum Op {
    Seal,
    Unseal,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Seal => "seal",
            Op::Unseal => "unseal",
        }
    }
}

/// Outcome of one call, before it is turned into a gRPC response.
enum Failure {
    Refused(Refusal),
    BadRequest(&'static str),
    Bao(BaoError),
    Overloaded,
}

impl Failure {
    fn status(&self) -> Status {
        match self {
            Failure::Refused(Refusal::InvalidUuid) => {
                Status::invalid_argument("node_uuid is not a valid UUID")
            }
            Failure::Refused(Refusal::NotAllowed { .. }) => {
                Status::permission_denied("node is not allowed")
            }
            Failure::BadRequest(msg) => Status::invalid_argument(*msg),
            Failure::Bao(err) => Status::new(err.code(), err.to_string()),
            Failure::Overloaded => Status::resource_exhausted("too many active KMS requests"),
        }
    }
}

impl KmsServer {
    pub fn new(allowlist: Arc<SharedAllowlist>, bao: Arc<Bao>, metrics: Arc<Metrics>) -> Self {
        Self {
            allowlist,
            bao,
            metrics,
            requests: Semaphore::new(MAX_ACTIVE_REQUESTS),
        }
    }

    async fn handle(
        &self,
        op: Op,
        request: Request<KmsRequest>,
    ) -> Result<Response<KmsResponse>, Status> {
        let start = Instant::now();
        let peer = request
            .extensions()
            .get::<PeerAddr>()
            .map(|p| p.0.to_string())
            .or_else(|| request.remote_addr().map(|a| a.to_string()))
            .unwrap_or_else(|| "unknown".into());
        let KmsRequest { node_uuid, data } = request.into_inner();
        let mut data = Zeroizing::new(data);
        let mut node: Option<Node> = None;
        let result = self.process(op, &node_uuid, &mut data, &mut node).await;
        drop(data);

        let elapsed = start.elapsed();
        let (result_label, status) = match &result {
            Ok(_) => ("ok", None),
            Err(f) => {
                let status = f.status();
                (code_label(status.code()), Some(status))
            }
        };
        self.metrics
            .requests
            .with_label_values(&[op.as_str(), result_label])
            .inc();
        self.metrics
            .latency
            .with_label_values(&[op.as_str()])
            .observe(elapsed.as_secs_f64());

        // The UUID as received is logged only when it parsed (canonical form):
        // arbitrary client strings don't go into the audit log verbatim.
        let uuid = node.as_ref().map(|n| n.uuid.as_str()).or(match &result {
            Err(Failure::Refused(Refusal::NotAllowed { uuid })) => Some(uuid.as_str()),
            _ => None,
        });
        let label = node.as_ref().and_then(|n| n.label.as_deref());
        let latency_ms = elapsed.as_secs_f64() * 1000.0;
        match &result {
            Ok(_) => tracing::info!(
                target: "audit", op = op.as_str(), node_uuid = uuid, node_label = label, peer,
                result = result_label, latency_ms, "kms request"
            ),
            Err(f) => {
                let reason = match f {
                    Failure::Refused(r) => r.to_string(),
                    Failure::BadRequest(m) => (*m).to_owned(),
                    Failure::Bao(e) => e.to_string(),
                    Failure::Overloaded => "too many active KMS requests".into(),
                };
                tracing::warn!(
                    target: "audit", op = op.as_str(), node_uuid = uuid, node_label = label, peer,
                    result = result_label, latency_ms, reason, "kms request failed"
                );
            }
        }

        match result {
            Ok(data) => Ok(Response::new(KmsResponse {
                data: data.to_vec(),
            })),
            Err(_) => Err(status.expect("set for every failure")),
        }
    }

    async fn process(
        &self,
        op: Op,
        node_uuid: &str,
        data: &mut [u8],
        node_out: &mut Option<Node>,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        // Allowlist first: an unknown node never causes an OpenBao request.
        let node = self
            .allowlist
            .get()
            .check(node_uuid)
            .map_err(Failure::Refused)?;
        *node_out = Some(node.clone());
        if data.is_empty() {
            return Err(Failure::BadRequest("data is empty"));
        }
        if data.len() > MAX_DATA_LEN {
            return Err(Failure::BadRequest("data is too large"));
        }
        let _permit = self
            .requests
            .try_acquire()
            .map_err(|_| Failure::Overloaded)?;
        let key = self.bao.config().key_name(&node.uuid);
        match op {
            Op::Seal => {
                let ciphertext = self
                    .bao
                    .encrypt(&key, &node.uuid, data)
                    .await
                    .map_err(Failure::Bao)?;
                // Returned verbatim (`vault:vN:...`): transit can rotate the
                // key and still decrypt, and rewrap needs nothing from Talos.
                Ok(Zeroizing::new(ciphertext.into_bytes()))
            }
            Op::Unseal => {
                let ciphertext = std::str::from_utf8(data)
                    .ok()
                    .filter(|c| c.starts_with("vault:v") && c.is_ascii())
                    .ok_or(Failure::BadRequest("data is not a transit ciphertext"))?;
                self.bao
                    .decrypt(&key, &node.uuid, ciphertext)
                    .await
                    .map_err(Failure::Bao)
            }
        }
    }
}

fn code_label(code: Code) -> &'static str {
    match code {
        Code::InvalidArgument => "invalid_argument",
        Code::PermissionDenied => "permission_denied",
        Code::NotFound => "not_found",
        Code::Unavailable => "unavailable",
        Code::Internal => "internal",
        Code::ResourceExhausted => "resource_exhausted",
        _ => "other",
    }
}

#[tonic::async_trait]
impl KmsService for KmsServer {
    async fn seal(&self, request: Request<KmsRequest>) -> Result<Response<KmsResponse>, Status> {
        self.handle(Op::Seal, request).await
    }

    async fn unseal(&self, request: Request<KmsRequest>) -> Result<Response<KmsResponse>, Status> {
        self.handle(Op::Unseal, request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, OpenBaoConfig};
    use std::time::Duration;

    #[tokio::test]
    async fn cancelling_transit_releases_global_capacity_and_unknown_nodes_still_fail_first() {
        const UUID: &str = "4c4c4544-0042-3510-8051-b4c04f4e3732";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let received = Arc::new(tokio::sync::Notify::new());
        let notify = received.clone();
        let app = axum::Router::new()
            .route(
                "/v1/auth/token/lookup-self",
                axum::routing::get(|| async { "{\"data\":{\"ttl\":3600,\"renewable\":false}}" }),
            )
            .fallback(move || {
                let notify = notify.clone();
                async move {
                    notify.notify_one();
                    std::future::pending::<&'static str>().await
                }
            });
        let backend = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, "synthetic-token").unwrap();
        let allowlist_path = dir.path().join("allowlist.toml");
        std::fs::write(&allowlist_path, format!("[[node]]\nuuid = \"{UUID}\"\n")).unwrap();
        let metrics = Arc::new(Metrics::new());
        let bao = Bao::new(
            OpenBaoConfig {
                address,
                ca_cert: None,
                transit_mount: "transit".into(),
                key_template: "node-{uuid}".into(),
                associated_data: true,
                request_timeout_secs: 5,
                auth: AuthConfig::Token { token_path },
            },
            metrics.clone(),
        )
        .unwrap();
        bao.login().await.unwrap();
        let mut kms = KmsServer::new(
            SharedAllowlist::load(&allowlist_path).unwrap(),
            bao,
            metrics,
        );
        kms.requests = Semaphore::new(1);
        let request = |uuid: &str| {
            Request::new(KmsRequest {
                node_uuid: uuid.into(),
                data: vec![7; 32],
            })
        };
        let mut first = Box::pin(kms.seal(request(UUID)));
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = &mut first => panic!("transit unexpectedly finished"),
                _ = received.notified() => {}
            }
        })
        .await
        .unwrap();
        assert_eq!(
            kms.seal(request(UUID)).await.unwrap_err().code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            kms.seal(request("00000000-0000-0000-0000-000000000001"))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        // Dropping the in-flight RPC releases its permit and Zeroizing
        // plaintext owners, even while the HTTP response is still pending.
        drop(first);
        assert_eq!(kms.requests.available_permits(), 1);
        let mut next = Box::pin(kms.seal(request(UUID)));
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = &mut next => panic!("capacity not reusable after cancellation"),
                _ = received.notified() => {}
            }
        })
        .await
        .unwrap();
        drop(next);
        backend.abort();
    }
}
