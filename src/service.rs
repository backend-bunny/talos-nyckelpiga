//! The `sidero.kms.KMSService` implementation.
//!
//! Every call is checked against the allowlist *before* any OpenBao request,
//! then mapped to transit on the node's own key. Each call emits one audit
//! event (target `audit`) with node UUID, label, peer, result and latency.
//! Request data, plaintexts and ciphertexts are never logged.

use std::sync::Arc;
use std::time::Instant;

use tonic::{Code, Request, Response, Status};
use zeroize::{Zeroize, Zeroizing};

use crate::allowlist::{Node, Refusal, SharedAllowlist};
use crate::bao::{Bao, BaoError, MAX_DATA_LEN};
use crate::metrics::Metrics;
use crate::proto::kms_service_server::KmsService;
use crate::proto::{Request as KmsRequest, Response as KmsResponse};
use crate::tls::PeerAddr;

/// Talos seals a 32-byte random key (internal/pkg/encryption/keys/kms.go).
/// Other sizes are accepted (the protocol doesn't fix one) up to MAX_DATA_LEN.
pub struct KmsServer {
    allowlist: Arc<SharedAllowlist>,
    bao: Arc<Bao>,
    metrics: Arc<Metrics>,
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
        }
    }
}

impl KmsServer {
    pub fn new(allowlist: Arc<SharedAllowlist>, bao: Arc<Bao>, metrics: Arc<Metrics>) -> Self {
        Self {
            allowlist,
            bao,
            metrics,
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
        let mut req = request.into_inner();
        let mut node: Option<Node> = None;
        let result = self
            .process(op, &req.node_uuid, &mut req.data, &mut node)
            .await;
        req.data.zeroize();

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
