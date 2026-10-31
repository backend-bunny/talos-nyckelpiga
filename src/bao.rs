//! OpenBao client: authentication and the two transit calls.
//!
//! Plain `reqwest` against the HTTP API (see the wiki decision
//! `openbao-client-reqwest`). The token is kept fresh by [`Bao::maintain`]:
//! log in, renew at two thirds of the TTL, and log in again whenever renewal
//! fails. A request that gets 403 drops the token, logs in once more and
//! retries.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{Mutex, RwLock};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{AuthConfig, OpenBaoConfig, SYSTEM_CA_BUNDLE};
use crate::metrics::Metrics;

/// Upper bound for a transit plaintext or ciphertext accepted from a client.
/// Talos seals 32 bytes and stores ~90-byte ciphertexts in a LUKS2 header
/// whose JSON area is a few KiB.
pub const MAX_DATA_LEN: usize = 4096;

/// Why an OpenBao call failed. `Display` never includes request data or
/// response bodies beyond OpenBao's own error strings.
#[derive(Debug, thiserror::Error)]
pub enum BaoError {
    /// Unreachable, timed out, sealed, standby, rate-limited or 5xx: retrying
    /// later can succeed.
    #[error("openbao unavailable: {0}")]
    Unavailable(String),
    /// No valid token could be obtained.
    #[error("not authenticated to openbao: {0}")]
    Unauthenticated(String),
    /// 403 with a fresh token: the policy doesn't allow this key (or the key
    /// doesn't exist and encrypt would need `create`).
    #[error("openbao denied the request: {0}")]
    PermissionDenied(String),
    /// The node's transit key doesn't exist (deleted: the node is revoked).
    #[error("transit key not found")]
    KeyNotFound,
    /// OpenBao rejected the input (malformed ciphertext, authentication tag
    /// or associated data mismatch, ...).
    #[error("openbao rejected the request: {0}")]
    InvalidRequest(String),
    /// Anything else: unexpected status or response shape.
    #[error("openbao error: {0}")]
    Other(String),
}

impl BaoError {
    /// gRPC status code for this failure. Talos retries every failure the same
    /// way (every 30 s, see the wiki), so codes are for operators and logs.
    pub fn code(&self) -> tonic::Code {
        match self {
            BaoError::Unavailable(_) | BaoError::Unauthenticated(_) => tonic::Code::Unavailable,
            BaoError::PermissionDenied(_) => tonic::Code::PermissionDenied,
            BaoError::KeyNotFound => tonic::Code::NotFound,
            BaoError::InvalidRequest(_) => tonic::Code::InvalidArgument,
            BaoError::Other(_) => tonic::Code::Internal,
        }
    }

    fn from_response(status: StatusCode, body: &[u8]) -> Self {
        let message = error_message(body);
        match status {
            StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::GATEWAY_TIMEOUT
            | StatusCode::INTERNAL_SERVER_ERROR => {
                BaoError::Unavailable(format!("{status}: {message}"))
            }
            StatusCode::FORBIDDEN => BaoError::PermissionDenied(message),
            StatusCode::BAD_REQUEST if message.contains("encryption key not found") => {
                BaoError::KeyNotFound
            }
            StatusCode::BAD_REQUEST => BaoError::InvalidRequest(message),
            _ => BaoError::Other(format!("{status}: {message}")),
        }
    }

    fn from_transport(err: reqwest::Error) -> Self {
        // Strip the URL: it carries the key name, which is fine, but keep
        // messages uniform and short.
        BaoError::Unavailable(err.without_url().to_string())
    }
}

/// OpenBao's `{"errors": [...]}`, joined. Bodies are short and never contain
/// plaintext for the calls made here (errors carry no `data`).
fn error_message(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Errors {
        errors: Vec<String>,
    }
    match serde_json::from_slice::<Errors>(body) {
        Ok(e) if !e.errors.is_empty() => {
            let mut msg = e.errors.join("; ");
            msg.truncate(512);
            msg
        }
        _ => "no error message".into(),
    }
}

struct Token {
    secret: Zeroizing<String>,
    expires: Option<Instant>,
    renewable: bool,
    ttl: Duration,
}

pub struct Bao {
    http: reqwest::Client,
    config: OpenBaoConfig,
    token: RwLock<Option<Arc<Token>>>,
    /// Serialises logins so concurrent 403s don't stampede OpenBao.
    login_lock: Mutex<()>,
    metrics: Arc<Metrics>,
}

#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: Zeroizing<String>,
    lease_duration: u64,
    renewable: bool,
}

#[derive(Deserialize)]
struct LookupResponse {
    data: LookupData,
}

#[derive(Deserialize)]
struct LookupData {
    ttl: u64,
    renewable: Option<bool>,
}

impl Bao {
    pub fn new(config: OpenBaoConfig, metrics: Arc<Metrics>) -> anyhow::Result<Arc<Self>> {
        let ca_path = config
            .ca_cert
            .clone()
            .or_else(|| std::env::var_os("SSL_CERT_FILE").map(PathBuf::from))
            .unwrap_or_else(|| SYSTEM_CA_BUNDLE.into());
        let mut roots = rustls::RootCertStore::empty();
        if config.address.starts_with("https://") {
            let pem = std::fs::read(&ca_path)
                .with_context(|| format!("reading OpenBao CA bundle {}", ca_path.display()))?;
            let certs = crate::tls::parse_certs(&pem)
                .with_context(|| format!("parsing OpenBao CA bundle {}", ca_path.display()))?;
            let (added, _ignored) = roots.add_parsable_certificates(certs);
            if added == 0 {
                anyhow::bail!("no usable CA certificates in {}", ca_path.display());
            }
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .timeout(config.request_timeout())
            .connect_timeout(config.request_timeout())
            .user_agent(concat!("talos-nyckelpiga/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building OpenBao HTTP client")?;
        Ok(Arc::new(Self {
            http,
            config,
            token: RwLock::new(None),
            login_lock: Mutex::new(()),
            metrics,
        }))
    }

    pub fn config(&self) -> &OpenBaoConfig {
        &self.config
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.config.address.trim_end_matches('/'), path)
    }

    /// True while a token is held that hasn't expired.
    pub async fn is_authenticated(&self) -> bool {
        match self.token.read().await.as_ref() {
            Some(t) => t.expires.is_none_or(|e| e > Instant::now()),
            None => false,
        }
    }

    async fn set_token(&self, token: Option<Token>) {
        self.metrics
            .openbao_authenticated
            .set(i64::from(token.is_some()));
        *self.token.write().await = token.map(Arc::new);
    }

    /// Obtain a token with the configured method and store it.
    pub async fn login(&self) -> Result<(), BaoError> {
        let result = self.do_login().await;
        let label = if result.is_ok() { "ok" } else { "error" };
        self.metrics
            .openbao_auth
            .with_label_values(&["login", label])
            .inc();
        match result {
            Ok(token) => {
                tracing::info!(
                    ttl_secs = token.ttl.as_secs(),
                    renewable = token.renewable,
                    "logged in to openbao"
                );
                self.set_token(Some(token)).await;
                Ok(())
            }
            Err(err) => {
                self.set_token(None).await;
                Err(err)
            }
        }
    }

    async fn do_login(&self) -> Result<Token, BaoError> {
        match &self.config.auth {
            AuthConfig::Kubernetes {
                mount,
                role,
                token_path,
            } => {
                let jwt = read_secret_file(token_path).await?;
                let body = json!({ "role": role, "jwt": jwt.as_str() });
                let resp = self
                    .http
                    .post(self.url(&format!("auth/{mount}/login")))
                    .header(CONTENT_TYPE, "application/json")
                    .body(to_body(&body))
                    .send()
                    .await
                    .map_err(BaoError::from_transport)?;
                drop(body);
                let auth: AuthResponse = parse_json(resp).await.map_err(|e| match e {
                    // A rejected JWT or role is an auth failure; keep retrying.
                    BaoError::PermissionDenied(m) | BaoError::InvalidRequest(m) => {
                        BaoError::Unauthenticated(m)
                    }
                    other => other,
                })?;
                let ttl = Duration::from_secs(auth.auth.lease_duration);
                Ok(Token {
                    secret: auth.auth.client_token,
                    expires: (auth.auth.lease_duration > 0).then(|| Instant::now() + ttl),
                    renewable: auth.auth.renewable,
                    ttl,
                })
            }
            AuthConfig::Token { token_path } => {
                let secret = read_secret_file(token_path).await?;
                let resp = self
                    .http
                    .get(self.url("auth/token/lookup-self"))
                    .header("X-Vault-Token", secret.as_str())
                    .send()
                    .await
                    .map_err(BaoError::from_transport)?;
                let lookup: LookupResponse = parse_json(resp).await.map_err(|e| match e {
                    BaoError::PermissionDenied(m) => BaoError::Unauthenticated(m),
                    other => other,
                })?;
                let ttl = Duration::from_secs(lookup.data.ttl);
                Ok(Token {
                    secret,
                    expires: (lookup.data.ttl > 0).then(|| Instant::now() + ttl),
                    renewable: lookup.data.renewable.unwrap_or(false),
                    ttl,
                })
            }
        }
    }

    /// Renew the current token. On success the expiry moves forward.
    async fn renew(&self) -> Result<(), BaoError> {
        let Some(token) = self.token.read().await.clone() else {
            return Err(BaoError::Unauthenticated("no token".into()));
        };
        let result: Result<AuthResponse, BaoError> = async {
            let resp = self
                .http
                .post(self.url("auth/token/renew-self"))
                .header("X-Vault-Token", token.secret.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body(to_body(&json!({})))
                .send()
                .await
                .map_err(BaoError::from_transport)?;
            parse_json(resp).await
        }
        .await;
        let label = if result.is_ok() { "ok" } else { "error" };
        self.metrics
            .openbao_auth
            .with_label_values(&["renew", label])
            .inc();
        let auth = result?.auth;
        let ttl = Duration::from_secs(auth.lease_duration);
        tracing::debug!(ttl_secs = ttl.as_secs(), "renewed openbao token");
        self.set_token(Some(Token {
            secret: auth.client_token,
            expires: (auth.lease_duration > 0).then(|| Instant::now() + ttl),
            renewable: auth.renewable,
            ttl,
        }))
        .await;
        Ok(())
    }

    /// Keep a valid token, forever: log in with backoff until it works, then
    /// renew at two thirds of the TTL, falling back to a fresh login.
    pub async fn maintain(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let token = self.token.read().await.clone();
            let Some(token) = token else {
                let _guard = self.login_lock.lock().await;
                if self.token.read().await.is_some() {
                    continue;
                }
                match self.login().await {
                    Ok(()) => backoff = Duration::from_secs(1),
                    Err(err) => {
                        tracing::warn!(error = %err, retry_in_secs = backoff.as_secs(), "openbao login failed");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                    }
                }
                continue;
            };
            let Some(expires) = token.expires else {
                // Non-expiring token: check it is still valid now and then.
                tokio::time::sleep(Duration::from_secs(300)).await;
                continue;
            };
            let wait = token.ttl.mul_f64(2.0 / 3.0).max(Duration::from_secs(1));
            tokio::time::sleep(wait.min(expires.saturating_duration_since(Instant::now()))).await;
            if !self.is_same_token(&token).await {
                continue; // replaced meanwhile (403 re-login)
            }
            let renewed = if token.renewable {
                self.renew().await
            } else {
                Err(BaoError::Unauthenticated("token not renewable".into()))
            };
            if let Err(err) = renewed {
                tracing::info!(error = %err, "openbao token renewal failed; logging in again");
                let _guard = self.login_lock.lock().await;
                if self.is_same_token(&token).await
                    && let Err(err) = self.login().await
                {
                    tracing::warn!(error = %err, "openbao login failed");
                }
            }
        }
    }

    async fn is_same_token(&self, token: &Arc<Token>) -> bool {
        self.token
            .read()
            .await
            .as_ref()
            .is_some_and(|t| Arc::ptr_eq(t, token))
    }

    async fn current_token(&self) -> Result<Arc<Token>, BaoError> {
        if let Some(t) = self.token.read().await.clone() {
            return Ok(t);
        }
        Err(BaoError::Unauthenticated(
            "no openbao token (login pending)".into(),
        ))
    }

    /// Replace a token OpenBao rejected, unless another task already did.
    async fn relogin(&self, rejected: &Arc<Token>) -> Result<(), BaoError> {
        let _guard = self.login_lock.lock().await;
        if !self.is_same_token(rejected).await && self.token.read().await.is_some() {
            return Ok(());
        }
        self.login().await
    }

    /// POST `body` to a transit path with the current token; on 403 log in
    /// again and retry once.
    async fn transit_post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, BaoError> {
        let url = self.url(&format!("{}/{}", self.config.transit_mount, path));
        let mut retried = false;
        loop {
            let token = self.current_token().await?;
            let resp = self
                .http
                .post(&url)
                .header("X-Vault-Token", token.secret.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body(to_body(body))
                .send()
                .await
                .map_err(BaoError::from_transport)?;
            match parse_json(resp).await {
                Err(BaoError::PermissionDenied(msg)) if !retried => {
                    tracing::info!(error = %msg, "openbao returned 403; logging in again");
                    retried = true;
                    self.relogin(&token).await?;
                }
                other => return other,
            }
        }
    }

    /// Transit encrypt: returns OpenBao's ciphertext string (`vault:vN:...`).
    pub async fn encrypt(
        &self,
        key: &str,
        node_uuid: &str,
        plaintext: &[u8],
    ) -> Result<String, BaoError> {
        #[derive(Deserialize)]
        struct Resp {
            data: Data,
        }
        #[derive(Deserialize)]
        struct Data {
            ciphertext: String,
        }
        let mut body = json!({ "plaintext": B64.encode(plaintext) });
        if self.config.associated_data {
            body["associated_data"] = B64.encode(node_uuid).into();
        }
        let result = self
            .transit_post::<Resp>(&format!("encrypt/{key}"), &body)
            .await;
        wipe_json(&mut body);
        Ok(result?.data.ciphertext)
    }

    /// Transit decrypt: returns the plaintext, wiped on drop.
    pub async fn decrypt(
        &self,
        key: &str,
        node_uuid: &str,
        ciphertext: &str,
    ) -> Result<Zeroizing<Vec<u8>>, BaoError> {
        #[derive(Deserialize)]
        struct Resp {
            data: Data,
        }
        #[derive(Deserialize)]
        struct Data {
            plaintext: Zeroizing<String>,
        }
        let mut body = json!({ "ciphertext": ciphertext });
        if self.config.associated_data {
            body["associated_data"] = B64.encode(node_uuid).into();
        }
        let resp = self
            .transit_post::<Resp>(&format!("decrypt/{key}"), &body)
            .await?;
        let mut plaintext = Zeroizing::new(Vec::new());
        B64.decode_vec(resp.data.plaintext.as_bytes(), &mut plaintext)
            .map_err(|_| BaoError::Other("transit returned plaintext that is not base64".into()))?;
        Ok(plaintext)
    }
}

/// Serialise a request body (reqwest's `json` feature is not enabled).
fn to_body(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("a serde_json::Value always serialises")
}

/// Overwrite string values in a request body we built (best effort: reqwest
/// serialises into its own buffer, which we can't reach).
fn wipe_json(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        for v in map.values_mut() {
            if let serde_json::Value::String(s) = v {
                s.zeroize();
            }
        }
    }
}

async fn read_secret_file(path: &std::path::Path) -> Result<Zeroizing<String>, BaoError> {
    let bytes = Zeroizing::new(
        tokio::fs::read(path)
            .await
            .map_err(|e| BaoError::Unauthenticated(format!("reading {}: {e}", path.display())))?,
    );
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| BaoError::Unauthenticated(format!("{} is not UTF-8", path.display())))?;
    Ok(Zeroizing::new(s.trim().to_owned()))
}

/// Read a response: JSON body on 2xx, a [`BaoError`] otherwise. The body
/// buffer is wiped after parsing (it may hold a plaintext or a token).
async fn parse_json<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T, BaoError> {
    let status = resp.status();
    let body = Zeroizing::new(
        resp.bytes()
            .await
            .map_err(BaoError::from_transport)?
            .to_vec(),
    );
    if !status.is_success() {
        return Err(BaoError::from_response(status, &body));
    }
    serde_json::from_slice(&body).map_err(|e| BaoError::Other(format!("unexpected response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(status: u16, body: &str) -> BaoError {
        BaoError::from_response(StatusCode::from_u16(status).unwrap(), body.as_bytes())
    }

    #[test]
    fn maps_openbao_errors_to_grpc_codes() {
        use tonic::Code;
        let cases = [
            (503, r#"{"errors":["Vault is sealed"]}"#, Code::Unavailable),
            (429, r#"{"errors":["rate limited"]}"#, Code::Unavailable),
            (500, r#"{"errors":["internal error"]}"#, Code::Unavailable),
            (502, "<html>bad gateway</html>", Code::Unavailable),
            (
                403,
                r#"{"errors":["permission denied"]}"#,
                Code::PermissionDenied,
            ),
            (
                400,
                r#"{"errors":["encryption key not found"]}"#,
                Code::NotFound,
            ),
            (
                400,
                r#"{"errors":["cipher: message authentication failed"]}"#,
                Code::InvalidArgument,
            ),
            (
                400,
                r#"{"errors":["refusing to use soft-deleted key"]}"#,
                Code::InvalidArgument,
            ),
            (404, r#"{"errors":[]}"#, Code::Internal),
        ];
        for (status, body, code) in cases {
            assert_eq!(err(status, body).code(), code, "{status} {body}");
        }
        assert!(matches!(
            err(400, r#"{"errors":["encryption key not found"]}"#),
            BaoError::KeyNotFound
        ));
        assert_eq!(
            err(503, r#"{"errors":["Vault is sealed"]}"#).to_string(),
            "openbao unavailable: 503 Service Unavailable: Vault is sealed"
        );
        assert_eq!(
            err(502, "<html>").to_string(),
            "openbao unavailable: 502 Bad Gateway: no error message"
        );
        assert_eq!(
            BaoError::Unauthenticated("x".into()).code(),
            Code::Unavailable
        );
    }

    #[test]
    fn wipe_json_clears_strings() {
        let mut v = json!({ "plaintext": "c2VjcmV0", "n": 1 });
        wipe_json(&mut v);
        assert!(v["plaintext"].as_str().unwrap().is_empty());
    }
}
