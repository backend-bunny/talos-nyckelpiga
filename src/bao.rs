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
use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

use crate::config::{AuthConfig, OpenBaoConfig, SYSTEM_CA_BUNDLE};
use crate::metrics::Metrics;
use crate::watch::FileWatch;

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
    http: ArcSwap<reqwest::Client>,
    ca_watch: Option<CaWatch>,
    config: OpenBaoConfig,
    token: RwLock<Option<Arc<Token>>>,
    /// Serialises logins so concurrent 403s don't stampede OpenBao.
    login_lock: Mutex<()>,
    metrics: Arc<Metrics>,
}

struct CaWatch {
    path: PathBuf,
    files: std::sync::Mutex<FileWatch>,
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

// Borrow secrets from Zeroizing owners: constructing JSON values would make
// ordinary String copies that survive cancellation without being wiped.
#[derive(Serialize)]
struct LoginRequest<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Serialize)]
struct TransitRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<String>,
}

impl Bao {
    pub fn new(config: OpenBaoConfig, metrics: Arc<Metrics>) -> anyhow::Result<Arc<Self>> {
        if config.address.starts_with("http://") {
            // Never print the URL: it could contain credentials or query data.
            tracing::warn!(
                "SECURITY WARNING: OpenBao uses unencrypted HTTP; credentials and key material are exposed to anyone who can observe or modify this network traffic; use HTTPS or a trusted encrypted transport"
            );
        }
        let (http, ca_watch) = if config.address.starts_with("https://") {
            let path = config
                .ca_cert
                .clone()
                .or_else(|| std::env::var_os("SSL_CERT_FILE").map(PathBuf::from))
                .unwrap_or_else(|| SYSTEM_CA_BUNDLE.into());
            let mut files = FileWatch::new(vec![path.clone()]);
            let contents = files.read()?;
            let http = build_http(&config, Some(&contents[0]))
                .with_context(|| format!("loading OpenBao CA bundle {}", path.display()))?;
            (
                http,
                Some(CaWatch {
                    path,
                    files: std::sync::Mutex::new(files),
                }),
            )
        } else {
            (build_http(&config, None)?, None)
        };
        Ok(Arc::new(Self {
            http: ArcSwap::from_pointee(http),
            ca_watch,
            config,
            token: RwLock::new(None),
            login_lock: Mutex::new(()),
            metrics,
        }))
    }

    pub fn config(&self) -> &OpenBaoConfig {
        &self.config
    }

    /// Reopen the original path on every tick: Kubernetes replaces ..data,
    /// not the mounted file's inode. Invalid updates keep the previous client.
    fn reload_ca(&self) {
        let Some(ca) = &self.ca_watch else { return };
        let mut files = ca.files.lock().unwrap();
        let result = files.read_if_changed().and_then(|contents| {
            contents
                .map(|contents| build_http(&self.config, Some(&contents[0])))
                .transpose()
        });
        match result {
            Ok(None) => {}
            Ok(Some(http)) => {
                // Replace the pool too: subsequent requests must not reuse a
                // connection/session authenticated by a removed root. Existing
                // in-flight requests retain their snapshot until they finish.
                self.http.store(Arc::new(http));
                self.metrics
                    .openbao_ca_reloads
                    .with_label_values(&["ok"])
                    .inc();
                tracing::info!(ca = %ca.path.display(), "openbao ca bundle reloaded");
            }
            Err(error) => {
                files.invalidate();
                self.metrics
                    .openbao_ca_reloads
                    .with_label_values(&["error"])
                    .inc();
                tracing::error!(ca = %ca.path.display(), error = %format!("{error:#}"),
                    "openbao ca reload failed; keeping previous trust store");
            }
        }
    }

    pub async fn watch_ca(self: Arc<Self>, interval: Duration) {
        if self.ca_watch.is_none() {
            return;
        }
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let this = self.clone();
            let _ = tokio::task::spawn_blocking(move || this.reload_ca()).await;
        }
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
                let body = LoginRequest { role, jwt: &jwt };
                let resp = self
                    .http
                    .load_full()
                    .post(self.url(&format!("auth/{mount}/login")))
                    .header(CONTENT_TYPE, "application/json")
                    .body(to_body(&body))
                    .send()
                    .await
                    .map_err(BaoError::from_transport)?;
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
                    .load_full()
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
                .load_full()
                .post(self.url("auth/token/renew-self"))
                .header("X-Vault-Token", token.secret.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body("{}")
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
        body: &TransitRequest<'_>,
    ) -> Result<T, BaoError> {
        let url = self.url(&format!("{}/{}", self.config.transit_mount, path));
        let mut retried = false;
        loop {
            let token = self.current_token().await?;
            let resp = self
                .http
                .load_full()
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
        let plaintext = Zeroizing::new(B64.encode(plaintext));
        let body = TransitRequest {
            plaintext: Some(&plaintext),
            ciphertext: None,
            associated_data: self.config.associated_data.then(|| B64.encode(node_uuid)),
        };
        let resp = self
            .transit_post::<Resp>(&format!("encrypt/{key}"), &body)
            .await?;
        Ok(resp.data.ciphertext)
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
        let body = TransitRequest {
            plaintext: None,
            ciphertext: Some(ciphertext),
            associated_data: self.config.associated_data.then(|| B64.encode(node_uuid)),
        };
        let resp = self
            .transit_post::<Resp>(&format!("decrypt/{key}"), &body)
            .await?;
        let mut plaintext = Zeroizing::new(Vec::new());
        B64.decode_vec(resp.data.plaintext.as_bytes(), &mut plaintext)
            .map_err(|_| BaoError::Other("transit returned plaintext that is not base64".into()))?;
        Ok(plaintext)
    }
}

/// Build completely before publication. Every root must parse; a partly broken
/// bundle must not silently remove trust. Multiple PEM blocks allow CA overlap.
fn build_http(config: &OpenBaoConfig, pem: Option<&[u8]>) -> anyhow::Result<reqwest::Client> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(pem) = pem {
        for cert in crate::tls::parse_certs(pem).context("parsing OpenBao CA bundle")? {
            roots
                .add(cert)
                .context("invalid certificate in OpenBao CA bundle")?;
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        // Applies equally to initial clients and clients built after reload.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.request_timeout())
        .connect_timeout(config.request_timeout())
        .user_agent(concat!("talos-nyckelpiga/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building OpenBao HTTP client")
}

/// Serialise a request body (reqwest's `json` feature is not enabled).
fn to_body(value: &impl Serialize) -> Vec<u8> {
    // Ownership of this serialized copy passes to reqwest; our borrowed
    // inputs remain in Zeroizing buffers even if the request is cancelled.
    serde_json::to_vec(value).expect("OpenBao request fields always serialise")
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
    if status.is_redirection() {
        // Do not read/log the Location or body: either may contain secrets.
        return Err(BaoError::Unavailable(
            "redirect refused; configure a directly reachable OpenBao endpoint".into(),
        ));
    }
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
mod ca_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(address: String, token_path: PathBuf) -> OpenBaoConfig {
        OpenBaoConfig {
            address,
            ca_cert: None,
            transit_mount: "transit".into(),
            key_template: "node-{uuid}".into(),
            associated_data: true,
            request_timeout_secs: 2,
            auth: AuthConfig::Token { token_path },
        }
    }

    #[test]
    fn plain_http_warns_without_logging_the_url() {
        #[derive(Clone)]
        struct Log(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Log {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let log = Log(Arc::new(std::sync::Mutex::new(Vec::new())));
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            Bao::new(
                test_config(
                    "http://secret-user:secret-password@localhost:8200/?secret-query".into(),
                    "unused".into(),
                ),
                Arc::new(Metrics::new()),
            )
            .unwrap();
        });
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("WARN"));
        assert!(text.contains("SECURITY WARNING"));
        assert!(text.contains("unencrypted HTTP"));
        assert!(!text.contains("secret-"));
    }

    #[tokio::test]
    async fn redirects_never_receive_authentication_or_transit_requests() {
        use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let location = format!(
            "http://{}/synthetic-redirect-secret",
            destination.local_addr().unwrap()
        );
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let destination_app = axum::Router::new().fallback(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { "{}" }
        });
        let destination_task =
            tokio::spawn(async move { axum::serve(destination, destination_app).await.unwrap() });
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", origin.local_addr().unwrap());
        let code = Arc::new(AtomicU16::new(307));
        let response_code = code.clone();
        let origin_app = axum::Router::new().fallback(move || {
            let location = location.clone();
            let code = response_code.load(Ordering::SeqCst);
            async move {
                (
                    StatusCode::from_u16(code).unwrap(),
                    [("location", location)],
                    "{\"errors\":[\"synthetic-redirect-secret\"]}",
                )
            }
        });
        let origin_task =
            tokio::spawn(async move { axum::serve(origin, origin_app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let secret_file = dir.path().join("secret");
        std::fs::write(&secret_file, "synthetic-auth-secret").unwrap();
        let config = test_config(address, secret_file.clone());
        let client = Bao::new(config.clone(), Arc::new(Metrics::new())).unwrap();
        let mut k8s_config = config;
        k8s_config.auth = AuthConfig::Kubernetes {
            mount: "kubernetes".into(),
            role: "kms".into(),
            token_path: secret_file,
        };
        let k8s = Bao::new(k8s_config, Arc::new(Metrics::new())).unwrap();
        for status in [301, 302, 303, 307, 308] {
            code.store(status, Ordering::SeqCst);
            let login = client.login().await.unwrap_err();
            let kubernetes = k8s.login().await.unwrap_err();
            client
                .set_token(Some(Token {
                    secret: Zeroizing::new("synthetic-auth-secret".into()),
                    expires: None,
                    renewable: false,
                    ttl: Duration::ZERO,
                }))
                .await;
            let encrypt = client
                .encrypt("node", "uuid", b"synthetic-plaintext")
                .await
                .unwrap_err();
            let decrypt = client
                .decrypt("node", "uuid", "vault:v1:synthetic")
                .await
                .unwrap_err();
            let renew = client.renew().await.unwrap_err();
            for error in [login, kubernetes, encrypt, decrypt, renew] {
                assert_eq!(error.code(), tonic::Code::Unavailable);
                assert!(error.to_string().contains("redirect refused"));
                assert!(!error.to_string().contains("synthetic-"));
            }
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        origin_task.abort();
        destination_task.abort();
    }

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
}
