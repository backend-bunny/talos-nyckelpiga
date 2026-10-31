//! End-to-end test: a real `bao server -dev`, the server over TLS, and a
//! tonic gRPC client speaking the Talos KMS protocol.
//!
//! Needs `bao` on PATH (devbox provides it). Without it the test is skipped,
//! unless NYCKELPIGA_REQUIRE_BAO=1 (set by CI and `task test`), which turns a
//! missing binary into a failure.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use talos_nyckelpiga::config::Config;
use talos_nyckelpiga::proto::Request;
use talos_nyckelpiga::proto::kms_service_client::KmsServiceClient;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tonic::Code;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

const ROOT_TOKEN: &str = "root";
const NODE_A: &str = "4c4c4544-0042-3510-8051-b4c04f4e3732";
const NODE_B: &str = "4c4c4544-0042-3510-8051-b4c04f4e3733";
/// Allowlisted, but no transit key exists for it.
const NODE_NO_KEY: &str = "4c4c4544-0042-3510-8051-b4c04f4e3734";
const NODE_UNKNOWN: &str = "00000000-0000-0000-0000-00000000dead";

fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn bao_available() -> bool {
    std::process::Command::new("bao")
        .arg("version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

struct DevBao {
    child: Child,
    /// HOME for bao: `-dev` writes ~/.vault-token, which must not be the user's.
    home: tempfile::TempDir,
    addr: String,
    unseal_key: String,
}

impl DevBao {
    async fn start() -> Self {
        let listen = free_port();
        let home = tempfile::tempdir().unwrap();
        let mut child = Command::new("bao")
            .args([
                "server",
                "-dev",
                &format!("-dev-root-token-id={ROOT_TOKEN}"),
                &format!("-dev-listen-address={listen}"),
            ])
            .env("HOME", home.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("starting bao server -dev");
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut unseal_key = None;
        let found = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some(k) = line.trim().strip_prefix("Unseal Key: ") {
                    unseal_key = Some(k.to_owned());
                }
                if line.contains("Development mode should NOT be used") {
                    return;
                }
            }
        })
        .await;
        assert!(found.is_ok(), "bao dev server did not start");
        // Keep draining stdout so bao never blocks on a full pipe.
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        Self {
            child,
            home,
            addr: format!("http://{listen}"),
            unseal_key: unseal_key.expect("bao printed no unseal key"),
        }
    }

    async fn cli(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new("bao")
            .args(args)
            .env("BAO_ADDR", &self.addr)
            .env("BAO_TOKEN", ROOT_TOKEN)
            .env("HOME", self.home.path())
            .output()
            .await
            .unwrap();
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }

    async fn ok(&self, args: &[&str]) -> String {
        self.cli(args)
            .await
            .unwrap_or_else(|e| panic!("bao {args:?}: {e}"))
    }
}

/// Transit, two node keys, and a policy shaped like production: `update` only
/// (no `create`, so encrypt can't create a missing key).
async fn provision(bao: &DevBao, dir: &Path) -> std::path::PathBuf {
    bao.ok(&["secrets", "enable", "transit"]).await;
    for node in [NODE_A, NODE_B] {
        let key = format!("transit/keys/talos-kms-{node}");
        bao.ok(&["write", "-f", &key]).await;
        bao.ok(&["write", &format!("{key}/config"), "deletion_allowed=true"])
            .await;
    }
    let policy = dir.join("policy.hcl");
    std::fs::write(
        &policy,
        r#"
path "transit/encrypt/talos-kms-*" { capabilities = ["update"] }
path "transit/decrypt/talos-kms-*" { capabilities = ["update"] }
"#,
    )
    .unwrap();
    bao.ok(&[
        "policy",
        "write",
        "talos-nyckelpiga",
        policy.to_str().unwrap(),
    ])
    .await;
    let token = bao
        .ok(&[
            "token",
            "create",
            "-policy=talos-nyckelpiga",
            "-ttl=1h",
            "-field=token",
        ])
        .await;
    let token_path = dir.join("bao-token");
    std::fs::write(&token_path, token.trim()).unwrap();
    token_path
}

struct Server {
    grpc: SocketAddr,
    health: SocketAddr,
    ca_pem: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start_server(bao: &DevBao, dir: &Path, token_path: &Path) -> Server {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("tls.crt"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("tls.key"), ck.signing_key.serialize_pem()).unwrap();
    std::fs::write(
        dir.join("allowlist.toml"),
        format!(
            "[[node]]\nuuid = \"{NODE_A}\"\nlabel = \"node-a\"\n\
             [[node]]\nuuid = \"{NODE_B}\"\nlabel = \"node-b\"\n\
             [[node]]\nuuid = \"{NODE_NO_KEY}\"\n"
        ),
    )
    .unwrap();
    let (grpc, health) = (free_port(), free_port());
    let config = Config::parse(
        &format!(
            r#"
            [server]
            listen = "{grpc}"
            tls_cert = "{d}/tls.crt"
            tls_key = "{d}/tls.key"
            reload_interval_secs = 1

            [health]
            listen = "{health}"

            [openbao]
            address = "{addr}"
            request_timeout_secs = 2

            [openbao.auth]
            method = "token"
            token_path = "{token}"

            [allowlist]
            path = "{d}/allowlist.toml"
            "#,
            d = dir.display(),
            addr = bao.addr,
            token = token_path.display(),
        ),
        Vec::new(),
    )
    .unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(talos_nyckelpiga::run(config, async {
        let _ = rx.await;
    }));
    let server = Server {
        grpc,
        health,
        ca_pem: ck.cert.pem(),
        shutdown: Some(tx),
        handle,
    };
    // Ready = logged in to OpenBao.
    for _ in 0..100 {
        if http_status(server.health, "/readyz").await == Some(200) {
            return server;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server never became ready");
}

/// Minimal HTTP/1.0 GET (the health port is plain HTTP).
async fn http_status(addr: SocketAddr, path: &str) -> Option<u16> {
    http_get(addr, path).await.map(|(s, _)| s)
}

async fn http_get(addr: SocketAddr, path: &str) -> Option<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).await.ok()?;
    let status = buf.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, buf))
}

async fn client(server: &Server) -> KmsServiceClient<Channel> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&server.ca_pem))
        .domain_name("localhost");
    let channel = Channel::from_shared(format!("https://localhost:{}", server.grpc.port()))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .expect("connecting over TLS");
    KmsServiceClient::new(channel)
}

/// Collects every log line (JSON, as in production) for inspection.
#[derive(Clone, Default)]
struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_logs() -> LogBuffer {
    let buf = LogBuffer::default();
    let writer = buf.clone();
    let _ = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .try_init();
    buf
}

fn req(uuid: &str, data: &[u8]) -> Request {
    Request {
        node_uuid: uuid.into(),
        data: data.to_vec(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn seal_unseal_against_openbao() {
    if !bao_available() {
        assert!(
            std::env::var_os("NYCKELPIGA_REQUIRE_BAO").is_none(),
            "NYCKELPIGA_REQUIRE_BAO is set but `bao` is not on PATH"
        );
        eprintln!("skipping: `bao` not on PATH (run inside devbox)");
        return;
    }
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let bao = DevBao::start().await;
    let token_path = provision(&bao, dir.path()).await;
    let mut server = start_server(&bao, dir.path(), &token_path).await;
    let mut kms = client(&server).await;

    let key = [7u8; 32];

    // Seal followed by Unseal round-trips; the stored blob is transit's string.
    let sealed = kms.seal(req(NODE_A, &key)).await.unwrap().into_inner().data;
    let sealed_str = std::str::from_utf8(&sealed).unwrap();
    assert!(sealed_str.starts_with("vault:v1:"), "{sealed_str}");
    let unsealed = kms
        .unseal(req(NODE_A, &sealed))
        .await
        .unwrap()
        .into_inner()
        .data;
    assert_eq!(unsealed, key);

    // The ciphertext is bound to the node: another node can't unseal it
    // (different key; and with associated_data even if keys were shared).
    let err = kms.unseal(req(NODE_B, &sealed)).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument, "{err:?}");

    // Unknown and malformed UUIDs are refused.
    let err = kms.seal(req(NODE_UNKNOWN, &key)).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = kms.unseal(req(NODE_UNKNOWN, &sealed)).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = kms.seal(req("not-a-uuid", &key)).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);

    // Bad request data.
    assert_eq!(
        kms.seal(req(NODE_A, b"")).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(
        kms.unseal(req(NODE_A, b"garbage"))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    let tampered = sealed_str.replacen("vault:v1:", "vault:v1:AAAA", 1);
    assert_eq!(
        kms.unseal(req(NODE_A, tampered.as_bytes()))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );

    // Allowlisted node without a key: the policy has no `create`, so encrypt
    // must not create one.
    let err = kms.seal(req(NODE_NO_KEY, &key)).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
    let keys = bao.ok(&["list", "-format=json", "transit/keys"]).await;
    assert!(!keys.contains(NODE_NO_KEY), "encrypt created a key: {keys}");

    // Key rotation: new seals use v2, old ciphertext still unseals.
    bao.ok(&[
        "write",
        "-f",
        &format!("transit/keys/talos-kms-{NODE_A}/rotate"),
    ])
    .await;
    let sealed_v2 = kms.seal(req(NODE_A, &key)).await.unwrap().into_inner().data;
    assert!(sealed_v2.starts_with(b"vault:v2:"));
    assert_eq!(
        kms.unseal(req(NODE_A, &sealed))
            .await
            .unwrap()
            .into_inner()
            .data,
        key
    );
    assert_eq!(
        kms.unseal(req(NODE_A, &sealed_v2))
            .await
            .unwrap()
            .into_inner()
            .data,
        key
    );

    // Sealed OpenBao: UNAVAILABLE (Talos retries), and it heals after unseal.
    bao.ok(&["operator", "seal"]).await;
    let err = kms.unseal(req(NODE_A, &sealed)).await.unwrap_err();
    assert_eq!(err.code(), Code::Unavailable, "{err:?}");
    bao.ok(&["operator", "unseal", &bao.unseal_key]).await;
    let mut healed = false;
    for _ in 0..50 {
        if let Ok(r) = kms.unseal(req(NODE_A, &sealed)).await {
            assert_eq!(r.into_inner().data, key);
            healed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(healed, "unseal did not recover after OpenBao was unsealed");

    // Revocation: deleting the node's key makes its disks unsealable.
    bao.ok(&["delete", &format!("transit/keys/talos-kms-{NODE_A}")])
        .await;
    let err = kms.unseal(req(NODE_A, &sealed)).await.unwrap_err();
    assert_eq!(err.code(), Code::NotFound, "{err:?}");
    // Node B is unaffected.
    let sealed_b = kms.seal(req(NODE_B, &key)).await.unwrap().into_inner().data;
    assert_eq!(
        kms.unseal(req(NODE_B, &sealed_b))
            .await
            .unwrap()
            .into_inner()
            .data,
        key
    );

    // Allowlist hot reload: removing node B refuses it without a restart.
    std::fs::write(
        dir.path().join("allowlist.toml"),
        format!("[[node]]\nuuid = \"{NODE_A}\"\n"),
    )
    .unwrap();
    let mut refused = false;
    for _ in 0..50 {
        if let Err(e) = kms.unseal(req(NODE_B, &sealed_b)).await {
            assert_eq!(e.code(), Code::PermissionDenied);
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(refused, "allowlist change was not picked up");

    // Health and metrics.
    assert_eq!(http_status(server.health, "/healthz").await, Some(200));
    let (status, metrics) = http_get(server.health, "/metrics").await.unwrap();
    assert_eq!(status, 200);
    assert!(
        metrics.contains("nyckelpiga_requests_total{op=\"seal\",result=\"ok\"}"),
        "{metrics}"
    );
    assert!(metrics.contains("nyckelpiga_openbao_authenticated 1"));
    assert!(
        !metrics.contains(NODE_A),
        "metrics must not carry node UUIDs"
    );

    server.shutdown.take().unwrap().send(()).unwrap();
    server.handle.await.unwrap().unwrap();
    drop(bao.child);

    // Audit log: one event per call with the node and result, and never key
    // material or ciphertext (any form), even at TRACE level.
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains(r#""target":"audit""#), "no audit events");
    assert!(logs.contains(r#""node_label":"node-a""#));
    assert!(logs.contains(r#""result":"permission_denied""#));
    assert!(logs.contains(NODE_UNKNOWN), "refused UUID should be logged");
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    for secret in [
        b64.encode(key),
        b64.encode(&key[..12]),
        "vault:v".to_owned(),
        sealed_str.split(':').nth(2).unwrap()[..16].to_owned(),
        hex(&key),
    ] {
        assert!(
            !logs.contains(&secret),
            "log contains secret material {secret:?}"
        );
    }
    let event_line = logs
        .lines()
        .find(|l| l.contains(r#""target":"audit""#))
        .unwrap();
    for field in ["op", "node_uuid", "peer", "result", "latency_ms"] {
        assert!(
            event_line.contains(&format!(r#""{field}":"#)),
            "audit event lacks {field}: {event_line}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_certificate_reload() {
    if !bao_available() {
        eprintln!("skipping: `bao` not on PATH (run inside devbox)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let bao = DevBao::start().await;
    let token_path = provision(&bao, dir.path()).await;
    let server = start_server(&bao, dir.path(), &token_path).await;
    let mut old = client(&server).await;

    // Rotate to a certificate from a different self-signed issuer.
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.path().join("tls.key"), ck.signing_key.serialize_pem()).unwrap();
    std::fs::write(dir.path().join("tls.crt"), ck.cert.pem()).unwrap();

    let new_ca = ck.cert.pem();
    let mut switched = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&new_ca))
            .domain_name("localhost");
        let endpoint = Channel::from_shared(format!("https://localhost:{}", server.grpc.port()))
            .unwrap()
            .tls_config(tls)
            .unwrap();
        if let Ok(ch) = endpoint.connect().await {
            let mut kms = KmsServiceClient::new(ch);
            kms.seal(req(NODE_A, &[1u8; 32])).await.unwrap();
            switched = true;
            break;
        }
    }
    assert!(switched, "new certificate was never served");
    // The established connection keeps working.
    old.seal(req(NODE_A, &[1u8; 32])).await.unwrap();
}

/// Kubernetes auth login against real OpenBao, with a fake Kubernetes API
/// that approves every TokenReview for one service account.
#[tokio::test(flavor = "multi_thread")]
async fn kubernetes_auth_login() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    if !bao_available() {
        eprintln!("skipping: `bao` not on PATH (run inside devbox)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let bao = DevBao::start().await;
    provision(&bao, dir.path()).await;

    // Fake kube-apiserver: POST /apis/authentication.k8s.io/v1/tokenreviews.
    let api = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/apis/authentication.k8s.io/v1/tokenreviews",
        axum::routing::post(|| async {
            (
                [("content-type", "application/json")],
                r#"{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{
                    "authenticated":true,
                    "user":{"username":"system:serviceaccount:kms:talos-nyckelpiga","uid":"11111111-2222-3333-4444-555555555555"}}}"#,
            )
        }),
    );
    tokio::spawn(async move { axum::serve(api, app).await.unwrap() });

    // OpenBao insists on a CA when not running in a pod; the fake API is
    // plain HTTP, so any certificate will do.
    let ca = dir.path().join("k8s-ca.crt");
    std::fs::write(
        &ca,
        rcgen::generate_simple_self_signed(vec!["k8s".into()])
            .unwrap()
            .cert
            .pem(),
    )
    .unwrap();
    bao.ok(&["auth", "enable", "kubernetes"]).await;
    bao.ok(&[
        "write",
        "auth/kubernetes/config",
        &format!("kubernetes_host=http://{api_addr}"),
        "disable_local_ca_jwt=true",
        &format!("kubernetes_ca_cert=@{}", ca.display()),
    ])
    .await;
    bao.ok(&[
        "write",
        "auth/kubernetes/role/talos-nyckelpiga",
        "bound_service_account_names=talos-nyckelpiga",
        "bound_service_account_namespaces=kms",
        "token_policies=talos-nyckelpiga",
        "token_ttl=1h",
    ])
    .await;

    // A service-account-shaped JWT. OpenBao reads its claims; the signature
    // is checked by the (fake) TokenReview API, not by OpenBao.
    let header = B64URL.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = B64URL.encode(
        r#"{"iss":"kubernetes/serviceaccount","sub":"system:serviceaccount:kms:talos-nyckelpiga",
            "kubernetes.io/serviceaccount/namespace":"kms",
            "kubernetes.io/serviceaccount/service-account.name":"talos-nyckelpiga",
            "kubernetes.io/serviceaccount/service-account.uid":"11111111-2222-3333-4444-555555555555"}"#,
    );
    let jwt = format!("{header}.{claims}.{}", B64URL.encode([0u8; 256]));
    let jwt_path = dir.path().join("sa-token");
    std::fs::write(&jwt_path, &jwt).unwrap();

    let config = Config::parse(
        &format!(
            r#"
            [server]
            tls_cert = "unused"
            tls_key = "unused"
            [openbao]
            address = "{addr}"
            [openbao.auth]
            method = "kubernetes"
            role = "talos-nyckelpiga"
            token_path = "{jwt}"
            [allowlist]
            path = "unused"
            "#,
            addr = bao.addr,
            jwt = jwt_path.display(),
        ),
        Vec::new(),
    )
    .unwrap();
    let metrics = std::sync::Arc::new(talos_nyckelpiga::metrics::Metrics::new());
    let client = talos_nyckelpiga::bao::Bao::new(config.openbao, metrics).unwrap();
    client.login().await.expect("kubernetes login");
    assert!(client.is_authenticated().await);
    let ct = client
        .encrypt(&format!("talos-kms-{NODE_A}"), NODE_A, &[3u8; 32])
        .await
        .unwrap();
    let pt = client
        .decrypt(&format!("talos-kms-{NODE_A}"), NODE_A, &ct)
        .await
        .unwrap();
    assert_eq!(pt.as_slice(), [3u8; 32]);

    // A wrong role is an authentication failure (Unavailable, retried).
    let mut bad = Config::parse(
        &format!(
            "[server]\ntls_cert=\"u\"\ntls_key=\"u\"\n[openbao]\naddress=\"{}\"\n[openbao.auth]\nmethod=\"kubernetes\"\nrole=\"nope\"\ntoken_path=\"{}\"\n[allowlist]\npath=\"u\"\n",
            bao.addr,
            jwt_path.display()
        ),
        Vec::new(),
    )
    .unwrap();
    bad.openbao.request_timeout_secs = 2;
    let client = talos_nyckelpiga::bao::Bao::new(
        bad.openbao,
        std::sync::Arc::new(talos_nyckelpiga::metrics::Metrics::new()),
    )
    .unwrap();
    let err = client.login().await.unwrap_err();
    assert_eq!(err.code(), Code::Unavailable, "{err:?}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
