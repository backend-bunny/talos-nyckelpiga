//! HTTPS trust tests, including the symlink layout used by Kubernetes volumes.

use super::*;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Clone, Default)]
struct Log(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn config(address: String, ca_path: PathBuf, token_path: PathBuf) -> OpenBaoConfig {
    OpenBaoConfig {
        address,
        ca_cert: Some(ca_path),
        transit_mount: "transit".into(),
        key_template: "node-{uuid}".into(),
        associated_data: true,
        request_timeout_secs: 2,
        auth: AuthConfig::Token { token_path },
    }
}

fn ca(name: &str) -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap()).unwrap()
}

struct HttpsServer {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl HttpsServer {
    async fn start(ca: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&key, ca)
            .unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(crate::tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = connections.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
                };
                let (tcp, _) = accepted.unwrap();
                let acceptor = acceptor.clone();
                let count = count.clone();
                tasks.spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    count.fetch_add(1, Ordering::SeqCst);
                    // Keep the connection alive so the removal test detects
                    // accidental reuse of a pool authenticated by the old root.
                    let mut io = BufReader::new(tls);
                    loop {
                        let mut line = String::new();
                        if !matches!(io.read_line(&mut line).await, Ok(n) if n > 0) { return; }
                        let redirect = line.contains(" /redirect ");
                        let mut length = 0;
                        loop {
                            line.clear();
                            if !matches!(io.read_line(&mut line).await, Ok(n) if n > 0) { return; }
                            if line == "\r\n" { break; }
                            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                        }
                        let mut body = vec![0; length];
                        if io.read_exact(&mut body).await.is_err() { return; }
                        let response = if redirect {
                            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n".to_owned()
                        } else {
                            let body = "{\"data\":{\"ttl\":3600,\"renewable\":false}}";
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                        };
                        if io.write_all(response.as_bytes()).await.is_err() || io.flush().await.is_err() { return; }
                    }
                });
            }
        });
        Self {
            addr,
            connections,
            task,
        }
    }

    fn url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }
}

impl Drop for HttpsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn swap_bundle(dir: &Path, revision: &str, pem: &str) {
    use std::os::unix::fs::symlink;
    let revision_path = dir.join(revision);
    std::fs::create_dir(&revision_path).unwrap();
    std::fs::write(revision_path.join("ca.crt"), pem).unwrap();
    symlink(revision, dir.join("..data_tmp")).unwrap();
    std::fs::rename(dir.join("..data_tmp"), dir.join("..data")).unwrap();
}

async fn wait_for_reloads(metrics: &Metrics, result: &str, count: u64) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while metrics
            .openbao_ca_reloads
            .with_label_values(&[result])
            .get()
            < count
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("CA watcher did not report the expected reload");
}

#[tokio::test]
async fn symlink_rotation_supports_overlap_rejects_bad_updates_and_retires_old_pools() {
    let (old_ca, new_ca) = (ca("old-root"), ca("new-root"));
    let old_server = HttpsServer::start(&old_ca).await;
    let new_server = HttpsServer::start(&new_ca).await;
    let dir = tempfile::tempdir().unwrap();
    swap_bundle(dir.path(), "..first", &old_ca.pem());
    let ca_path = dir.path().join("ca.crt");
    std::os::unix::fs::symlink("..data/ca.crt", &ca_path).unwrap();
    let token_path = dir.path().join("token");
    std::fs::write(&token_path, "synthetic-token").unwrap();
    let metrics = Arc::new(Metrics::new());
    let client = Bao::new(
        config(old_server.url(), ca_path, token_path),
        metrics.clone(),
    )
    .unwrap();
    client.login().await.unwrap();
    client.login().await.unwrap();
    assert_eq!(
        old_server.connections.load(Ordering::SeqCst),
        1,
        "mock must exercise connection reuse"
    );
    assert!(
        client
            .http
            .load_full()
            .get(new_server.url())
            .send()
            .await
            .is_err()
    );
    let token = client.current_token().await.unwrap();

    // Unchanged files must not churn HTTP connections or metrics.
    let first = client.http.load_full();
    client.reload_ca();
    assert!(Arc::ptr_eq(&first, &client.http.load_full()));
    assert_eq!(
        metrics.openbao_ca_reloads.with_label_values(&["ok"]).get(),
        0
    );

    let watcher = tokio::spawn(client.clone().watch_ca(Duration::from_millis(20)));
    swap_bundle(
        dir.path(),
        "..overlap",
        &format!("{}{}", old_ca.pem(), new_ca.pem()),
    );
    wait_for_reloads(&metrics, "ok", 1).await;
    assert!(
        client.is_same_token(&token).await,
        "CA rotation must preserve authentication"
    );
    assert!(!Arc::ptr_eq(&first, &client.http.load_full()));
    for server in [&old_server, &new_server] {
        assert_eq!(
            client
                .http
                .load_full()
                .get(server.url())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        client
            .http
            .load_full()
            .get(format!("{}/redirect", new_server.url()))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TEMPORARY_REDIRECT,
        "reload must preserve redirect refusal"
    );

    let overlap = client.http.load_full();
    swap_bundle(dir.path(), "..broken", "not a certificate");
    wait_for_reloads(&metrics, "error", 2).await; // retry without another file change
    assert!(Arc::ptr_eq(&overlap, &client.http.load_full()));
    client.login().await.unwrap();

    swap_bundle(dir.path(), "..new-only", &new_ca.pem());
    wait_for_reloads(&metrics, "ok", 2).await;
    // Both previous clients still have live pooled connections to old_server.
    // A request through Bao must nevertheless use the new pool/trust store.
    assert!(
        client.login().await.is_err(),
        "removed root still trusted through an old pool"
    );
    assert_eq!(
        client
            .http
            .load_full()
            .get(new_server.url())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    watcher.abort();
    let _ = watcher.await;
}

#[test]
fn invalid_or_partly_invalid_bundles_fail_closed_and_retry() {
    let logs = Log::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _capture = tracing::subscriber::set_default(subscriber);
    let issuer = ca("root");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.crt");
    let config = config(
        "https://localhost:8200".into(),
        path.clone(),
        "unused".into(),
    );
    let metrics = Arc::new(Metrics::new());
    std::fs::write(&path, "garbage").unwrap();
    assert!(Bao::new(config.clone(), metrics.clone()).is_err());
    std::fs::write(&path, issuer.pem()).unwrap();
    let client = Bao::new(config, metrics.clone()).unwrap();
    let good = client.http.load_full();
    for bad in [
        String::new(),
        "synthetic-secret-file-contents".into(),
        format!(
            "{}\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            issuer.pem()
        ),
        format!("{}\n-----BEGIN CERTIFICATE-----\n", issuer.pem()),
    ] {
        std::fs::write(&path, bad).unwrap();
        let before = metrics
            .openbao_ca_reloads
            .with_label_values(&["error"])
            .get();
        client.reload_ca();
        client.reload_ca();
        assert_eq!(
            metrics
                .openbao_ca_reloads
                .with_label_values(&["error"])
                .get(),
            before + 2
        );
        assert!(Arc::ptr_eq(&good, &client.http.load_full()));
    }
    std::fs::remove_file(&path).unwrap();
    client.reload_ca();
    assert!(Arc::ptr_eq(&good, &client.http.load_full()));
    std::fs::write(&path, issuer.pem()).unwrap();
    client.reload_ca();
    assert!(!Arc::ptr_eq(&good, &client.http.load_full()));
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("keeping previous trust store"));
    assert!(logs.contains("openbao ca bundle reloaded"));
    assert!(!logs.contains("synthetic-secret-file-contents"));
    assert!(!logs.contains("BEGIN CERTIFICATE"));
    assert!(
        metrics
            .render()
            .contains("nyckelpiga_openbao_ca_reloads_total{result=\"error\"}")
    );
}

#[tokio::test]
async fn plain_http_does_not_read_or_watch_a_ca_file() {
    let metrics = Arc::new(Metrics::new());
    let client = Bao::new(
        config(
            "http://localhost:8200".into(),
            "/nonexistent/ca.crt".into(),
            "unused".into(),
        ),
        metrics,
    )
    .unwrap();
    assert!(client.ca_watch.is_none());
    tokio::time::timeout(
        Duration::from_secs(1),
        client.watch_ca(Duration::from_secs(30)),
    )
    .await
    .unwrap();
}
