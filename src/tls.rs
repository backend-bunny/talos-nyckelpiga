//! TLS for the gRPC listener, with certificate reload.
//!
//! The certificate (cert-manager, ~60-day renewals) is served through a
//! rustls [`ResolvesServerCert`] that holds the current [`CertifiedKey`] in an
//! [`ArcSwap`]. A background task re-reads `tls.crt`/`tls.key` every reload
//! interval and swaps in the new pair when it changed and parses; new
//! handshakes use it, existing connections are untouched. A broken update
//! keeps the old pair (see the wiki decision `tls-reload`).

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, bail};
use arc_swap::ArcSwap;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tonic::transport::server::Connected;

use crate::metrics::Metrics;
use crate::net::LimitedIo;
use crate::watch::FileWatch;

/// TLS handshakes that take longer than this are dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 64;
const MAX_HANDSHAKES: usize = 16;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTION_AGE: Duration = Duration::from_secs(300);
// RFC 9113 section 3.4: the HTTP/2 client preface is 24 bytes. Hyper
// validates its contents; we bound how long it may take to arrive.
const CLIENT_PREFACE_LEN: usize = 24;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// All certificates in a PEM bundle; fails if there are none.
pub fn parse_certs(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        bail!("no PEM certificates found");
    }
    Ok(certs)
}

fn certified_key(
    cert_pem: &[u8],
    key_pem: &[u8],
    provider: &CryptoProvider,
) -> anyhow::Result<CertifiedKey> {
    let certs = parse_certs(cert_pem).context("certificate")?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("private key")?;
    let ck = CertifiedKey::from_der(certs, key, provider).context("certificate and key")?;
    // Catches a cert/key pair that doesn't match (e.g. caught mid-rotation).
    ck.keys_match()
        .context("certificate does not match the private key")?;
    Ok(ck)
}

pub struct ReloadingCert {
    current: ArcSwap<CertifiedKey>,
    watch: Mutex<FileWatch>,
    provider: Arc<CryptoProvider>,
    cert_path: PathBuf,
}

impl fmt::Debug for ReloadingCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadingCert")
            .field("cert_path", &self.cert_path)
            .finish_non_exhaustive()
    }
}

impl ReloadingCert {
    /// Load the pair; failing here is fatal.
    pub fn load(cert_path: PathBuf, key_path: PathBuf) -> anyhow::Result<Arc<Self>> {
        let provider = provider();
        let mut watch = FileWatch::new(vec![cert_path.clone(), key_path]);
        let files = watch.read()?;
        let ck = certified_key(&files[0], &files[1], &provider)
            .with_context(|| format!("loading TLS pair {}", cert_path.display()))?;
        tracing::info!(cert = %cert_path.display(), "tls certificate loaded");
        Ok(Arc::new(Self {
            current: ArcSwap::from_pointee(ck),
            watch: Mutex::new(watch),
            provider,
            cert_path,
        }))
    }

    /// Swap in the files' pair if they changed and are valid.
    pub fn reload(&self, metrics: &Metrics) {
        let mut watch = self.watch.lock().unwrap();
        let result = watch.read_if_changed().and_then(|files| {
            files
                .map(|f| certified_key(&f[0], &f[1], &self.provider))
                .transpose()
        });
        match result {
            Ok(None) => {}
            Ok(Some(ck)) => {
                metrics.tls_reloads.with_label_values(&["ok"]).inc();
                tracing::info!(cert = %self.cert_path.display(), "tls certificate reloaded");
                self.current.store(Arc::new(ck));
            }
            Err(err) => {
                metrics.tls_reloads.with_label_values(&["error"]).inc();
                // Usually transient (cert and key caught mid-update): retry
                // on the next tick even if the files don't change again.
                watch.invalidate();
                tracing::error!(cert = %self.cert_path.display(), error = %format!("{err:#}"), "tls certificate reload failed; keeping previous certificate");
            }
        }
    }

    pub async fn watch(self: Arc<Self>, interval: Duration, metrics: Arc<Metrics>) {
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let this = self.clone();
            let metrics = metrics.clone();
            let _ = tokio::task::spawn_blocking(move || this.reload(&metrics)).await;
        }
    }

    pub fn server_config(self: &Arc<Self>) -> anyhow::Result<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        // grpc-go (Talos) enforces ALPN: the server must select h2.
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(config)
    }
}

impl ResolvesServerCert for ReloadingCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

/// Connection info tonic attaches to each request (see [`Connected`]).
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub SocketAddr);

/// A TLS connection plus its peer address, for tonic's `serve_with_incoming`.
pub struct TlsConn {
    inner: LimitedIo<TlsStream<TcpStream>>,
    peer: SocketAddr,
}

impl Connected for TlsConn {
    type ConnectInfo = PeerAddr;
    fn connect_info(&self) -> PeerAddr {
        PeerAddr(self.peer)
    }
}

impl AsyncRead for TlsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Accept TCP connections and complete TLS handshakes concurrently; yields
/// established connections. Failed handshakes are logged and dropped.
pub fn incoming(
    listener: TcpListener,
    config: rustls::ServerConfig,
) -> tokio_stream::wrappers::ReceiverStream<std::io::Result<TlsConn>> {
    incoming_with_limits(listener, config, MAX_CONNECTIONS, MAX_HANDSHAKES)
}

fn incoming_with_limits(
    listener: TcpListener,
    config: rustls::ServerConfig,
    max_connections: usize,
    max_handshakes: usize,
) -> tokio_stream::wrappers::ReceiverStream<std::io::Result<TlsConn>> {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let connections = Arc::new(Semaphore::new(max_connections));
    let handshakes = Arc::new(Semaphore::new(max_handshakes));
    let (tx, rx) = tokio::sync::mpsc::channel(max_connections);
    tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! {
                _ = tx.closed() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
                accepted = listener.accept() => accepted,
            };
            let (tcp, peer) = match accepted {
                Ok((tcp, peer)) => (tcp, crate::net::canonical_peer(peer)),
                Err(err) => {
                    tracing::warn!(error = %err, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Reject overload before allocating a TLS task. Permits cover
            // queued, handshaking and established connections, not just the
            // channel between this accept loop and tonic.
            let permits = connections
                .clone()
                .try_acquire_owned()
                .and_then(|connection| {
                    handshakes
                        .clone()
                        .try_acquire_owned()
                        .map(|handshake| (connection, handshake))
                });
            let Ok((connection, handshake)) = permits else {
                drop(tcp);
                tokio::task::yield_now().await;
                continue;
            };
            let acceptor = acceptor.clone();
            let conn_tx = tx.clone();
            tasks.spawn(async move {
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(inner)) => {
                        drop(handshake);
                        let inner = LimitedIo::new(
                            inner,
                            connection,
                            IDLE_TIMEOUT,
                            MAX_CONNECTION_AGE,
                            Some((CLIENT_PREFACE_LEN, HANDSHAKE_TIMEOUT)),
                        );
                        let _ = conn_tx.send(Ok(TlsConn { inner, peer })).await;
                    }
                    Ok(Err(err)) => {
                        tracing::debug!(peer = %peer, error = %err, "tls handshake failed")
                    }
                    Err(_) => tracing::debug!(peer = %peer, "tls handshake timed out"),
                }
            });
        }
        // JoinSet drops/aborts pending handshakes when tonic drops incoming.
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio_stream::StreamExt;

    fn test_configs() -> (rustls::ServerConfig, tokio_rustls::TlsConnector) {
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pair.cert.der().clone()).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![pair.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(pair.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec()];
        let mut client = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        (server, tokio_rustls::TlsConnector::from(Arc::new(client)))
    }

    #[tokio::test]
    async fn established_connections_hold_capacity_until_dropped() {
        let (config, connector) = test_configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut incoming = incoming_with_limits(listener, config, 1, 1);
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let client = connector
            .connect(name.clone(), TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        let conn = incoming.next().await.unwrap().unwrap();
        let refused = tokio::time::timeout(
            Duration::from_secs(2),
            connector.connect(name.clone(), TcpStream::connect(addr).await.unwrap()),
        )
        .await
        .unwrap();
        assert!(
            refused.is_err(),
            "connection limit did not cover established TLS sockets"
        );
        drop(conn);
        drop(client);
        let _client = connector
            .connect(name, TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        let _conn = incoming.next().await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn dropping_incoming_closes_stalled_handshakes_and_listener() {
        let (config, _) = test_configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = incoming_with_limits(listener, config, 2, 1);
        let mut stalled = TcpStream::connect(addr).await.unwrap();
        tokio::task::yield_now().await;
        drop(incoming);
        let closed = tokio::time::timeout(Duration::from_secs(2), stalled.read_u8())
            .await
            .unwrap();
        assert!(closed.is_err());
        assert!(TcpStream::connect(addr).await.is_err());
    }

    fn pair(name: &str) -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        (ck.cert.pem(), ck.signing_key.serialize_pem())
    }

    #[test]
    fn reload_swaps_valid_pairs_only() {
        let dir = tempfile::tempdir().unwrap();
        let (crt, key) = (dir.path().join("tls.crt"), dir.path().join("tls.key"));
        let (c1, k1) = pair("one.example.com");
        std::fs::write(&crt, &c1).unwrap();
        std::fs::write(&key, &k1).unwrap();
        let rc = ReloadingCert::load(crt.clone(), key.clone()).unwrap();
        let metrics = Metrics::new();
        let first = rc.current.load_full();

        // Unchanged: no swap.
        rc.reload(&metrics);
        assert!(Arc::ptr_eq(&first, &rc.current.load_full()));

        // New cert with the old key: mismatched, rejected.
        let (c2, k2) = pair("two.example.com");
        std::fs::write(&crt, &c2).unwrap();
        rc.reload(&metrics);
        assert!(Arc::ptr_eq(&first, &rc.current.load_full()));

        // Matching pair: swapped.
        std::fs::write(&key, &k2).unwrap();
        rc.reload(&metrics);
        assert!(!Arc::ptr_eq(&first, &rc.current.load_full()));
        assert_eq!(metrics.tls_reloads.with_label_values(&["ok"]).get(), 1);
        assert_eq!(metrics.tls_reloads.with_label_values(&["error"]).get(), 1);
    }

    #[test]
    fn load_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let (crt, key) = (dir.path().join("tls.crt"), dir.path().join("tls.key"));
        std::fs::write(&crt, "nope").unwrap();
        std::fs::write(&key, "nope").unwrap();
        assert!(ReloadingCert::load(crt, key).is_err());
    }
}
