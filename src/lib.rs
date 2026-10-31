//! talos-nyckelpiga: a Talos Linux KMS server backed by OpenBao transit.
//!
//! Talos seals each encrypted volume's key with `Seal` and gets it back at
//! boot with `Unseal`. Both map to OpenBao transit `encrypt`/`decrypt` on one
//! key per node; deleting a node's key revokes it.

pub mod allowlist;
pub mod bao;
pub mod config;
pub mod health;
pub mod metrics;
pub mod service;
pub mod tls;
pub mod watch;

/// Generated from the vendored `proto/kms.proto` (MPL-2.0).
pub mod proto {
    tonic::include_proto!("sidero.kms");
}

use std::future::Future;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;

use crate::allowlist::SharedAllowlist;
use crate::bao::Bao;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::proto::kms_service_server::KmsServiceServer;
use crate::service::KmsServer;
use crate::tls::ReloadingCert;

/// Run the server until `shutdown` completes. Startup fails on an invalid
/// certificate or allowlist; OpenBao being unavailable is not fatal (the
/// login is retried and `/readyz` reports it).
pub async fn run(
    config: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let metrics = Arc::new(Metrics::new());
    let interval = config.reload_interval();

    let cert = ReloadingCert::load(
        config.server.tls_cert.clone(),
        config.server.tls_key.clone(),
    )?;
    let allowlist = SharedAllowlist::load(&config.allowlist.path)?;
    let bao = Bao::new(config.openbao.clone(), metrics.clone())?;

    let grpc_listener = TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("binding {}", config.server.listen))?;
    let health_listener = TcpListener::bind(config.health.listen)
        .await
        .with_context(|| format!("binding {}", config.health.listen))?;
    tracing::info!(grpc = %config.server.listen, health = %config.health.listen, "listening");

    let mut background = tokio::task::JoinSet::new();
    background.spawn(cert.clone().watch(interval, metrics.clone()));
    background.spawn(allowlist.clone().watch(interval, metrics.clone()));
    background.spawn(bao.clone().maintain());
    let health = health::router(bao.clone(), metrics.clone());
    background.spawn(async move {
        if let Err(err) = axum::serve(health_listener, health).await {
            tracing::error!(error = %err, "health server failed");
        }
    });

    let incoming = tls::incoming(grpc_listener, cert.server_config()?);
    let result = tonic::transport::Server::builder()
        .add_service(KmsServiceServer::new(KmsServer::new(
            allowlist, bao, metrics,
        )))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .context("grpc server");
    background.abort_all();
    tracing::info!("stopped");
    result
}
