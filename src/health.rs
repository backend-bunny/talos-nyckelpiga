//! Plain-HTTP health and metrics endpoints on a separate, non-TLS port.
//!
//! - `/healthz`: the process is up (liveness).
//! - `/readyz`: an OpenBao token is held (readiness).
//! - `/metrics`: Prometheus text format.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;

use crate::bao::Bao;
use crate::metrics::Metrics;

#[derive(Clone)]
struct AppState {
    bao: Arc<Bao>,
    metrics: Arc<Metrics>,
}

pub fn router(bao: Arc<Bao>, metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .with_state(AppState { bao, metrics })
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    if state.bao.is_authenticated().await {
        (StatusCode::OK, "ready\n")
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "not authenticated to openbao\n",
        )
    }
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render(),
    )
}
