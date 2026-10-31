//! Prometheus metrics, served on the health port at `/metrics`.
//!
//! Labels never carry node UUIDs, key names or anything derived from request
//! data: per-node detail lives in the audit log.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};

pub struct Metrics {
    registry: Registry,
    /// Seal/Unseal calls by `op` and `result` (ok or a gRPC code name).
    pub requests: IntCounterVec,
    /// Seal/Unseal latency in seconds by `op`.
    pub latency: HistogramVec,
    /// 1 while the server holds a valid OpenBao token.
    pub openbao_authenticated: IntGauge,
    /// OpenBao logins and token renewals by `kind` and `result`.
    pub openbao_auth: IntCounterVec,
    pub tls_reloads: IntCounterVec,
    pub allowlist_reloads: IntCounterVec,
    pub allowlist_nodes: IntGauge,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new_custom(Some("nyckelpiga".into()), None).unwrap();
        let requests = IntCounterVec::new(
            Opts::new("requests_total", "KMS calls by operation and result"),
            &["op", "result"],
        )
        .unwrap();
        let latency = HistogramVec::new(
            HistogramOpts::new("request_duration_seconds", "KMS call latency").buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["op"],
        )
        .unwrap();
        let openbao_authenticated =
            IntGauge::new("openbao_authenticated", "1 while an OpenBao token is held").unwrap();
        let openbao_auth = IntCounterVec::new(
            Opts::new("openbao_auth_total", "OpenBao logins and token renewals"),
            &["kind", "result"],
        )
        .unwrap();
        let tls_reloads = IntCounterVec::new(
            Opts::new("tls_reloads_total", "TLS certificate reloads by result"),
            &["result"],
        )
        .unwrap();
        let allowlist_reloads = IntCounterVec::new(
            Opts::new("allowlist_reloads_total", "Allowlist reloads by result"),
            &["result"],
        )
        .unwrap();
        let allowlist_nodes =
            IntGauge::new("allowlist_nodes", "Nodes in the active allowlist").unwrap();

        for c in [
            Box::new(requests.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(latency.clone()),
            Box::new(openbao_authenticated.clone()),
            Box::new(openbao_auth.clone()),
            Box::new(tls_reloads.clone()),
            Box::new(allowlist_reloads.clone()),
            Box::new(allowlist_nodes.clone()),
        ] {
            registry.register(c).unwrap();
        }
        Self {
            registry,
            requests,
            latency,
            openbao_authenticated,
            openbao_auth,
            tls_reloads,
            allowlist_reloads,
            allowlist_nodes,
        }
    }

    /// The registry in Prometheus text format.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buf)
            .expect("encoding metrics into a Vec can't fail");
        String::from_utf8(buf).expect("prometheus text format is UTF-8")
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
