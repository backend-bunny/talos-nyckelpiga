//! Server configuration: one TOML file plus `NYCKELPIGA_*` environment
//! overrides.
//!
//! An override names a config key path with `__` between table levels, e.g.
//! `NYCKELPIGA_OPENBAO__ADDRESS=https://bao:8200` sets `[openbao] address`.
//! The value is parsed as a TOML value when it is one (numbers, booleans,
//! quoted strings) and taken as a plain string otherwise.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

pub const ENV_PREFIX: &str = "NYCKELPIGA_";

/// Placeholder in [`OpenBaoConfig::key_template`] replaced by the node UUID.
pub const UUID_PLACEHOLDER: &str = "{uuid}";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub health: HealthConfig,
    pub openbao: OpenBaoConfig,
    pub allowlist: AllowlistConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// gRPC (TLS) listen address.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// PEM certificate chain, e.g. a mounted `kubernetes.io/tls` Secret's `tls.crt`.
    pub tls_cert: PathBuf,
    /// PEM private key (`tls.key`).
    pub tls_key: PathBuf,
    /// How often the certificate and allowlist files are checked for changes.
    #[serde(default = "default_reload_interval")]
    pub reload_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    /// Plain-HTTP listen address for `/healthz`, `/readyz` and `/metrics`.
    #[serde(default = "default_health_listen")]
    pub listen: SocketAddr,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            listen: default_health_listen(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenBaoConfig {
    /// Base URL, e.g. `https://openbao.openbao.svc:8200`.
    pub address: String,
    /// PEM CA bundle that is trusted *instead of* the system roots. Unset:
    /// the system bundle ([`SYSTEM_CA_BUNDLE`] or `$SSL_CERT_FILE`).
    pub ca_cert: Option<PathBuf>,
    /// Transit secrets engine mount path.
    #[serde(default = "default_transit_mount")]
    pub transit_mount: String,
    /// Transit key name for a node; `{uuid}` is replaced by the node UUID.
    #[serde(default = "default_key_template")]
    pub key_template: String,
    /// Bind each ciphertext to its node UUID with transit `associated_data`.
    /// Requires an AEAD key type (the default `aes256-gcm96` is one).
    #[serde(default = "default_true")]
    pub associated_data: bool,
    /// Timeout for each OpenBao HTTP request.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase", deny_unknown_fields)]
pub enum AuthConfig {
    /// Kubernetes auth: log in with the pod's projected service-account token.
    Kubernetes {
        #[serde(default = "default_k8s_mount")]
        mount: String,
        role: String,
        #[serde(default = "default_k8s_token_path")]
        token_path: PathBuf,
    },
    /// An OpenBao token read from a file (e.g. an OpenBao Agent sink). The file
    /// is re-read whenever the token is rejected. Meant for tests and
    /// non-Kubernetes deployments; it is an auth credential, not key material.
    Token { token_path: PathBuf },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistConfig {
    /// TOML file with the permitted nodes (see [`crate::allowlist`]).
    pub path: PathBuf,
}

/// Wolfi's `ca-certificates-bundle` path (also Debian's and Alpine's).
pub const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

fn default_listen() -> SocketAddr {
    "0.0.0.0:4050".parse().unwrap()
}
fn default_health_listen() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}
fn default_reload_interval() -> u64 {
    30
}
fn default_transit_mount() -> String {
    "transit".into()
}
fn default_key_template() -> String {
    format!("talos-kms-{UUID_PLACEHOLDER}")
}
fn default_true() -> bool {
    true
}
fn default_request_timeout() -> u64 {
    5
}
fn default_k8s_mount() -> String {
    "kubernetes".into()
}
fn default_k8s_token_path() -> PathBuf {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".into()
}

impl Config {
    /// Read `path` and apply overrides from the process environment.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text, std::env::vars())
            .with_context(|| format!("loading config {}", path.display()))
    }

    /// Parse `text` and apply `NYCKELPIGA_*` overrides from `env`.
    pub fn parse(
        text: &str,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> anyhow::Result<Self> {
        let mut table: toml::Table = toml::from_str(text)?;
        for (name, value) in env {
            if let Some(path) = name.strip_prefix(ENV_PREFIX) {
                apply_override(&mut table, path, &value)
                    .with_context(|| format!("environment override {name}"))?;
            }
        }
        let config: Config = table.try_into()?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let bao = &self.openbao;
        if !bao.address.starts_with("https://") && !bao.address.starts_with("http://") {
            bail!(
                "openbao.address must be an http(s) URL, got {:?}",
                bao.address
            );
        }
        if bao.key_template.matches(UUID_PLACEHOLDER).count() != 1 {
            bail!("openbao.key_template must contain {UUID_PLACEHOLDER} exactly once");
        }
        // Key names end up in URL paths: keep them to what transit allows.
        let literal = bao.key_template.replace(UUID_PLACEHOLDER, "");
        if !literal
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            bail!(
                "openbao.key_template may only contain [A-Za-z0-9._-] besides {UUID_PLACEHOLDER}"
            );
        }
        if bao.transit_mount.is_empty() || bao.transit_mount.contains("..") {
            bail!("openbao.transit_mount is invalid");
        }
        if self.server.reload_interval_secs == 0 {
            bail!("server.reload_interval_secs must be > 0");
        }
        if bao.request_timeout_secs == 0 {
            bail!("openbao.request_timeout_secs must be > 0");
        }
        Ok(())
    }

    pub fn reload_interval(&self) -> Duration {
        Duration::from_secs(self.server.reload_interval_secs)
    }
}

impl OpenBaoConfig {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    /// Transit key name for a (canonical) node UUID.
    pub fn key_name(&self, uuid: &str) -> String {
        self.key_template.replace(UUID_PLACEHOLDER, uuid)
    }
}

fn apply_override(table: &mut toml::Table, path: &str, value: &str) -> anyhow::Result<()> {
    let keys: Vec<String> = path.split("__").map(str::to_ascii_lowercase).collect();
    if keys.iter().any(String::is_empty) {
        bail!("empty key segment");
    }
    let (last, parents) = keys
        .split_last()
        .expect("split yields at least one segment");
    let mut current = table;
    for key in parents {
        let entry = current
            .entry(key.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        current = entry
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("{key} is not a table"))?;
    }
    current.insert(last.clone(), parse_value(value));
    Ok(())
}

fn parse_value(value: &str) -> toml::Value {
    // `toml` parses documents, so wrap the value as one.
    toml::from_str::<toml::Table>(&format!("v = {value}"))
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [server]
        tls_cert = "/tls/tls.crt"
        tls_key = "/tls/tls.key"

        [openbao]
        address = "https://bao.example.com:8200"

        [openbao.auth]
        method = "kubernetes"
        role = "talos-nyckelpiga"

        [allowlist]
        path = "/etc/talos-nyckelpiga/allowlist.toml"
    "#;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn defaults() {
        let c = Config::parse(MINIMAL, env(&[])).unwrap();
        assert_eq!(c.server.listen, "0.0.0.0:4050".parse().unwrap());
        assert_eq!(c.health.listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(c.openbao.transit_mount, "transit");
        assert!(c.openbao.associated_data);
        assert_eq!(c.openbao.key_name("abc"), "talos-kms-abc");
        match c.openbao.auth {
            AuthConfig::Kubernetes {
                mount,
                role,
                token_path,
            } => {
                assert_eq!(mount, "kubernetes");
                assert_eq!(role, "talos-nyckelpiga");
                assert_eq!(
                    token_path,
                    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
                );
            }
            other => panic!("unexpected auth {other:?}"),
        }
    }

    #[test]
    fn env_overrides() {
        let c = Config::parse(
            MINIMAL,
            env(&[
                ("NYCKELPIGA_OPENBAO__ADDRESS", "http://127.0.0.1:8200"),
                ("NYCKELPIGA_OPENBAO__ASSOCIATED_DATA", "false"),
                ("NYCKELPIGA_SERVER__RELOAD_INTERVAL_SECS", "5"),
                ("NYCKELPIGA_HEALTH__LISTEN", "127.0.0.1:9000"),
                ("NYCKELPIGA_OPENBAO__AUTH__ROLE", "other"),
                ("UNRELATED", "x"),
            ]),
        )
        .unwrap();
        assert_eq!(c.openbao.address, "http://127.0.0.1:8200");
        assert!(!c.openbao.associated_data);
        assert_eq!(c.server.reload_interval_secs, 5);
        assert_eq!(c.health.listen, "127.0.0.1:9000".parse().unwrap());
        assert!(
            matches!(c.openbao.auth, AuthConfig::Kubernetes { ref role, .. } if role == "other")
        );
    }

    #[test]
    fn token_auth() {
        let text = MINIMAL.replace(
            "method = \"kubernetes\"\n        role = \"talos-nyckelpiga\"",
            "method = \"token\"\n        token_path = \"/run/bao-token\"",
        );
        let c = Config::parse(&text, env(&[])).unwrap();
        assert!(matches!(c.openbao.auth, AuthConfig::Token { .. }));
    }

    #[test]
    fn rejects_unknown_keys() {
        let text = format!("{MINIMAL}\n[extra]\nx = 1\n");
        assert!(Config::parse(&text, env(&[])).is_err());
        assert!(Config::parse(MINIMAL, env(&[("NYCKELPIGA_SERVER__TYPO", "1")])).is_err());
    }

    #[test]
    fn rejects_bad_key_template() {
        for bad in ["static-key", "a-{uuid}-{uuid}", "a/{uuid}", "../{uuid}"] {
            let e = env(&[("NYCKELPIGA_OPENBAO__KEY_TEMPLATE", bad)]);
            assert!(Config::parse(MINIMAL, e).is_err(), "{bad} accepted");
        }
        let e = env(&[("NYCKELPIGA_OPENBAO__KEY_TEMPLATE", "node.{uuid}")]);
        assert_eq!(
            Config::parse(MINIMAL, e).unwrap().openbao.key_name("u"),
            "node.u"
        );
    }

    #[test]
    fn rejects_bad_address() {
        let e = env(&[("NYCKELPIGA_OPENBAO__ADDRESS", "bao:8200")]);
        assert!(Config::parse(MINIMAL, e).is_err());
    }

    #[test]
    fn example_config_parses() {
        let text = include_str!("../examples/config.toml");
        Config::parse(text, env(&[])).unwrap();
    }
}
