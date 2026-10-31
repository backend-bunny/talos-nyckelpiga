//! Allowlist of node UUIDs that may Seal/Unseal, with optional labels for logs.
//!
//! ```toml
//! [[node]]
//! uuid = "4c4c4544-0042-3510-8051-b4c04f4e3732"
//! label = "worker-1"
//! ```
//!
//! UUIDs are compared in canonical form (lowercase, hyphenated), which is what
//! Talos sends for SMBIOS UUIDs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use serde::Deserialize;

use crate::metrics::Metrics;
use crate::watch::FileWatch;

/// A node that passed the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Canonical (lowercase, hyphenated) UUID.
    pub uuid: String,
    pub label: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Allowlist {
    nodes: HashMap<String, Option<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    node: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    uuid: String,
    label: Option<String>,
}

/// Why a node UUID was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("node_uuid is not a valid UUID")]
    InvalidUuid,
    #[error("node is not in the allowlist")]
    NotAllowed { uuid: String },
}

/// Parse `s` as a UUID in the hyphenated form Talos sends and return it in
/// canonical form. Braced, URN and simple (no hyphens) forms are refused, so
/// one node maps to exactly one key name.
pub fn canonical_uuid(s: &str) -> Option<String> {
    if s.len() != 36 {
        return None;
    }
    uuid::Uuid::try_parse(s)
        .ok()
        .map(|u| u.hyphenated().to_string())
}

impl Allowlist {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let file: File = toml::from_str(text)?;
        let mut nodes = HashMap::new();
        for entry in file.node {
            let Some(uuid) = canonical_uuid(&entry.uuid) else {
                bail!("invalid node uuid {:?}", entry.uuid);
            };
            if nodes.insert(uuid.clone(), entry.label).is_some() {
                bail!("duplicate node uuid {uuid}");
            }
        }
        Ok(Self { nodes })
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Validate `node_uuid` and look it up.
    pub fn check(&self, node_uuid: &str) -> Result<Node, Refusal> {
        let uuid = canonical_uuid(node_uuid).ok_or(Refusal::InvalidUuid)?;
        match self.nodes.get(&uuid) {
            Some(label) => Ok(Node {
                uuid,
                label: label.clone(),
            }),
            None => Err(Refusal::NotAllowed { uuid }),
        }
    }
}

/// The current allowlist, replaced when its file changes.
pub struct SharedAllowlist {
    current: ArcSwap<Allowlist>,
    watch: std::sync::Mutex<FileWatch>,
    path: PathBuf,
}

impl SharedAllowlist {
    /// Load `path`. Failing here is fatal: the server never starts without a
    /// valid allowlist.
    pub fn load(path: &Path) -> anyhow::Result<Arc<Self>> {
        let mut watch = FileWatch::new(vec![path.to_owned()]);
        let contents = watch.read()?.remove(0);
        let list =
            parse_bytes(&contents).with_context(|| format!("allowlist {}", path.display()))?;
        tracing::info!(path = %path.display(), nodes = list.len(), "allowlist loaded");
        Ok(Arc::new(Self {
            current: ArcSwap::from_pointee(list),
            watch: std::sync::Mutex::new(watch),
            path: path.to_owned(),
        }))
    }

    pub fn get(&self) -> Arc<Allowlist> {
        self.current.load_full()
    }

    /// Re-read the file if it changed. A file that can't be read or parsed
    /// keeps the previous list active.
    pub fn reload(&self, metrics: &Metrics) {
        let mut watch = self.watch.lock().unwrap();
        let changed = watch.read_if_changed();
        let contents = match changed {
            Ok(None) => return,
            Ok(Some(mut files)) => files.remove(0),
            Err(err) => {
                watch.invalidate();
                metrics
                    .allowlist_reloads
                    .with_label_values(&["error"])
                    .inc();
                tracing::error!(path = %self.path.display(), error = %format!("{err:#}"), "allowlist reload failed; keeping previous list");
                return;
            }
        };
        match parse_bytes(&contents) {
            Ok(list) => {
                metrics.allowlist_reloads.with_label_values(&["ok"]).inc();
                metrics.allowlist_nodes.set(list.len() as i64);
                tracing::info!(path = %self.path.display(), nodes = list.len(), "allowlist reloaded");
                self.current.store(Arc::new(list));
            }
            Err(err) => {
                watch.invalidate();
                metrics
                    .allowlist_reloads
                    .with_label_values(&["error"])
                    .inc();
                tracing::error!(path = %self.path.display(), error = %format!("{err:#}"), "allowlist reload failed; keeping previous list");
            }
        }
    }

    /// Poll for changes every `interval`, forever.
    pub async fn watch(self: Arc<Self>, interval: Duration, metrics: Arc<Metrics>) {
        metrics.allowlist_nodes.set(self.get().len() as i64);
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let this = self.clone();
            let metrics = metrics.clone();
            let _ = tokio::task::spawn_blocking(move || this.reload(&metrics)).await;
        }
    }
}

fn parse_bytes(contents: &[u8]) -> anyhow::Result<Allowlist> {
    Allowlist::parse(std::str::from_utf8(contents).context("not UTF-8")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "4c4c4544-0042-3510-8051-b4c04f4e3732";

    #[test]
    fn check_allowed_and_refused() {
        let list = Allowlist::parse(&format!(
            "[[node]]\nuuid = \"{}\"\nlabel = \"worker-1\"\n[[node]]\nuuid = \"00000000-0000-0000-0000-000000000001\"\n",
            UUID.to_uppercase()
        ))
        .unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(
            list.check(UUID),
            Ok(Node {
                uuid: UUID.into(),
                label: Some("worker-1".into())
            })
        );
        // Talos sends lowercase, but case alone never changes the identity.
        assert_eq!(list.check(&UUID.to_uppercase()).unwrap().uuid, UUID);
        assert_eq!(
            list.check("00000000-0000-0000-0000-000000000001")
                .unwrap()
                .label,
            None
        );
        assert_eq!(
            list.check("00000000-0000-0000-0000-000000000002"),
            Err(Refusal::NotAllowed {
                uuid: "00000000-0000-0000-0000-000000000002".into()
            })
        );
    }

    #[test]
    fn invalid_uuid_syntax() {
        let list = Allowlist::parse("").unwrap();
        assert!(list.is_empty());
        for bad in [
            "",
            "not-a-uuid",
            "4c4c4544004235108051b4c04f4e3732",
            "{4c4c4544-0042-3510-8051-b4c04f4e3732}",
            "urn:uuid:4c4c4544-0042-3510-8051-b4c04f4e3732",
            "4c4c4544-0042-3510-8051-b4c04f4e373g",
            "../../sys/seal-status-0000000000000",
        ] {
            assert_eq!(list.check(bad), Err(Refusal::InvalidUuid), "{bad:?}");
        }
    }

    #[test]
    fn rejects_bad_files() {
        assert!(Allowlist::parse("[[node]]\nuuid = \"nope\"\n").is_err());
        assert!(
            Allowlist::parse(&format!(
                "[[node]]\nuuid = \"{UUID}\"\n[[node]]\nuuid = \"{UUID}\"\n"
            ))
            .is_err()
        );
        assert!(
            Allowlist::parse(&format!("[[node]]\nuuid = \"{UUID}\"\nhostname = \"x\"\n")).is_err()
        );
    }

    #[test]
    fn example_allowlist_parses() {
        let list = Allowlist::parse(include_str!("../examples/allowlist.toml")).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn reload_keeps_previous_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.toml");
        std::fs::write(&path, format!("[[node]]\nuuid = \"{UUID}\"\n")).unwrap();
        let shared = SharedAllowlist::load(&path).unwrap();
        let metrics = Metrics::new();

        std::fs::write(&path, "[[node]]\nuuid = \"broken\"\n").unwrap();
        shared.reload(&metrics);
        assert!(shared.get().check(UUID).is_ok());

        std::fs::write(&path, "").unwrap();
        shared.reload(&metrics);
        assert!(shared.get().check(UUID).is_err());
    }
}
