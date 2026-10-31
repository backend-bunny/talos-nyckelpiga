//! Change detection for mounted files by polling their contents.
//!
//! Kubernetes updates Secret and ConfigMap volumes by swapping a `..data`
//! symlink, which inotify on the file path doesn't reliably report. Hashing
//! the contents on a timer catches every update, including one that swaps
//! several files (certificate and key) at once.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;

use anyhow::Context;
use zeroize::Zeroizing;

pub struct FileWatch {
    paths: Vec<PathBuf>,
    last: Option<u64>,
}

/// File contents, wiped on drop (one of the watched files is a private key).
pub type Contents = Zeroizing<Vec<u8>>;

impl FileWatch {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths, last: None }
    }

    /// Read every file, in order, and remember their combined hash.
    pub fn read(&mut self) -> anyhow::Result<Vec<Contents>> {
        let files = self.read_all()?;
        self.last = Some(hash(&files));
        Ok(files)
    }

    /// Like [`Self::read`], but `None` when nothing changed since the last read.
    pub fn read_if_changed(&mut self) -> anyhow::Result<Option<Vec<Contents>>> {
        let files = self.read_all()?;
        let h = hash(&files);
        if self.last == Some(h) {
            return Ok(None);
        }
        self.last = Some(h);
        Ok(Some(files))
    }

    /// Forget the last contents, so the next [`Self::read_if_changed`]
    /// returns the files again. Used when the caller rejected them: a broken
    /// update is retried (and reported) every tick until it is fixed.
    pub fn invalidate(&mut self) {
        self.last = None;
    }

    fn read_all(&self) -> anyhow::Result<Vec<Contents>> {
        self.paths
            .iter()
            .map(|p| {
                std::fs::read(p)
                    .map(Zeroizing::new)
                    .with_context(|| format!("reading {}", p.display()))
            })
            .collect()
    }
}

fn hash(files: &[Contents]) -> u64 {
    let mut h = DefaultHasher::new();
    for f in files {
        f.as_slice().hash(&mut h);
    }
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_changes() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, "1").unwrap();
        std::fs::write(&b, "2").unwrap();
        let mut w = FileWatch::new(vec![a.clone(), b.clone()]);
        let first = w.read().unwrap();
        assert_eq!(first[0].as_slice(), b"1");
        assert!(w.read_if_changed().unwrap().is_none());
        std::fs::write(&b, "3").unwrap();
        let changed = w.read_if_changed().unwrap().unwrap();
        assert_eq!(changed[1].as_slice(), b"3");
        assert!(w.read_if_changed().unwrap().is_none());
        std::fs::remove_file(&a).unwrap();
        assert!(w.read_if_changed().is_err());
    }
}
