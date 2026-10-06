//! Local PISA-shaped store (directive §14, §15).
//!
//! This is not a network client for an external PISA service. It stores
//! Bookworm claims under an evidence identity so a later request can reuse
//! them when the source hashes still match, and must treat them as stale
//! when they do not.

use bookworm_core::{Claim, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashRef {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub key: String,
    pub intent: String,
    pub question: Option<String>,
    pub target: String,
    pub revision: Option<String>,
    pub source_hashes: Vec<HashRef>,
    pub request_id: String,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    Miss,
    Fresh(Record),
    Stale(Record),
}

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        Ok(Store {
            dir: dir.to_path_buf(),
        })
    }

    pub fn put(&self, record: &Record) -> Result<()> {
        let path = self.path_for(&record.key);
        let tmp = self.dir.join(format!(".{}.tmp", record.key));
        let json = serde_json::to_string_pretty(record).map_err(|e| Error::Cache {
            detail: format!("pisa serialize: {e}"),
        })?;
        {
            let mut file = fs::File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
            file.write_all(json.as_bytes())
                .map_err(|e| Error::io(&tmp, e))?;
        }
        fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))?;
        Ok(())
    }

    pub fn lookup(&self, key: &str, current: &[HashRef]) -> Lookup {
        let path = self.path_for(key);
        let Ok(text) = fs::read_to_string(&path) else {
            return Lookup::Miss;
        };
        let Ok(record) = serde_json::from_str::<Record>(&text) else {
            return Lookup::Miss;
        };
        if hashes_match(&record.source_hashes, current) {
            Lookup::Fresh(record)
        } else {
            Lookup::Stale(record)
        }
    }
}

/// Identity that also binds fidelity and the caller token ceiling, so a
/// later request with a different budget is not treated as the same acquisition.
pub fn scoped_key(intent: &str, target: &str, fidelity: &str, max_tokens: Option<u64>) -> String {
    let budget = match max_tokens {
        Some(n) => n.to_string(),
        None => "none".to_string(),
    };
    let question = format!("fidelity={fidelity};budget={budget}");
    record_key(intent, Some(&question), target)
}

pub fn record_key(intent: &str, question: Option<&str>, target: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(intent.as_bytes());
    hasher.update([0]);
    hasher.update(question.unwrap_or("").as_bytes());
    hasher.update([0]);
    hasher.update(target.as_bytes());
    hex::encode(hasher.finalize())
}

fn hashes_match(stored: &[HashRef], current: &[HashRef]) -> bool {
    if stored.len() != current.len() {
        return false;
    }
    stored.iter().zip(current.iter()).all(|(s, c)| {
        s.path == c.path && s.sha256.eq_ignore_ascii_case(&c.sha256)
    })
}

impl Store {
    fn path_for(&self, key: &str) -> PathBuf {
        let safe: String = key
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        self.dir.join(format!("{safe}.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_then_stale_when_hash_changes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = record_key("read", None, "/tmp/a.rs");
        let record = Record {
            key: key.clone(),
            intent: "read".into(),
            question: None,
            target: "/tmp/a.rs".into(),
            revision: None,
            source_hashes: vec![HashRef {
                path: "/tmp/a.rs".into(),
                sha256: "abc".into(),
            }],
            request_id: "bw-req-1".into(),
            claims: Vec::new(),
        };
        store.put(&record).unwrap();
        assert!(matches!(
            store.lookup(&key, &record.source_hashes),
            Lookup::Fresh(_)
        ));
        let changed = vec![HashRef {
            path: "/tmp/a.rs".into(),
            sha256: "def".into(),
        }];
        assert!(matches!(store.lookup(&key, &changed), Lookup::Stale(_)));
    }
}
