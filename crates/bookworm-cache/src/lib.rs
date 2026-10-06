//! Evidence-addressed cache (directive §14, §15, §26).
//!
//! Cached entries are keyed by the deterministic request identity (§26) but
//! *validity* never derives from the key or the path: a cached envelope is
//! only reusable while its recorded evidence identity — repository revision
//! plus content hashes — still matches the live target (§15: "A result MUST
//! NOT be considered valid merely because path == previous_path").
//!
//! Storage is a plain directory of JSON envelopes written atomically.
//! Single-process use in v1; multi-agent locking arrives with locksmith
//! integration (ROADMAP P5).

use bookworm_core::{Error, Result};
use bookworm_evidence::{EvidenceEnvelope, HashEntry};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct EvidenceCache {
    dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryMeta {
    pub request_id: String,
    pub target: String,
    pub revision: Option<String>,
    pub result_hash: String,
    pub created_unix: Option<u64>,
    pub bytes: u64,
}

impl EvidenceCache {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        Ok(EvidenceCache {
            dir: dir.to_path_buf(),
        })
    }

    /// Default cache location: `$BOOKWORM_CACHE_DIR`, else
    /// `$XDG_CACHE_HOME/bookworm`, else `~/.cache/bookworm`.
    pub fn default_dir() -> PathBuf {
        if let Ok(dir) = std::env::var("BOOKWORM_CACHE_DIR") {
            return PathBuf::from(dir);
        }
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("bookworm");
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".cache").join("bookworm")
    }

    fn path_for(&self, request_id: &str) -> PathBuf {
        // request ids are generated hex; refuse anything path-shaped.
        let safe: String = request_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        self.dir.join(format!("{safe}.json"))
    }

    /// Store an envelope atomically (temp file + rename).
    pub fn put(&self, envelope: &EvidenceEnvelope) -> Result<()> {
        let final_path = self.path_for(&envelope.request_id);
        let tmp_path = self.dir.join(format!(
            ".{}.tmp",
            final_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("entry")
        ));
        let json = envelope.to_json(true);
        {
            let mut f = fs::File::create(&tmp_path).map_err(|e| Error::io(&tmp_path, e))?;
            f.write_all(json.as_bytes())
                .map_err(|e| Error::io(&tmp_path, e))?;
        }
        fs::rename(&tmp_path, &final_path).map_err(|e| Error::io(&final_path, e))?;
        Ok(())
    }

    pub fn get(&self, request_id: &str) -> Option<EvidenceEnvelope> {
        let text = fs::read_to_string(self.path_for(request_id)).ok()?;
        EvidenceEnvelope::from_json(&text).ok()
    }

    pub fn entries(&self) -> Result<Vec<EntryMeta>> {
        let mut metas = Vec::new();
        let read = match fs::read_dir(&self.dir) {
            Ok(r) => r,
            Err(e) => return Err(Error::io(&self.dir, e)),
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if let Ok(env) = fs::read_to_string(&path).map_err(|e| Error::io(&path, e)) {
                if let Ok(envelope) = EvidenceEnvelope::from_json(&env) {
                    metas.push(EntryMeta {
                        request_id: envelope.request_id,
                        target: envelope.target.target.clone(),
                        revision: envelope.target.revision.clone(),
                        result_hash: envelope.identity.result_hash,
                        created_unix: envelope.timestamp_unix,
                        bytes,
                    });
                }
            }
        }
        metas.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        Ok(metas)
    }

    /// Remove one entry; returns true when an entry was removed.
    pub fn invalidate(&self, request_id: &str) -> Result<bool> {
        let path = self.path_for(request_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::io(&path, e)),
        }
    }

    /// Remove every entry; returns how many were removed.
    pub fn clear(&self) -> Result<usize> {
        let mut removed = 0;
        for meta in self.entries()? {
            if self.invalidate(&meta.request_id)? {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// §15 validity: cached knowledge is valid only while the recorded evidence
/// identity matches the current evidence identity. Any hash change invalidates.
pub fn identity_matches(stored: &[HashEntry], current: &[HashEntry]) -> bool {
    if stored.len() != current.len() {
        return false;
    }
    stored
        .iter()
        .zip(current.iter())
        .all(|(s, c)| s.path == c.path && s.sha256.eq_ignore_ascii_case(&c.sha256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bookworm_core::{ContextRequest, ReadIntent, Target};

    fn envelope(id_seed: &str, hash: &str) -> EvidenceEnvelope {
        let mut req = ContextRequest::new(
            ReadIntent::Read,
            vec![Target::File {
                path: id_seed.into(),
            }],
        );
        req.question = Some(format!("seed:{id_seed}:{hash}"));
        let mut env = EvidenceEnvelope::new(
            req.request_id(),
            bookworm_evidence::TargetIdentity {
                repository: None,
                revision: None,
                working_tree: None,
                target: id_seed.into(),
                target_kind: "file".into(),
                canonical_path: id_seed.into(),
            },
        );
        env.identity.source_hashes = bookworm_evidence::single_source_hash(id_seed, hash);
        env.finalize()
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = EvidenceCache::open(dir.path()).unwrap();
        let env = envelope("/tmp/a.rs", "aaaa");
        cache.put(&env).unwrap();
        let back = cache.get(&env.request_id).unwrap();
        assert_eq!(back.identity.result_hash, env.identity.result_hash);
    }

    #[test]
    fn invalidate_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let cache = EvidenceCache::open(dir.path()).unwrap();
        let a = envelope("/tmp/a.rs", "aaaa");
        let b = envelope("/tmp/b.rs", "bbbb");
        cache.put(&a).unwrap();
        cache.put(&b).unwrap();
        assert!(cache.invalidate(&a.request_id).unwrap());
        assert!(!cache.invalidate(&a.request_id).unwrap());
        assert_eq!(cache.entries().unwrap().len(), 1);
        assert_eq!(cache.clear().unwrap(), 1);
        assert!(cache.entries().unwrap().is_empty());
    }

    #[test]
    fn path_shaped_ids_cannot_escape_the_cache_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cache = EvidenceCache::open(dir.path()).unwrap();
        assert!(cache.get("../../etc/passwd").is_none());
        let before = cache.entries().unwrap().len();
        assert_eq!(before, 0);
    }

    #[test]
    fn identity_validity_semantics() {
        let stored = bookworm_evidence::single_source_hash("/x.rs", "aa");
        assert!(identity_matches(
            &stored,
            &bookworm_evidence::single_source_hash("/x.rs", "aa")
        ));
        assert!(identity_matches(
            &stored,
            &bookworm_evidence::single_source_hash("/x.rs", "AA")
        ));
        // Changed content invalidates — path equality is not validity (§15).
        assert!(!identity_matches(
            &stored,
            &bookworm_evidence::single_source_hash("/x.rs", "bb")
        ));
        assert!(!identity_matches(&stored, &[]));
    }
}
