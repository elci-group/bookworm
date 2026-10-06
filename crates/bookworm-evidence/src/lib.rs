//! The BOOKWORM/1 evidence envelope (directive §12): machine-readable
//! provenance for every substantive response, plus deterministic result
//! hashing.
//!
//! The envelope exists so an orchestrator can distinguish "Bookworm looked at
//! the entire relevant module" from "Bookworm found three apparently relevant
//! files" — epistemically different states that must never be represented
//! identically (§12).
//!
//! `result_hash` covers everything except the wall-clock timestamp, the
//! cache-hit marker and itself, so repeated acquisition of unchanged evidence
//! under an equal request yields an identical hash (BW-G01, BW-I06).

use bookworm_core::{Claim, Coverage, Error, Result, ENVELOPE_VERSION};
use bookworm_resolver::{Inventory, ResolvedTarget};
use bookworm_verify::VerificationReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetIdentity {
    pub repository: Option<String>,
    pub revision: Option<String>,
    /// "clean" | "dirty" | None when not inside a repository.
    pub working_tree: Option<String>,
    pub target: String,
    pub target_kind: String,
    pub canonical_path: String,
}

impl TargetIdentity {
    pub fn from_resolved(resolved: &ResolvedTarget) -> Self {
        let (repository, revision, working_tree) = match &resolved.repository {
            Some(repo) => (
                Some(repo.root.to_string_lossy().into_owned()),
                repo.revision.clone(),
                Some(if repo.dirty {
                    "dirty".to_string()
                } else {
                    "clean".to_string()
                }),
            ),
            None => (None, None, None),
        };
        TargetIdentity {
            repository,
            revision,
            working_tree,
            target: resolved.requested.to_string_lossy().into_owned(),
            target_kind: resolved.kind.as_str().to_string(),
            canonical_path: resolved.canonical.to_string_lossy().into_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasurementBlock {
    pub files_discovered: u64,
    pub files_considered: u64,
    pub files_read: u64,
    pub lines_read: u64,
    pub bytes_read: u64,
    /// Estimated tokens of acquired evidence; `None` when no estimate exists.
    pub tokens_ingested: Option<u64>,
    pub estimation_method: Option<String>,
}

impl Default for MeasurementBlock {
    fn default() -> Self {
        MeasurementBlock {
            files_discovered: 0,
            files_considered: 0,
            files_read: 0,
            lines_read: 0,
            bytes_read: 0,
            tokens_ingested: None,
            estimation_method: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyBlock {
    pub classification: String,
    pub language: Option<String>,
    pub ingestion_strategy: String,
    /// Name of the reader that produced the package. `deterministic` and
    /// `structural` are local readers. `None` means no reader ran.
    pub reader_model: Option<String>,
    pub consensus_mode: String,
    pub coverage: Coverage,
    pub omissions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ContentPayload {
    Text { text: String, lines: u64 },
    Binary { bytes: u64 },
}

/// A single located finding (used by `locate` and `map` outputs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    pub line_start: u64,
    pub line_end: u64,
    pub excerpt: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutputBlock {
    /// "complete" | "partial" | "failed" — an honest terminal state (§18).
    pub status: String,
    pub content: Option<ContentPayload>,
    pub findings: Vec<Finding>,
    pub claims: Vec<Claim>,
    pub citations: Vec<bookworm_core::EvidenceSpan>,
    pub unknowns: Vec<String>,
    pub conflicts: Vec<String>,
}

impl Default for OutputBlock {
    fn default() -> Self {
        OutputBlock {
            status: "complete".to_string(),
            content: None,
            findings: Vec::new(),
            claims: Vec::new(),
            citations: Vec::new(),
            unknowns: Vec::new(),
            conflicts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashEntry {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityBlock {
    pub source_hashes: Vec<HashEntry>,
    pub result_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEnvelope {
    pub version: String,
    pub request_id: String,
    /// Wall-clock acquisition time (unix seconds). Excluded from
    /// `result_hash` so equal evidence stays hash-equal (BW-G01).
    pub timestamp_unix: Option<u64>,
    /// Served from the evidence cache against unchanged identity (§14/§15).
    /// Excluded from `result_hash`.
    pub cache_hit: bool,
    /// `fresh`, `stale`, or `miss` from the local PISA store. Excluded from
    /// `result_hash` so a lookup does not change evidence identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pisa_status: Option<String>,
    pub target: TargetIdentity,
    pub measurement: MeasurementBlock,
    pub strategy: StrategyBlock,
    pub verification: VerificationReport,
    pub output: OutputBlock,
    pub identity: IdentityBlock,
}

impl EvidenceEnvelope {
    pub fn new(request_id: String, target: TargetIdentity) -> Self {
        EvidenceEnvelope {
            version: ENVELOPE_VERSION.to_string(),
            request_id,
            timestamp_unix: None,
            cache_hit: false,
            pisa_status: None,
            target,
            measurement: MeasurementBlock::default(),
            strategy: StrategyBlock {
                classification: "unknown".to_string(),
                language: None,
                ingestion_strategy: "tier0_deterministic".to_string(),
                reader_model: None,
                consensus_mode: "NONE".to_string(),
                coverage: Coverage::Unknown,
                omissions: Vec::new(),
            },
            verification: VerificationReport::empty(),
            output: OutputBlock::default(),
            identity: IdentityBlock {
                source_hashes: Vec::new(),
                result_hash: String::new(),
            },
        }
    }

    pub fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// SHA-256 over the canonical envelope with the non-evidence fields
    /// (timestamp, cache marker, result hash itself) zeroed out.
    pub fn compute_result_hash(&self) -> String {
        let mut canonical = self.clone();
        canonical.timestamp_unix = None;
        canonical.cache_hit = false;
        canonical.pisa_status = None;
        canonical.identity.result_hash = String::new();
        let bytes = serde_json::to_vec(&canonical).expect("envelope serialization is total");
        hex::encode(Sha256::digest(&bytes))
    }

    /// Stamp the result hash and the acquisition timestamp. Call exactly once,
    /// after all evidence blocks are populated.
    pub fn finalize(mut self) -> Self {
        let hash = self.compute_result_hash();
        self.identity.result_hash = hash;
        self.timestamp_unix = Some(Self::now_unix());
        self
    }

    pub fn to_json(&self, pretty: bool) -> String {
        if pretty {
            serde_json::to_string_pretty(self).expect("envelope serialization is total")
        } else {
            serde_json::to_string(self).expect("envelope serialization is total")
        }
    }

    pub fn from_json(text: &str) -> Result<Self> {
        serde_json::from_str(text).map_err(|e| Error::Cache {
            detail: format!("corrupt envelope: {e}"),
        })
    }
}

/// Convenience: identity entries for a single measured source file.
pub fn single_source_hash(path: &str, sha256: &str) -> Vec<HashEntry> {
    vec![HashEntry {
        path: path.to_string(),
        sha256: sha256.to_string(),
    }]
}

/// Inventory-level citation: hash over the deterministic listing itself, so
/// directory claims remain identity-bound (§I06).
pub fn inventory_hash(inv: &Inventory) -> String {
    let mut listing = String::new();
    for entry in &inv.entries {
        listing.push_str(&entry.path);
        listing.push('\t');
        listing.push_str(entry.kind.as_str());
        listing.push('\t');
        listing.push_str(&entry.size_bytes.to_string());
        listing.push('\n');
    }
    hex::encode(Sha256::digest(listing.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bookworm_core::ReadIntent;
    use bookworm_verify::Check;

    fn sample_envelope() -> EvidenceEnvelope {
        let req = bookworm_core::ContextRequest::new(
            ReadIntent::Read,
            vec![bookworm_core::Target::File {
                path: "/tmp/x.rs".into(),
            }],
        );
        let mut env = EvidenceEnvelope::new(
            req.request_id(),
            TargetIdentity {
                repository: Some("/repo".into()),
                revision: Some("abc123".into()),
                working_tree: Some("clean".into()),
                target: "/tmp/x.rs".into(),
                target_kind: "file".into(),
                canonical_path: "/repo/x.rs".into(),
            },
        );
        env.strategy.classification = "source_code".into();
        env.strategy.coverage = Coverage::Exhaustive;
        env.identity.source_hashes = single_source_hash("/repo/x.rs", "cafebabe");
        env
    }

    #[test]
    fn result_hash_is_deterministic_across_time_and_cache_state() {
        let a = sample_envelope().finalize();
        let mut b = sample_envelope().finalize();
        // Different timestamp and cache marker must not change the hash.
        b.timestamp_unix = Some(1);
        b.cache_hit = true;
        b.pisa_status = Some("fresh".to_string());
        assert_eq!(a.identity.result_hash, b.compute_result_hash());
    }

    #[test]
    fn result_hash_tracks_content() {
        let a = sample_envelope().finalize();
        let mut b = sample_envelope();
        b.strategy.classification = "markup".into();
        let b = b.finalize();
        assert_ne!(a.identity.result_hash, b.identity.result_hash);
    }

    #[test]
    fn json_roundtrip_preserves_hash() {
        let env = sample_envelope().finalize();
        let json = env.to_json(true);
        let back = EvidenceEnvelope::from_json(&json).unwrap();
        assert_eq!(back, env);
        assert_eq!(back.identity.result_hash, env.identity.result_hash);
    }

    #[test]
    fn empty_verification_report_serializes() {
        let env = sample_envelope().finalize();
        assert_eq!(env.verification.attempted, 0);
        let report = bookworm_verify::run(&[Check::PathExists {
            path: "/nonexistent-bw".into(),
        }]);
        assert_eq!(report.failed, 1);
    }
}
