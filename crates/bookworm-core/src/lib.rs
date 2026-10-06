//! Bookworm core: the typed request model and the shared evidence vocabulary.
//!
//! Implements directive §4 (Request Model), §I05 (uncertainty states),
//! §11 (Claim Model), §17 (Coverage Semantics) and the shared encoding
//! vocabulary used by resolution, measurement and classification.
//!
//! This crate is pure data and pure functions: no filesystem I/O, no
//! wall-clock reads, no inference. Everything here is deterministic by
//! construction (BW-I01).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Path, PathBuf};

/// Envelope schema identifier (§12).
pub const ENVELOPE_VERSION: &str = "BOOKWORM/1";

// ---------------------------------------------------------------------------
// Errors — §18: fail closed, report the failure state, never fabricate
// completion.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    TargetMissing {
        path: PathBuf,
    },
    PermissionDenied {
        path: PathBuf,
    },
    OutsideScope {
        path: PathBuf,
        root: PathBuf,
    },
    UnsupportedEncoding {
        path: PathBuf,
        detail: String,
    },
    AmbiguousTarget {
        detail: String,
    },
    BudgetImpossible {
        detail: String,
    },
    UnsupportedWithoutReader {
        detail: String,
    },
    Verification {
        detail: String,
    },
    Cache {
        detail: String,
    },
    Usage {
        detail: String,
    },
    Io {
        source: std::io::Error,
        path: PathBuf,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TargetMissing { path } => write!(f, "target missing: {}", path.display()),
            Error::PermissionDenied { path } => write!(f, "permission denied: {}", path.display()),
            Error::OutsideScope { path, root } => {
                write!(
                    f,
                    "target {} is outside the authorised scope root {}",
                    path.display(),
                    root.display()
                )
            }
            Error::UnsupportedEncoding { path, detail } => {
                write!(f, "unsupported encoding for {}: {}", path.display(), detail)
            }
            Error::AmbiguousTarget { detail } => write!(f, "ambiguous target: {detail}"),
            Error::BudgetImpossible { detail } => write!(f, "token budget impossible: {detail}"),
            Error::UnsupportedWithoutReader { detail } => {
                write!(f, "unsupported without reader integration: {detail}")
            }
            Error::Verification { detail } => write!(f, "verification failure: {detail}"),
            Error::Cache { detail } => write!(f, "cache failure: {detail}"),
            Error::Usage { detail } => write!(f, "usage error: {detail}"),
            Error::Io { source, path } => write!(f, "I/O error on {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    /// Attach a path to a raw I/O error.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            source,
            path: path.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Request model — §4
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadIntent {
    Read,
    Locate,
    Explain,
    Summarise,
    Extract,
    Compare,
    Trace,
    Verify,
    Impact,
    Map,
}

impl ReadIntent {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(ReadIntent::Read),
            "locate" => Some(ReadIntent::Locate),
            "explain" => Some(ReadIntent::Explain),
            "summarise" | "summarize" => Some(ReadIntent::Summarise),
            "extract" => Some(ReadIntent::Extract),
            "compare" => Some(ReadIntent::Compare),
            "trace" => Some(ReadIntent::Trace),
            "verify" => Some(ReadIntent::Verify),
            "impact" => Some(ReadIntent::Impact),
            "map" => Some(ReadIntent::Map),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ReadIntent::Read => "read",
            ReadIntent::Locate => "locate",
            ReadIntent::Explain => "explain",
            ReadIntent::Summarise => "summarise",
            ReadIntent::Extract => "extract",
            ReadIntent::Compare => "compare",
            ReadIntent::Trace => "trace",
            ReadIntent::Verify => "verify",
            ReadIntent::Impact => "impact",
            ReadIntent::Map => "map",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    File {
        path: PathBuf,
    },
    Directory {
        path: PathBuf,
    },
    Repository {
        path: PathBuf,
    },
    Revision {
        repo: PathBuf,
        revision: String,
    },
    Symbol {
        name: String,
        scope: Option<PathBuf>,
    },
    LineRange {
        path: PathBuf,
        start: u64,
        end: u64,
    },
    Glob {
        pattern: String,
        root: PathBuf,
    },
    Dependency {
        name: String,
        manifest: Option<PathBuf>,
    },
    Configuration {
        key: String,
        path: Option<PathBuf>,
    },
    Stdin,
    Url {
        url: String,
    },
}

impl Target {
    /// Primary filesystem path of the target, if any.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Target::File { path }
            | Target::Directory { path }
            | Target::Repository { path }
            | Target::Revision { repo: path, .. }
            | Target::Symbol {
                scope: Some(path), ..
            }
            | Target::LineRange { path, .. }
            | Target::Glob { root: path, .. }
            | Target::Dependency {
                manifest: Some(path),
                ..
            }
            | Target::Configuration {
                path: Some(path), ..
            } => Some(path),
            _ => None,
        }
    }

    /// Compact human-readable description used inside envelopes.
    pub fn describe(&self) -> String {
        match self {
            Target::File { path } => format!("file:{}", path.display()),
            Target::Directory { path } => format!("directory:{}", path.display()),
            Target::Repository { path } => format!("repository:{}", path.display()),
            Target::Revision { repo, revision } => {
                format!("revision:{revision}@{}", repo.display())
            }
            Target::Symbol { name, scope } => match scope {
                Some(p) => format!("symbol:{name} in {}", p.display()),
                None => format!("symbol:{name}"),
            },
            Target::LineRange { path, start, end } => {
                format!("lines:{start}-{end}@{}", path.display())
            }
            Target::Glob { pattern, root } => format!("glob:{pattern} in {}", root.display()),
            Target::Dependency { name, manifest } => match manifest {
                Some(p) => format!("dependency:{name} in {}", p.display()),
                None => format!("dependency:{name}"),
            },
            Target::Configuration { key, path } => match path {
                Some(p) => format!("configuration:{key} in {}", p.display()),
                None => format!("configuration:{key}"),
            },
            Target::Stdin => "stdin".to_string(),
            Target::Url { url } => format!("url:{url}"),
        }
    }
}

/// Requested evidence fidelity. Ordered from least to most compression;
/// `Raw`/`Lossless` can be satisfied without any lossy step (BW-I02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fidelity {
    Raw,
    Lossless,
    Selective,
    Structural,
    Extractive,
    Semantic,
}

impl Fidelity {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "raw" => Some(Fidelity::Raw),
            "lossless" => Some(Fidelity::Lossless),
            "selective" => Some(Fidelity::Selective),
            "structural" => Some(Fidelity::Structural),
            "extractive" => Some(Fidelity::Extractive),
            "semantic" => Some(Fidelity::Semantic),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Fidelity::Raw => "raw",
            Fidelity::Lossless => "lossless",
            Fidelity::Selective => "selective",
            Fidelity::Structural => "structural",
            Fidelity::Extractive => "extractive",
            Fidelity::Semantic => "semantic",
        }
    }

    /// True when this fidelity demand can be met by a lossless read.
    pub fn lossless_ok(&self) -> bool {
        matches!(self, Fidelity::Raw | Fidelity::Lossless)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct Budget {
    /// Hard ceiling on input tokens for any single ingestion plan.
    pub max_input_tokens: Option<u64>,
    /// Abstract cost ceiling; units are defined by the routing layer.
    pub max_cost_units: Option<f64>,
    /// Output tokens reserved on the reader model (§7: O).
    pub reserved_output_tokens: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_input_tokens: None,
            max_cost_units: None,
            reserved_output_tokens: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPolicy {
    Off,
    Standard,
    Strict,
}

impl VerificationPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(VerificationPolicy::Off),
            "standard" => Some(VerificationPolicy::Standard),
            "strict" => Some(VerificationPolicy::Strict),
            _ => None,
        }
    }
}

/// v1 is inference-free and therefore local-only by construction (§19).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyPolicy {
    pub local_only: bool,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        PrivacyPolicy { local_only: true }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessPolicy {
    /// Revalidate against current evidence identity (hash + revision).
    Latest,
    /// Pin to a specific repository revision (§I06).
    Pinned(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextRequest {
    pub intent: ReadIntent,
    pub targets: Vec<Target>,
    pub question: Option<String>,
    pub fidelity: Fidelity,
    pub budget: Budget,
    pub verification: VerificationPolicy,
    pub privacy: PrivacyPolicy,
    pub freshness: FreshnessPolicy,
}

impl ContextRequest {
    pub fn new(intent: ReadIntent, targets: Vec<Target>) -> Self {
        ContextRequest {
            intent,
            targets,
            question: None,
            fidelity: Fidelity::Lossless,
            budget: Budget::default(),
            verification: VerificationPolicy::Standard,
            privacy: PrivacyPolicy::default(),
            freshness: FreshnessPolicy::Latest,
        }
    }

    /// Canonical JSON. Struct field order is fixed by serde, so serialization
    /// of equal requests is byte-identical — the basis for the §26 operation
    /// identity and deterministic request ids.
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).expect("ContextRequest serialization is total")
    }

    /// Deterministic request identity: `bw-req-` + first 12 hex of SHA-256
    /// over the canonical request. Equal requests yield equal ids (§26 step
    /// deduplication); the id contains no timestamp (BW-G01).
    pub fn request_id(&self) -> String {
        let digest = Sha256::digest(self.canonical_json().as_bytes());
        let hexed = hex::encode(digest);
        format!("bw-req-{}", &hexed[..12])
    }
}

// ---------------------------------------------------------------------------
// Uncertainty states — §I05 / §11 claim statuses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    /// Known: established by deterministic evidence.
    Verified,
    Unverified,
    Inferred,
    Ambiguous,
    Conflicting,
    Unknown,
}

impl ClaimStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaimStatus::Verified => "verified",
            ClaimStatus::Unverified => "unverified",
            ClaimStatus::Inferred => "inferred",
            ClaimStatus::Ambiguous => "ambiguous",
            ClaimStatus::Conflicting => "conflicting",
            ClaimStatus::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Coverage semantics — §17
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Exhaustive,
    StructurallyExhaustive,
    Targeted,
    Sampled,
    Partial,
    Unknown,
}

impl Coverage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Coverage::Exhaustive => "exhaustive",
            Coverage::StructurallyExhaustive => "structurally_exhaustive",
            Coverage::Targeted => "targeted",
            Coverage::Sampled => "sampled",
            Coverage::Partial => "partial",
            Coverage::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Claim model — §11
// ---------------------------------------------------------------------------

/// A provenance span: path, 1-based inclusive line range, and the SHA-256 of
/// the covered content. For v1 the hash is the whole-file blob hash; range
/// fingerprints arrive with structural integration (§15).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceSpan {
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    pub statement: String,
    pub status: ClaimStatus,
    pub confidence: Option<f64>,
    pub evidence: Vec<EvidenceSpan>,
    pub verification: Vec<String>,
}

impl Claim {
    /// A deterministic, machine-established claim: status `verified`,
    /// confidence 1.0, with the methods that established it.
    pub fn deterministic(
        claim_id: &str,
        statement: String,
        evidence: Vec<EvidenceSpan>,
        methods: Vec<String>,
    ) -> Self {
        Claim {
            claim_id: claim_id.to_string(),
            statement,
            status: ClaimStatus::Verified,
            confidence: Some(1.0),
            evidence,
            verification: methods,
        }
    }

    /// A claim Bookworm cannot establish and will not guess (§I05).
    pub fn unknown(claim_id: &str, statement: String) -> Self {
        Claim {
            claim_id: claim_id.to_string(),
            statement,
            status: ClaimStatus::Unknown,
            confidence: None,
            evidence: Vec::new(),
            verification: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding vocabulary — shared by resolver (§5), classify (§6) and measure (§7)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    /// NUL byte detected in the sniff window.
    Binary,
    /// Not valid UTF-8 and no BOM: possibly non-UTF-8 text. Treated as
    /// unreadable text; content operations fail closed (§18).
    UnknownText,
}

impl Encoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::Utf8 => "utf-8",
            Encoding::Utf8Bom => "utf-8-bom",
            Encoding::Utf16Le => "utf-16le",
            Encoding::Utf16Be => "utf-16be",
            Encoding::Binary => "binary",
            Encoding::UnknownText => "unknown-text",
        }
    }

    pub fn is_text(&self) -> bool {
        matches!(
            self,
            Encoding::Utf8 | Encoding::Utf8Bom | Encoding::Utf16Le | Encoding::Utf16Be
        )
    }
}

/// Bytes examined by [`sniff_encoding`]. 8 KiB is enough to see a BOM, a NUL
/// and a representative prefix for UTF-8 validation.
pub const SNIFF_WINDOW: usize = 8192;

/// Deterministic encoding sniff over a content prefix.
pub fn sniff_encoding(head: &[u8]) -> Encoding {
    if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Encoding::Utf8Bom;
    }
    if head.starts_with(&[0xFF, 0xFE]) {
        return Encoding::Utf16Le;
    }
    if head.starts_with(&[0xFE, 0xFF]) {
        return Encoding::Utf16Be;
    }
    if head.contains(&0u8) {
        return Encoding::Binary;
    }
    match std::str::from_utf8(head) {
        Ok(_) => Encoding::Utf8,
        // A multibyte character cut at the window edge is not evidence of
        // non-UTF-8 content.
        Err(e) if e.error_len().is_none() && head.len() - e.valid_up_to() <= 3 => Encoding::Utf8,
        Err(_) => Encoding::UnknownText,
    }
}

/// Decode content to text according to the sniffed encoding. Returns `None`
/// for binary/unknown encodings rather than guessing (§I05).
pub fn decode_text(bytes: &[u8], encoding: Encoding) -> Option<String> {
    match encoding {
        Encoding::Utf8 => std::str::from_utf8(bytes).ok().map(str::to_string),
        Encoding::Utf8Bom => {
            let body = bytes.get(3..).unwrap_or(bytes);
            std::str::from_utf8(body).ok().map(str::to_string)
        }
        Encoding::Utf16Le => {
            let body = bytes.get(2..).unwrap_or(bytes);
            let units: Vec<u16> = body
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units).ok()
        }
        Encoding::Utf16Be => {
            let body = bytes.get(2..).unwrap_or(bytes);
            let units: Vec<u16> = body
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units).ok()
        }
        Encoding::Binary | Encoding::UnknownText => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_stable_and_path_sensitive() {
        let a = ContextRequest::new(
            ReadIntent::Read,
            vec![Target::File {
                path: "/tmp/x.rs".into(),
            }],
        );
        let b = ContextRequest::new(
            ReadIntent::Read,
            vec![Target::File {
                path: "/tmp/x.rs".into(),
            }],
        );
        assert_eq!(a.request_id(), b.request_id());
        let c = ContextRequest::new(
            ReadIntent::Read,
            vec![Target::File {
                path: "/tmp/y.rs".into(),
            }],
        );
        assert_ne!(a.request_id(), c.request_id());
        assert!(a.request_id().starts_with("bw-req-"));
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let a = ContextRequest::new(
            ReadIntent::Map,
            vec![Target::Directory {
                path: "/repo".into(),
            }],
        );
        let b = a.clone();
        assert_eq!(a.canonical_json(), b.canonical_json());
    }

    #[test]
    fn sniff_detects_bom_binary_and_truncated_utf8() {
        assert_eq!(sniff_encoding(&[0xEF, 0xBB, 0xBF, b'a']), Encoding::Utf8Bom);
        assert_eq!(sniff_encoding(&[0xFF, 0xFE, 0x61, 0x00]), Encoding::Utf16Le);
        assert_eq!(sniff_encoding(b"ab\x00cd"), Encoding::Binary);
        assert_eq!(sniff_encoding(b"plain text"), Encoding::Utf8);
        // 4-byte emoji truncated to its first 3 bytes at the window edge.
        let mut edge = vec![b'x'; SNIFF_WINDOW - 3];
        edge.push(0xF0);
        edge.push(0x9F);
        edge.push(0x92);
        assert_eq!(sniff_encoding(&edge), Encoding::Utf8);
        assert_eq!(sniff_encoding(b"\xffbad"), Encoding::UnknownText);
    }

    #[test]
    fn decode_utf16_roundtrip() {
        let text = "héllo wörld";
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut bytes = vec![0xFF, 0xFE];
        for u in units {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(sniff_encoding(&bytes), Encoding::Utf16Le);
        assert_eq!(
            decode_text(&bytes, Encoding::Utf16Le).as_deref(),
            Some(text)
        );
    }

    #[test]
    fn decode_binary_is_none() {
        assert!(decode_text(&[0, 1, 2], Encoding::Binary).is_none());
        assert!(decode_text(b"\xff\xfe", Encoding::UnknownText).is_none());
    }

    #[test]
    fn fidelity_and_intent_parse() {
        assert_eq!(Fidelity::parse("lossless"), Some(Fidelity::Lossless));
        assert_eq!(Fidelity::parse("nope"), None);
        assert!(Fidelity::Lossless.lossless_ok());
        assert!(!Fidelity::Semantic.lossless_ok());
        assert_eq!(ReadIntent::parse("summarize"), Some(ReadIntent::Summarise));
        assert_eq!(
            VerificationPolicy::parse("strict"),
            Some(VerificationPolicy::Strict)
        );
    }
}
