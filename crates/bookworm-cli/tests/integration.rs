//! End-to-end pipeline tests over the CLI library surface. These exercise
//! the acceptance gates that the deterministic core can prove: G01
//! (determinism), G02 (revision integrity plumbing), G03 (provenance),
//! G04 (budget compliance), G05 (honest coverage), G08 (cache correctness).

use bookworm_budget::default_model;
use bookworm_cache::EvidenceCache;
use bookworm_classify::classify;
use bookworm_cli::{assemble_read, locate, locate_envelope, read_with_cache};
use bookworm_core::{ClaimStatus, Coverage, Error, Fidelity, FreshnessPolicy};
use bookworm_evidence::TargetIdentity;
use bookworm_measure::measure_file;
use bookworm_policy::ScopePolicy;
use bookworm_resolver::resolve;
use std::fs;
use std::path::Path;

fn fixture_file(name: &str, content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    fs::write(&path, content).expect("write fixture");
    (dir, path)
}

fn read_envelope_for(path: &Path) -> bookworm_evidence::EvidenceEnvelope {
    read_with_cache(
        path,
        Fidelity::Lossless,
        &default_model(),
        None,
        None,
        None,
        &ScopePolicy::unrestricted(),
    )
    .expect("read pipeline")
    .envelope
}

#[test]
fn read_envelope_is_deterministic_and_provenance_bound() {
    let (_dir, path) = fixture_file("auth.rs", "pub fn issue() {}\npub fn refresh() {}\n");

    let e1 = read_envelope_for(&path);
    let e2 = read_envelope_for(&path);
    assert_eq!(
        e1.identity.result_hash, e2.identity.result_hash,
        "G01: identical evidence must hash identically"
    );
    assert_eq!(e1.request_id, e2.request_id);

    // G03: claims carry evidence spans whose hash matches the measured blob.
    let (_, m) = measure_file(&path).unwrap();
    assert_eq!(e1.identity.source_hashes.len(), 1);
    assert_eq!(e1.identity.source_hashes[0].sha256, m.sha256);
    for claim in &e1.output.claims {
        assert!(
            !claim.evidence.is_empty(),
            "claim without evidence: {}",
            claim.statement
        );
        assert!(claim.evidence.iter().all(|s| s.hash == m.sha256));
        assert_eq!(claim.status, ClaimStatus::Verified);
    }

    // Lossless content attached with exhaustive coverage.
    assert_eq!(e1.output.status, "complete");
    assert_eq!(e1.strategy.coverage, Coverage::Exhaustive);
    assert!(e1.output.content.is_some());
    assert!(e1.verification.passed >= 1, "hash re-verification must run");
}

#[test]
fn oversized_target_reports_partial_with_unknown_coverage() {
    // ~1.6 MB of text ≈ ~400k estimated tokens: far beyond every builtin
    // model's net context.
    let line = "fn pad() { let x = 1; let y = 2; let z = 3; }\n";
    let big: String = line.repeat(30_000);
    let (_dir, path) = fixture_file("big.rs", &big);

    let env = read_envelope_for(&path);
    assert_eq!(
        env.output.status, "partial",
        "must not fabricate a lossless read"
    );
    assert_eq!(env.strategy.coverage, Coverage::Unknown);
    assert!(env.output.content.is_none());
    assert!(!env.output.unknowns.is_empty());
    assert!(env
        .strategy
        .omissions
        .iter()
        .any(|o| o.contains("exceeds net context")));
}

#[test]
fn caller_token_ceiling_fails_closed() {
    let (_dir, path) = fixture_file("small.rs", "fn main() {}\n");
    let outcome = read_with_cache(
        &path,
        Fidelity::Lossless,
        &default_model(),
        None,
        Some(1), // one token ceiling
        None,
        &ScopePolicy::unrestricted(),
    );
    let env = outcome.expect("read still assembles").envelope;
    assert_eq!(env.output.status, "partial");
    assert_eq!(env.strategy.coverage, Coverage::Unknown);
}

#[test]
fn directory_read_fails_closed_with_map_hint() {
    let dir = tempfile::tempdir().unwrap();
    let err = read_with_cache(
        dir.path(),
        Fidelity::Lossless,
        &default_model(),
        None,
        None,
        None,
        &ScopePolicy::unrestricted(),
    );
    assert!(matches!(err, Err(Error::AmbiguousTarget { .. })));
}

#[test]
fn locate_negative_result_is_exhaustive_not_targeted() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"alpha beta\n").unwrap();
    fs::write(dir.path().join("b.txt"), b"gamma delta\n").unwrap();
    fs::write(dir.path().join("blob.bin"), [0u8, 1, 0, 2]).unwrap();

    let outcome = locate(dir.path(), "zzz_absent", false, 50).unwrap();
    let env = locate_envelope(dir.path(), "zzz_absent", &outcome);
    assert!(outcome.findings.is_empty());
    // G05: absence inside an exhaustive scan is reported as exhaustive.
    assert_eq!(env.strategy.coverage, Coverage::Exhaustive);
    assert_eq!(outcome.files_considered, 2);
    assert_eq!(outcome.binary_skipped, 1);
    assert!(env.strategy.omissions.iter().any(|o| o.contains("binary")));
    assert!(env.output.claims[0].statement.contains("not found in any"));
}

#[test]
fn locate_finds_terms_with_line_numbers() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"one\ntwo needle here\nthree\n").unwrap();
    fs::write(dir.path().join("b.txt"), b"nope\n").unwrap();
    let outcome = locate(dir.path(), "needle", false, 50).unwrap();
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].line_start, 2);
    assert!(outcome.findings[0].path.ends_with("a.txt"));
}

#[test]
fn cache_hit_on_unchanged_identity_and_invalidation_on_change() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = EvidenceCache::open(cache_dir.path()).unwrap();
    let path = dir.path().join("x.rs");
    fs::write(&path, b"fn one() {}\n").unwrap();

    let first = read_with_cache(
        &path,
        Fidelity::Lossless,
        &default_model(),
        None,
        None,
        Some(&cache),
        &ScopePolicy::unrestricted(),
    )
    .unwrap();
    assert!(!first.envelope.cache_hit);

    // Same evidence: deterministic request id + matching identity => hit.
    let second = read_with_cache(
        &path,
        Fidelity::Lossless,
        &default_model(),
        None,
        None,
        Some(&cache),
        &ScopePolicy::unrestricted(),
    )
    .unwrap();
    assert!(
        second.envelope.cache_hit,
        "unchanged evidence must be served from cache"
    );
    assert_eq!(
        second.envelope.identity.result_hash,
        first.envelope.identity.result_hash
    );

    // G08: changed content invalidates the cached knowledge.
    fs::write(&path, b"fn two() {}\n").unwrap();
    let third = read_with_cache(
        &path,
        Fidelity::Lossless,
        &default_model(),
        None,
        None,
        Some(&cache),
        &ScopePolicy::unrestricted(),
    )
    .unwrap();
    assert!(
        !third.envelope.cache_hit,
        "changed evidence must not be served from cache"
    );
    assert_ne!(
        third.envelope.identity.result_hash,
        first.envelope.identity.result_hash
    );
}

#[test]
fn pinned_revision_mismatch_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.rs");
    fs::write(&path, b"fn f() {}\n").unwrap();

    let resolved = resolve(&path, &ScopePolicy::unrestricted()).unwrap();
    let (bytes, m) = measure_file(&path).unwrap();
    let classification = classify(&path, &bytes, m.encoding);
    let mut request = bookworm_core::ContextRequest::new(
        bookworm_core::ReadIntent::Read,
        vec![bookworm_core::Target::File { path: path.clone() }],
    );
    request.freshness =
        FreshnessPolicy::Pinned("0deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string());

    let env = assemble_read(
        &resolved,
        &bytes,
        &m,
        &classification,
        &request,
        &default_model(),
    );
    // Not inside a repository: the revision check cannot pass, so the
    // envelope must report failure rather than pretending to be pinned.
    assert_eq!(env.output.status, "failed");
    assert!(env
        .output
        .conflicts
        .iter()
        .any(|c| c.contains("revision_is")));
}

#[test]
fn scope_root_rejects_targets_outside() {
    let inside = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let file = outside.path().join("secret.txt");
    fs::write(&file, b"s").unwrap();
    let policy = ScopePolicy::with_roots(vec![inside.path().to_path_buf()]);
    let err = read_with_cache(
        &file,
        Fidelity::Lossless,
        &default_model(),
        None,
        None,
        None,
        &policy,
    );
    assert!(matches!(err, Err(Error::OutsideScope { .. })));
}

#[test]
fn envelope_fields_survive_json_roundtrip_through_cache() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = EvidenceCache::open(cache_dir.path()).unwrap();
    let path = dir.path().join("x.rs");
    fs::write(&path, b"fn f() {}\n").unwrap();
    let outcome = read_with_cache(
        &path,
        Fidelity::Lossless,
        &default_model(),
        None,
        None,
        Some(&cache),
        &ScopePolicy::unrestricted(),
    )
    .unwrap();
    let back = cache
        .get(&outcome.envelope.request_id)
        .expect("cached envelope");
    assert_eq!(back, outcome.envelope);
}

#[test]
fn target_identity_reflects_resolution() {
    let (_dir, path) = fixture_file("plain.txt", "hello\n");
    let env = read_envelope_for(&path);
    let identity: TargetIdentity = env.target.clone();
    assert_eq!(identity.target_kind, "file");
    assert!(identity.canonical_path.ends_with("plain.txt"));
    assert!(identity.working_tree.is_none());
}
