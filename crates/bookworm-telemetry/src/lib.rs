//! Process-local counters (directive §20).
//!
//! These are the counters a single Bookworm process can prove. They are not
//! a cluster metrics system. Names match the directive's minimum set where
//! this process actually observes the event.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

static REQUESTS: AtomicU64 = AtomicU64::new(0);
static BYTES_SCANNED: AtomicU64 = AtomicU64::new(0);
static LINES_SCANNED: AtomicU64 = AtomicU64::new(0);
static TOKENS_INGESTED: AtomicU64 = AtomicU64::new(0);
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static PISA_HITS: AtomicU64 = AtomicU64::new(0);
static DETERMINISTIC: AtomicU64 = AtomicU64::new(0);
static VERIFICATION_PASSES: AtomicU64 = AtomicU64::new(0);
static VERIFICATION_FAILURES: AtomicU64 = AtomicU64::new(0);
static CLAIM_CONFLICTS: AtomicU64 = AtomicU64::new(0);

fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

pub fn record_request() {
    add(&REQUESTS, 1);
}

pub fn record_bytes(n: u64) {
    add(&BYTES_SCANNED, n);
}

pub fn record_lines(n: u64) {
    add(&LINES_SCANNED, n);
}

pub fn record_tokens(n: u64) {
    add(&TOKENS_INGESTED, n);
}

pub fn record_cache_hit() {
    add(&CACHE_HITS, 1);
}

pub fn record_pisa_hit() {
    add(&PISA_HITS, 1);
}

pub fn record_deterministic() {
    add(&DETERMINISTIC, 1);
}

pub fn record_verification(passed: u64, failed: u64) {
    add(&VERIFICATION_PASSES, passed);
    add(&VERIFICATION_FAILURES, failed);
}

pub fn record_conflicts(n: u64) {
    add(&CLAIM_CONFLICTS, n);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub bookworm_requests_total: u64,
    pub bookworm_bytes_scanned: u64,
    pub bookworm_lines_scanned: u64,
    pub bookworm_tokens_ingested: u64,
    pub bookworm_cache_hits: u64,
    pub bookworm_pisa_hits: u64,
    pub bookworm_deterministic_resolutions: u64,
    pub bookworm_verification_passes: u64,
    pub bookworm_verification_failures: u64,
    pub bookworm_claim_conflicts: u64,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        bookworm_requests_total: REQUESTS.load(Ordering::Relaxed),
        bookworm_bytes_scanned: BYTES_SCANNED.load(Ordering::Relaxed),
        bookworm_lines_scanned: LINES_SCANNED.load(Ordering::Relaxed),
        bookworm_tokens_ingested: TOKENS_INGESTED.load(Ordering::Relaxed),
        bookworm_cache_hits: CACHE_HITS.load(Ordering::Relaxed),
        bookworm_pisa_hits: PISA_HITS.load(Ordering::Relaxed),
        bookworm_deterministic_resolutions: DETERMINISTIC.load(Ordering::Relaxed),
        bookworm_verification_passes: VERIFICATION_PASSES.load(Ordering::Relaxed),
        bookworm_verification_failures: VERIFICATION_FAILURES.load(Ordering::Relaxed),
        bookworm_claim_conflicts: CLAIM_CONFLICTS.load(Ordering::Relaxed),
    }
}

/// Test-only reset. Production commands do not call this.
pub fn reset_for_tests() {
    for c in [
        &REQUESTS,
        &BYTES_SCANNED,
        &LINES_SCANNED,
        &TOKENS_INGESTED,
        &CACHE_HITS,
        &PISA_HITS,
        &DETERMINISTIC,
        &VERIFICATION_PASSES,
        &VERIFICATION_FAILURES,
        &CLAIM_CONFLICTS,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        reset_for_tests();
        record_request();
        record_bytes(12);
        record_lines(3);
        record_cache_hit();
        record_verification(2, 1);
        let snap = snapshot();
        assert_eq!(snap.bookworm_requests_total, 1);
        assert_eq!(snap.bookworm_bytes_scanned, 12);
        assert_eq!(snap.bookworm_lines_scanned, 3);
        assert_eq!(snap.bookworm_cache_hits, 1);
        assert_eq!(snap.bookworm_verification_passes, 2);
        assert_eq!(snap.bookworm_verification_failures, 1);
    }
}
