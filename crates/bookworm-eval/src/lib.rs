//! Evaluation harness (directive §21).
//!
//! The checks live in `bookworm-cli` so the binary and this crate share one
//! implementation. This crate does not add a second pipeline.

use std::path::Path;

pub use bookworm_cli::{EvalCheck, EvalReport};

pub fn run(fixture: &Path) -> bookworm_core::Result<EvalReport> {
    bookworm_cli::eval_fixture(fixture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_fixture_passes() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sample-src");
        let report = run(&fixture).expect("eval fixture");
        assert!(
            report.ok(),
            "failed checks: {:?}",
            report
                .checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| format!("{}: {}", c.name, c.detail))
                .collect::<Vec<_>>()
        );
    }
}
