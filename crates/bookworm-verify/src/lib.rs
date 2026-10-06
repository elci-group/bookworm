//! Deterministic verification engine (directive §13).
//!
//! Machine-checkable assertions are checked by machine, never debated with a
//! model: "Never spend another inference call debating something the machine
//! can directly establish."
//!
//! v1 implements the initial capability list: path existence, text existence,
//! line/range validation, symbol existence, dependency existence, manifest
//! validation, Git revision verification and hash verification. The symbol
//! check is honestly labelled `lexical_word_scan` — it is a word-boundary
//! text scan, not AST symbol resolution, which arrives with structural
//! integration (ROADMAP P2).

use bookworm_core::{decode_text, Encoding, Error, Result};
use bookworm_measure::measure_file;
use bookworm_resolver::repo_context;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    PathExists {
        path: PathBuf,
    },
    /// Substring (regex=false) or regular-expression (regex=true) search over
    /// decoded text.
    TextExists {
        path: PathBuf,
        needle: String,
        regex: bool,
    },
    /// 1-based inclusive line range validation.
    LineRangeValid {
        path: PathBuf,
        start: u64,
        end: u64,
    },
    SymbolExists {
        path: PathBuf,
        symbol: String,
    },
    /// Dependency declared in a Cargo manifest (`dependencies`,
    /// `dev-dependencies` or `build-dependencies`).
    DependencyExists {
        manifest: PathBuf,
        name: String,
    },
    RevisionIs {
        repo: PathBuf,
        revision: String,
    },
    HashIs {
        path: PathBuf,
        sha256: String,
    },
}

impl Check {
    pub fn describe(&self) -> String {
        match self {
            Check::PathExists { path } => format!("path_exists {}", path.display()),
            Check::TextExists {
                path,
                needle,
                regex,
            } => {
                format!(
                    "text_exists {} '{}' (regex={regex})",
                    path.display(),
                    needle
                )
            }
            Check::LineRangeValid { path, start, end } => {
                format!("line_range_valid {}:{start}-{end}", path.display())
            }
            Check::SymbolExists { path, symbol } => {
                format!("symbol_exists {symbol} in {}", path.display())
            }
            Check::DependencyExists { manifest, name } => {
                format!("dependency_exists {name} in {}", manifest.display())
            }
            Check::RevisionIs { repo, revision } => {
                format!("revision_is {revision} @ {}", repo.display())
            }
            Check::HashIs { path, sha256 } => format!("hash_is {} == {sha256}", path.display()),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Check::PathExists { .. } => "path_exists",
            Check::TextExists { .. } => "text_exists",
            Check::LineRangeValid { .. } => "line_range_valid",
            Check::SymbolExists { .. } => "symbol_exists",
            Check::DependencyExists { .. } => "dependency_exists",
            Check::RevisionIs { .. } => "revision_is",
            Check::HashIs { .. } => "hash_is",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    pub kind: String,
    pub target: String,
    pub passed: bool,
    /// The deterministic method used; part of the audit trail (BW-I04).
    pub method: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub attempted: u64,
    pub passed: u64,
    pub failed: u64,
    pub results: Vec<CheckResult>,
}

impl VerificationReport {
    pub fn empty() -> Self {
        VerificationReport {
            attempted: 0,
            passed: 0,
            failed: 0,
            results: Vec::new(),
        }
    }
}

fn result(check: &Check, passed: bool, method: &str, detail: String) -> CheckResult {
    CheckResult {
        kind: check.kind().to_string(),
        target: check.describe(),
        passed,
        method: method.to_string(),
        detail,
    }
}

fn read_text(path: &PathBuf) -> Result<(Vec<u8>, Encoding, Option<String>)> {
    let (bytes, measurement) = measure_file(path).map_err(|e| Error::io(path, e))?;
    let text = decode_text(&bytes, measurement.encoding);
    Ok((bytes, measurement.encoding, text))
}

/// Run every check deterministically. A check that cannot even be attempted
/// (missing file, invalid regex, unreadable manifest) fails closed with its
/// reason recorded — it never passes by omission (§18).
pub fn run(checks: &[Check]) -> VerificationReport {
    let mut results = Vec::with_capacity(checks.len());
    for check in checks {
        results.push(run_one(check));
    }
    let passed = results.iter().filter(|r| r.passed).count() as u64;
    VerificationReport {
        attempted: results.len() as u64,
        passed,
        failed: results.len() as u64 - passed,
        results,
    }
}

fn run_one(check: &Check) -> CheckResult {
    match check {
        Check::PathExists { path } => {
            let passed = path.exists();
            result(check, passed, "stat", format!("exists={passed}"))
        }
        Check::TextExists {
            path,
            needle,
            regex,
        } => match read_text(path) {
            Err(e) => result(check, false, "text_scan", format!("unreadable target: {e}")),
            Ok((_, _, None)) => result(
                check,
                false,
                "text_scan",
                "target is not decodable text".to_string(),
            ),
            Ok((_, _, Some(text))) => {
                if *regex {
                    match regex::Regex::new(needle) {
                        Err(e) => result(check, false, "regex_scan", format!("invalid regex: {e}")),
                        Ok(re) => {
                            let n = re.find_iter(&text).count();
                            result(check, n > 0, "regex_scan", format!("{n} match(es)"))
                        }
                    }
                } else {
                    let n = text.matches(needle.as_str()).count();
                    result(check, n > 0, "text_scan", format!("{n} match(es)"))
                }
            }
        },
        Check::LineRangeValid { path, start, end } => match read_text(path) {
            Err(e) => result(
                check,
                false,
                "line_count",
                format!("unreadable target: {e}"),
            ),
            Ok((_, _, None)) => result(
                check,
                false,
                "line_count",
                "target is not decodable text".to_string(),
            ),
            Ok((_, _, Some(text))) => {
                let lines = text.lines().count() as u64;
                let passed = *start >= 1 && start <= end && *end <= lines;
                result(
                    check,
                    passed,
                    "line_count",
                    format!("range {start}-{end} vs {lines} lines"),
                )
            }
        },
        Check::SymbolExists { path, symbol } => match read_text(path) {
            Err(e) => result(
                check,
                false,
                "lexical_word_scan",
                format!("unreadable target: {e}"),
            ),
            Ok((_, _, None)) => result(
                check,
                false,
                "lexical_word_scan",
                "target is not decodable text".to_string(),
            ),
            Ok((_, _, Some(text))) => {
                let n = count_word_occurrences(&text, symbol);
                result(
                    check,
                    n > 0,
                    "lexical_word_scan",
                    format!("{n} word-boundary occurrence(s)"),
                )
            }
        },
        Check::DependencyExists { manifest, name } => {
            let content = match std::fs::read_to_string(manifest) {
                Ok(c) => c,
                Err(e) => {
                    return result(
                        check,
                        false,
                        "manifest_parse",
                        format!("unreadable manifest: {e}"),
                    )
                }
            };
            match content.parse::<toml::Table>() {
                Err(e) => result(check, false, "manifest_parse", format!("invalid TOML: {e}")),
                Ok(table) => {
                    let found = ["dependencies", "dev-dependencies", "build-dependencies"]
                        .iter()
                        .any(|section| {
                            table
                                .get(*section)
                                .and_then(|v| v.as_table())
                                .map(|t| t.contains_key(name))
                                .unwrap_or(false)
                        });
                    result(
                        check,
                        found,
                        "manifest_parse",
                        if found {
                            format!("declared under [*_dependencies]: {name}")
                        } else {
                            format!("{name} not declared")
                        },
                    )
                }
            }
        }
        Check::RevisionIs { repo, revision } => match repo_context(repo) {
            None => result(
                check,
                false,
                "git_rev_parse",
                "target is not inside a Git repository".to_string(),
            ),
            Some(ctx) => match ctx.revision {
                None => result(
                    check,
                    false,
                    "git_rev_parse",
                    "repository has an unborn HEAD".to_string(),
                ),
                Some(actual) => {
                    let passed = actual == *revision;
                    result(
                        check,
                        passed,
                        "git_rev_parse",
                        format!("HEAD={actual} expected={revision}"),
                    )
                }
            },
        },
        Check::HashIs { path, sha256 } => match measure_file(path) {
            Err(e) => result(check, false, "sha256", format!("unreadable target: {e}")),
            Ok((_, m)) => {
                let passed = m.sha256.eq_ignore_ascii_case(sha256);
                result(
                    check,
                    passed,
                    "sha256",
                    format!("actual={} expected={}", m.sha256, sha256),
                )
            }
        },
    }
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Count occurrences of `symbol` delimited by non-word characters on both
/// sides. A lexical approximation of symbol existence — labelled as such in
/// the check method, per BW-I05 honesty rules.
fn count_word_occurrences(text: &str, symbol: &str) -> usize {
    let mut count = 0usize;
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find(symbol) {
        let start = search_from + rel;
        let end = start + symbol.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .map(|c| !is_word_char(c))
            .unwrap_or(true);
        let after_ok = text[end..]
            .chars()
            .next()
            .map(|c| !is_word_char(c))
            .unwrap_or(true);
        if before_ok && after_ok {
            count += 1;
        }
        search_from = end;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn write(path: &std::path::Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn path_exists_check() {
        let dir = scratch();
        let f = dir.path().join("a.txt");
        write(&f, "x");
        let report = run(&[
            Check::PathExists { path: f.clone() },
            Check::PathExists {
                path: dir.path().join("no.txt"),
            },
        ]);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn text_and_regex_checks() {
        let dir = scratch();
        let f = dir.path().join("a.rs");
        write(&f, "fn refresh_tokens() {}\n// refresh tokens here\n");
        let report = run(&[
            Check::TextExists {
                path: f.clone(),
                needle: "refresh".into(),
                regex: false,
            },
            Check::TextExists {
                path: f.clone(),
                needle: "refresh_tokens\\(\\)".into(),
                regex: true,
            },
            Check::TextExists {
                path: f.clone(),
                needle: "absent_term".into(),
                regex: false,
            },
        ]);
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn invalid_regex_fails_closed() {
        let dir = scratch();
        let f = dir.path().join("a.txt");
        write(&f, "x");
        let report = run(&[Check::TextExists {
            path: f,
            needle: "([".into(),
            regex: true,
        }]);
        assert_eq!(report.failed, 1);
        assert!(report.results[0].detail.contains("invalid regex"));
    }

    #[test]
    fn symbol_scan_respects_word_boundaries() {
        let dir = scratch();
        let f = dir.path().join("a.rs");
        write(&f, "fn foo() {}\nlet foobar = foo() + foobar;\n");
        let report = run(&[Check::SymbolExists {
            path: f,
            symbol: "foo".into(),
        }]);
        assert_eq!(report.passed, 1);
        assert!(
            report.results[0].detail.contains("2 word-boundary"),
            "detail was: {}",
            report.results[0].detail
        );
    }

    #[test]
    fn symbol_absent_fails() {
        let dir = scratch();
        let f = dir.path().join("a.rs");
        write(&f, "fn bar() {}\n");
        let report = run(&[Check::SymbolExists {
            path: f,
            symbol: "foo".into(),
        }]);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn line_range_validation() {
        let dir = scratch();
        let f = dir.path().join("lines.txt");
        write(&f, "l1\nl2\nl3\n");
        let report = run(&[
            Check::LineRangeValid {
                path: f.clone(),
                start: 2,
                end: 3,
            },
            Check::LineRangeValid {
                path: f.clone(),
                start: 3,
                end: 9,
            },
            Check::LineRangeValid {
                path: f.clone(),
                start: 0,
                end: 1,
            },
        ]);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 2);
    }

    #[test]
    fn dependency_check_on_cargo_manifest() {
        let dir = scratch();
        let m = dir.path().join("Cargo.toml");
        write(&m, "[package]\nname = 'x'\n\n[dependencies]\nserde = '1'\n\n[dev-dependencies]\ntempfile = '3'\n");
        let report = run(&[
            Check::DependencyExists {
                manifest: m.clone(),
                name: "serde".into(),
            },
            Check::DependencyExists {
                manifest: m.clone(),
                name: "tempfile".into(),
            },
            Check::DependencyExists {
                manifest: m.clone(),
                name: "tokio".into(),
            },
        ]);
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn invalid_manifest_fails_closed() {
        let dir = scratch();
        let m = dir.path().join("Cargo.toml");
        write(&m, "[not toml at all =");
        let report = run(&[Check::DependencyExists {
            manifest: m,
            name: "serde".into(),
        }]);
        assert_eq!(report.failed, 1);
        assert!(report.results[0].detail.contains("invalid TOML"));
    }

    #[test]
    fn hash_check() {
        let dir = scratch();
        let f = dir.path().join("a.txt");
        write(&f, "hello\n");
        // SHA-256 of "hello\n"
        let good = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
        let report = run(&[
            Check::HashIs {
                path: f.clone(),
                sha256: good.into(),
            },
            Check::HashIs {
                path: f,
                sha256: "deadbeef".into(),
            },
        ]);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn word_occurrence_helper_is_boundaried() {
        assert_eq!(count_word_occurrences("foo foo_bar (foo) foobar", "foo"), 2);
        assert_eq!(count_word_occurrences("no match here", "foo"), 0);
        assert_eq!(count_word_occurrences("foo at start", "foo"), 1);
        assert_eq!(count_word_occurrences("end foo", "foo"), 1);
    }
}
