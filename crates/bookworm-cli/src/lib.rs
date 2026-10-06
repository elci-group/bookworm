//! Bookworm CLI (directive §23): the complete v1 command surface over the
//! deterministic acquisition pipeline.
//!
//! v1 is inference-free: every command answers deterministically or fails
//! closed with its reason (§18). Commands that would require a semantic
//! reader report `status: partial` plus the exact missing capability rather
//! than fabricating output.

use bookworm_budget::{self, ModelSpec, TierPlan};
use bookworm_cache::{identity_matches, EvidenceCache};
use bookworm_classify::{classify, Classification};
use bookworm_core::{
    Budget, Claim, ClaimStatus, ContextRequest, Coverage, Error, Fidelity, FreshnessPolicy,
    ReadIntent, Result, Target, ENVELOPE_VERSION,
};
use bookworm_evidence::{
    ContentPayload, EvidenceEnvelope, Finding, HashEntry, IdentityBlock, MeasurementBlock,
    OutputBlock, StrategyBlock, TargetIdentity,
};
use bookworm_measure::{measure_file, Measurement};
use bookworm_policy::{ScopePolicy, READ_ONLY};
use bookworm_resolver::{
    git_available, inventory, resolve, InventoryOptions, ResolvedTarget, TargetKind,
};
use bookworm_verify::{run as run_checks, Check, VerificationReport};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Command surface
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "bookworm",
    version,
    about = "Deterministic evidence acquisition, reading and context resolution (ELCI BOOKWORM/1)"
)]
pub struct Cli {
    /// Emit machine-readable JSON (§23: all major functionality)
    #[arg(long, global = true)]
    pub json: bool,

    /// Evidence cache directory override
    #[arg(long, global = true, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Bypass the evidence cache for this invocation
    #[arg(long, global = true)]
    pub no_cache: bool,

    /// Restrict filesystem scope to this root (authorisation boundary, §19)
    #[arg(long, global = true, value_name = "ROOT")]
    pub root: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Lossless evidence read of a file target (§8 tier 1)
    Read {
        target: PathBuf,
        /// Print only the raw content, without the envelope
        #[arg(long)]
        raw: bool,
        /// Fidelity floor: raw|lossless|selective|structural|extractive|semantic
        #[arg(long, default_value = "lossless")]
        fidelity: String,
        /// Reader model used for budget accounting
        #[arg(long, default_value = "openai-gpt-4o")]
        model: String,
        /// Pin evidence to a Git revision; mismatch fails closed (BW-G02)
        #[arg(long)]
        revision: Option<String>,
        /// Hard input-token ceiling
        #[arg(long)]
        max_tokens: Option<u64>,
    },
    /// Exhaustive text search across a scope (tier 0)
    Locate {
        pattern: String,
        /// Search root (default: current directory)
        #[arg(default_value = ".")]
        root: PathBuf,
        /// Treat the pattern as a regular expression
        #[arg(long)]
        regex: bool,
        #[arg(long, default_value = "50")]
        max_results: usize,
    },
    /// Structural inventory of a directory or repository (§5)
    Map {
        target: PathBuf,
        #[arg(long, default_value = "3")]
        depth: usize,
        /// Include generated and vendored subtrees
        #[arg(long)]
        all: bool,
    },
    /// Deterministic measurement of a target (§7)
    Measure { target: PathBuf },
    /// Token accounting and tier feasibility for a target (§7/§8)
    Estimate {
        target: PathBuf,
        #[arg(long, default_value = "openai-gpt-4o")]
        model: String,
    },
    /// Deterministic strategy plan for a target (§9 pending reader integration)
    Route {
        target: PathBuf,
        #[arg(long, default_value = "openai-gpt-4o")]
        model: String,
    },
    /// Run deterministic checks against a target (§13)
    Verify {
        target: PathBuf,
        /// Substring that must exist in the target text (repeatable)
        #[arg(long)]
        text: Vec<String>,
        /// Regular expression that must match the target text (repeatable)
        #[arg(long)]
        regex: Vec<String>,
        /// Word-boundary symbol that must exist (repeatable, lexical scan)
        #[arg(long)]
        symbol: Vec<String>,
        /// Line range that must be valid, e.g. 10:42
        #[arg(long, value_parser = parse_line_range)]
        line_range: Option<(u64, u64)>,
        /// Cargo dependency that must be declared (repeatable)
        #[arg(long)]
        dep: Vec<String>,
        /// SHA-256 the target content must hash to
        #[arg(long)]
        hash: Option<String>,
        /// Git revision the target repository must be at
        #[arg(long)]
        revision: Option<String>,
    },
    /// Retrieve a cached evidence envelope by request id
    Evidence { request_id: String },
    /// Retrieve the claims of a cached envelope
    Claims { request_id: String },
    /// Inspect or manage the evidence cache (§15)
    Cache {
        #[command(subcommand)]
        cmd: CacheCommand,
    },
    /// Environment self-checks
    Doctor,
    /// Run the built-in evaluation seed over a fixture tree (§21)
    Eval {
        #[arg(default_value = "fixtures/sample-src")]
        fixture: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum CacheCommand {
    /// List cache entries
    Status,
    /// Drop one entry by request id
    Invalidate { request_id: String },
    /// Drop every entry
    Clear,
}

fn parse_line_range(s: &str) -> std::result::Result<(u64, u64), String> {
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| format!("expected START:END, got {s:?}"))?;
    let start: u64 = a.trim().parse().map_err(|e| format!("bad start: {e}"))?;
    let end: u64 = b.trim().parse().map_err(|e| format!("bad end: {e}"))?;
    Ok((start, end))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(cli: &Cli) -> Result<i32> {
    let scope = match &cli.root {
        Some(root) => ScopePolicy::with_roots(vec![root.clone()]),
        None => ScopePolicy::unrestricted(),
    };
    match &cli.command {
        Command::Read {
            target,
            raw,
            fidelity,
            model,
            revision,
            max_tokens,
        } => cmd_read(
            cli,
            target,
            *raw,
            fidelity,
            model,
            revision.as_deref(),
            *max_tokens,
            &scope,
        ),
        Command::Locate {
            pattern,
            root,
            regex,
            max_results,
        } => cmd_locate(cli, pattern, root, *regex, *max_results),
        Command::Map { target, depth, all } => cmd_map(cli, target, *depth, *all, &scope),
        Command::Measure { target } => cmd_measure(cli, target, &scope),
        Command::Estimate { target, model } => cmd_estimate(cli, target, model, &scope),
        Command::Route { target, model } => cmd_route(cli, target, model, &scope),
        Command::Verify {
            target,
            text,
            regex,
            symbol,
            line_range,
            dep,
            hash,
            revision,
        } => cmd_verify(
            cli,
            target,
            text,
            regex,
            symbol,
            *line_range,
            dep,
            hash.as_deref(),
            revision.as_deref(),
        ),
        Command::Evidence { request_id } => cmd_evidence(cli, request_id),
        Command::Claims { request_id } => cmd_claims(cli, request_id),
        Command::Cache { cmd } => cmd_cache(cli, cmd),
        Command::Doctor => cmd_doctor(cli),
        Command::Eval { fixture } => cmd_eval(cli, fixture),
    }
}

fn cache_for(cli: &Cli) -> Result<Option<EvidenceCache>> {
    if cli.no_cache {
        return Ok(None);
    }
    let dir = cli
        .cache_dir
        .clone()
        .unwrap_or_else(EvidenceCache::default_dir);
    Ok(Some(EvidenceCache::open(&dir)?))
}

fn print_json(value: &impl Serialize) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("serialization is total")
    );
}

// ---------------------------------------------------------------------------
// Read pipeline (§8 tier 1)
// ---------------------------------------------------------------------------

pub struct ReadOutcome {
    pub envelope: EvidenceEnvelope,
    pub raw: Vec<u8>,
    pub text: Option<String>,
}

fn read_request(
    path: &Path,
    fidelity: Fidelity,
    max_tokens: Option<u64>,
    pinned_revision: Option<&str>,
) -> ContextRequest {
    let mut req = ContextRequest::new(
        ReadIntent::Read,
        vec![Target::File {
            path: path.to_path_buf(),
        }],
    );
    req.fidelity = fidelity;
    req.budget = Budget {
        max_input_tokens: max_tokens,
        ..Budget::default()
    };
    if let Some(rev) = pinned_revision {
        req.freshness = FreshnessPolicy::Pinned(rev.to_string());
    }
    req
}

/// Assemble a read envelope from pre-measured evidence. Deterministic given
/// its inputs; the caller owns resolution and measurement so the cache path
/// can validate identity before paying for assembly.
pub fn assemble_read(
    resolved: &ResolvedTarget,
    bytes: &[u8],
    measurement: &Measurement,
    classification: &Classification,
    request: &ContextRequest,
    model: &ModelSpec,
) -> EvidenceEnvelope {
    let plan = bookworm_budget::plan_lossless(model, measurement.estimated_tokens, &request.budget);
    let mut env = EvidenceEnvelope::new(
        request.request_id(),
        TargetIdentity::from_resolved(resolved),
    );

    env.measurement = MeasurementBlock {
        files_discovered: 1,
        files_considered: 1,
        files_read: 1,
        lines_read: measurement.lines,
        bytes_read: measurement.bytes,
        tokens_ingested: measurement.estimated_tokens,
        estimation_method: measurement.estimation_method.clone(),
    };

    env.strategy = StrategyBlock {
        classification: classification.class.as_str().to_string(),
        language: classification.language.map(|l| l.as_str().to_string()),
        ingestion_strategy: if plan.feasible {
            bookworm_budget::IngestionTier::Tier1.as_str().to_string()
        } else {
            bookworm_budget::IngestionTier::Tier3.as_str().to_string()
        },
        reader_model: None,
        consensus_mode: "NONE".to_string(),
        coverage: if plan.feasible {
            Coverage::Exhaustive
        } else {
            Coverage::Unknown
        },
        omissions: plan.notes.clone(),
    };

    // Lossless before lossy (BW-I02): the full content is always attached
    // when it fits, regardless of a lower fidelity request.
    let text = bookworm_core::decode_text(bytes, measurement.encoding);
    let mut output = OutputBlock::default();
    if plan.feasible {
        output.content = Some(match &text {
            Some(t) => ContentPayload::Text {
                text: t.clone(),
                lines: measurement.lines,
            },
            None => ContentPayload::Binary {
                bytes: measurement.bytes,
            },
        });
    } else {
        output.status = "partial".to_string();
        output.unknowns.push(
            "full content exceeds the deterministic lossless budget; semantic tiers require reader integration (ROADMAP P1)"
                .to_string(),
        );
    }
    if !request.fidelity.lossless_ok() {
        output.unknowns.push(format!(
            "requested fidelity '{}' requires semantic processing; not available in the inference-free v1 pipeline",
            request.fidelity.as_str()
        ));
    }

    // Deterministic claims (§11): measured facts, each with evidence spans.
    let canonical = resolved.canonical.to_string_lossy().into_owned();
    let span = bookworm_core::EvidenceSpan {
        path: canonical.clone(),
        start_line: 1,
        end_line: measurement.lines.max(1),
        hash: measurement.sha256.clone(),
    };
    let mut claim_no = 0usize;
    let mut next_id = || {
        claim_no += 1;
        format!("bw-c-{claim_no:04}")
    };
    output.claims.push(Claim::deterministic(
        &next_id(),
        format!(
            "{} contains {} lines and {} bytes ({} encoding)",
            canonical,
            measurement.lines,
            measurement.bytes,
            measurement.encoding.as_str()
        ),
        vec![span.clone()],
        vec![
            "byte_measurement".to_string(),
            "line_count".to_string(),
            "encoding_sniff".to_string(),
        ],
    ));
    output.claims.push(Claim::deterministic(
        &next_id(),
        format!(
            "content class is {}{} — basis: {}",
            classification.class.as_str(),
            classification
                .language
                .map(|l| format!(" ({})", l.as_str()))
                .unwrap_or_default(),
            classification.basis
        ),
        vec![span.clone()],
        vec!["path_convention".to_string()],
    ));
    if let Some(repo) = &resolved.repository {
        output.claims.push(Claim::deterministic(
            &next_id(),
            format!(
                "repository {} at revision {} (working tree {})",
                repo.root.display(),
                repo.revision.as_deref().unwrap_or("unborn"),
                if repo.dirty { "dirty" } else { "clean" }
            ),
            vec![span.clone()],
            vec!["git_rev_parse".to_string(), "git_status".to_string()],
        ));
    }
    output.citations.push(span.clone());

    // Verification (§13): re-measure the file to detect mutation during
    // acquisition (§18) and enforce any pinned revision (BW-G02).
    let mut checks = vec![Check::HashIs {
        path: resolved.canonical.clone(),
        sha256: measurement.sha256.clone(),
    }];
    if let FreshnessPolicy::Pinned(rev) = &request.freshness {
        checks.push(Check::RevisionIs {
            repo: resolved.canonical.clone(),
            revision: rev.clone(),
        });
    }
    let report: VerificationReport = run_checks(&checks);
    if report.failed > 0 {
        output.status = "failed".to_string();
        for r in &report.results {
            if !r.passed {
                output
                    .conflicts
                    .push(format!("verification failed: {} — {}", r.kind, r.detail));
            }
        }
    }
    env.verification = report;
    env.output = output;
    env.identity = IdentityBlock {
        source_hashes: vec![HashEntry {
            path: canonical,
            sha256: measurement.sha256.clone(),
        }],
        result_hash: String::new(),
    };
    env.finalize()
}

/// Full read path with cache validation (§14/§15): a cached envelope is
/// reused only while its evidence identity matches the live target.
pub fn read_with_cache(
    path: &Path,
    fidelity: Fidelity,
    model: &ModelSpec,
    pinned_revision: Option<&str>,
    max_tokens: Option<u64>,
    cache: Option<&EvidenceCache>,
    scope: &ScopePolicy,
) -> Result<ReadOutcome> {
    let resolved = resolve(path, scope)?;
    if resolved.kind == TargetKind::Directory {
        return Err(Error::AmbiguousTarget {
            detail: "target is a directory; use `bookworm map` for structural inventories"
                .to_string(),
        });
    }
    // The request identity uses the canonical path so the same target
    // addressed from different working directories deduplicates (§26).
    let request = read_request(&resolved.canonical, fidelity, max_tokens, pinned_revision);
    let id = request.request_id();

    let (bytes, measurement) =
        measure_file(&resolved.canonical).map_err(|e| Error::io(&resolved.canonical, e))?;
    let classification = classify(&resolved.canonical, &bytes, measurement.encoding);

    let current_hash = HashEntry {
        path: resolved.canonical.to_string_lossy().into_owned(),
        sha256: measurement.sha256.clone(),
    };
    let current_revision = resolved
        .repository
        .as_ref()
        .and_then(|r| r.revision.clone());

    if let Some(cache) = cache {
        if let Some(cached) = cache.get(&id) {
            let hashes_match = identity_matches(
                &cached.identity.source_hashes,
                std::slice::from_ref(&current_hash),
            );
            let revision_match = cached.target.revision == current_revision;
            if hashes_match && revision_match {
                let mut served = cached;
                served.cache_hit = true;
                let text = bookworm_core::decode_text(&bytes, measurement.encoding);
                return Ok(ReadOutcome {
                    envelope: served,
                    raw: bytes,
                    text,
                });
            }
            cache.invalidate(&id)?;
        }
    }

    let envelope = assemble_read(
        &resolved,
        &bytes,
        &measurement,
        &classification,
        &request,
        model,
    );
    if let Some(cache) = cache {
        cache.put(&envelope)?;
    }
    let text = bookworm_core::decode_text(&bytes, measurement.encoding);
    Ok(ReadOutcome {
        envelope,
        raw: bytes,
        text,
    })
}

fn model_or_err(name: &str) -> Result<ModelSpec> {
    bookworm_budget::find_model(name).ok_or_else(|| Error::Usage {
        detail: format!(
            "unknown model {name:?}; builtin registry: {}",
            bookworm_budget::builtin_models()
                .iter()
                .map(|m| m.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

fn fidelity_or_err(s: &str) -> Result<Fidelity> {
    Fidelity::parse(s).ok_or_else(|| Error::Usage {
        detail: format!(
            "unknown fidelity {s:?}; expected raw|lossless|selective|structural|extractive|semantic"
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn cmd_read(
    cli: &Cli,
    target: &Path,
    raw: bool,
    fidelity: &str,
    model: &str,
    revision: Option<&str>,
    max_tokens: Option<u64>,
    scope: &ScopePolicy,
) -> Result<i32> {
    let fidelity = fidelity_or_err(fidelity)?;
    let model = model_or_err(model)?;
    let cache = cache_for(cli)?;
    let outcome = read_with_cache(
        target,
        fidelity,
        &model,
        revision,
        max_tokens,
        cache.as_ref(),
        scope,
    )?;

    if raw {
        std::io::stdout()
            .write_all(&outcome.raw)
            .map_err(|e| Error::io("<stdout>", e))?;
        return Ok(0);
    }
    if cli.json {
        print_json(&outcome.envelope);
        return Ok(0);
    }
    print_human_envelope(&outcome.envelope);
    if let Some(ContentPayload::Text { text, .. }) = &outcome.envelope.output.content {
        println!("--- content ---");
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Locate pipeline (tier 0)
// ---------------------------------------------------------------------------

pub struct LocateOutcome {
    pub findings: Vec<Finding>,
    pub files_discovered: u64,
    pub files_considered: u64,
    pub lines_scanned: u64,
    pub binary_skipped: u64,
    pub undecodable_skipped: u64,
    pub notes: Vec<String>,
}

/// Exhaustive text search over a scope. Every file is walked and every
/// decodable text file scanned, so a zero-result outcome still carries
/// `Coverage::Exhaustive` plus explicit skip notes — "not found" is never
/// confused with "not exhaustively searched" (§17, §21 negative-query).
pub fn locate(
    root: &Path,
    pattern: &str,
    is_regex: bool,
    max_results: usize,
) -> Result<LocateOutcome> {
    let canonical = std::fs::canonicalize(root).map_err(|_| Error::TargetMissing {
        path: root.to_path_buf(),
    })?;
    let re = if is_regex {
        Some(regex::Regex::new(pattern).map_err(|e| Error::Usage {
            detail: format!("invalid regex: {e}"),
        })?)
    } else {
        None
    };

    let mut outcome = LocateOutcome {
        findings: Vec::new(),
        files_discovered: 0,
        files_considered: 0,
        lines_scanned: 0,
        binary_skipped: 0,
        undecodable_skipped: 0,
        notes: Vec::new(),
    };

    let filter_root = canonical.clone();
    let walker = WalkDir::new(&canonical)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(move |e| {
            if e.depth() == 0 {
                return true;
            }
            match e.path().strip_prefix(&filter_root) {
                Ok(rel) => rel.components().all(|c| c.as_os_str() != ".git"),
                Err(_) => true,
            }
        });

    for entry in walker {
        let entry = entry.map_err(|e| Error::io(&canonical, std::io::Error::other(e)))?;
        if !entry.file_type().is_file() {
            continue;
        }
        outcome.files_discovered += 1;
        let path = entry.path();
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => {
                outcome.undecodable_skipped += 1;
                continue;
            }
        };
        let encoding = bookworm_core::sniff_encoding(&bytes);
        let Some(text) = bookworm_core::decode_text(&bytes, encoding) else {
            if encoding == bookworm_core::Encoding::Binary {
                outcome.binary_skipped += 1;
            } else {
                outcome.undecodable_skipped += 1;
            }
            continue;
        };
        outcome.files_considered += 1;
        outcome.lines_scanned += text.lines().count() as u64;
        for (i, line) in text.lines().enumerate() {
            let matched = match &re {
                Some(re) => re.is_match(line),
                None => line.contains(pattern),
            };
            if matched && outcome.findings.len() < max_results {
                outcome.findings.push(Finding {
                    path: path.to_string_lossy().into_owned(),
                    line_start: i as u64 + 1,
                    line_end: i as u64 + 1,
                    excerpt: truncate(line.trim(), 160),
                    kind: "match".to_string(),
                });
            }
        }
    }

    if outcome.binary_skipped > 0 {
        outcome
            .notes
            .push(format!("{} binary file(s) skipped", outcome.binary_skipped));
    }
    if outcome.undecodable_skipped > 0 {
        outcome.notes.push(format!(
            "{} undecodable file(s) skipped",
            outcome.undecodable_skipped
        ));
    }
    if !outcome.findings.is_empty() && outcome.findings.len() == max_results {
        outcome.notes.push(format!(
            "result list capped at {max_results}; scan counts remain whole-scope"
        ));
    }
    Ok(outcome)
}

pub fn resolved_root_of(root: &Path) -> PathBuf {
    std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

pub fn locate_envelope(root: &Path, pattern: &str, outcome: &LocateOutcome) -> EvidenceEnvelope {
    let mut req = ContextRequest::new(
        ReadIntent::Locate,
        vec![Target::Directory {
            path: resolved_root_of(root),
        }],
    );
    req.question = Some(pattern.to_string());
    let resolved_root = resolved_root_of(root);

    let mut env = EvidenceEnvelope::new(
        req.request_id(),
        TargetIdentity {
            repository: None,
            revision: None,
            working_tree: None,
            target: resolved_root.to_string_lossy().into_owned(),
            target_kind: "directory".to_string(),
            canonical_path: resolved_root.to_string_lossy().into_owned(),
        },
    );
    env.measurement = MeasurementBlock {
        files_discovered: outcome.files_discovered,
        files_considered: outcome.files_considered,
        files_read: outcome.files_considered,
        lines_read: outcome.lines_scanned,
        bytes_read: 0,
        tokens_ingested: None,
        estimation_method: None,
    };
    env.strategy = StrategyBlock {
        classification: "scope".to_string(),
        language: None,
        ingestion_strategy: bookworm_budget::IngestionTier::Tier0.as_str().to_string(),
        reader_model: None,
        consensus_mode: "NONE".to_string(),
        coverage: Coverage::Exhaustive,
        omissions: outcome.notes.clone(),
    };

    let matched_files: std::collections::BTreeSet<&str> =
        outcome.findings.iter().map(|f| f.path.as_str()).collect();
    let statement = if outcome.findings.is_empty() {
        format!(
            "pattern {:?} not found in any of the {} decodable text file(s) scanned under {} ({} binary, {} undecodable skipped)",
            pattern,
            outcome.files_considered,
            root.display(),
            outcome.binary_skipped,
            outcome.undecodable_skipped
        )
    } else {
        format!(
            "pattern {:?} found on {} line(s) across {} file(s) of {} scanned",
            pattern,
            outcome.findings.len(),
            matched_files.len(),
            outcome.files_considered
        )
    };
    env.output.claims.push(Claim::deterministic(
        "bw-c-0001",
        statement,
        outcome
            .findings
            .iter()
            .take(5)
            .map(|f| bookworm_core::EvidenceSpan {
                path: f.path.clone(),
                start_line: f.line_start,
                end_line: f.line_end,
                hash: String::new(),
            })
            .collect(),
        vec!["full_scope_text_scan".to_string()],
    ));
    env.output.findings = outcome.findings.clone();
    env.identity = IdentityBlock {
        source_hashes: Vec::new(),
        result_hash: String::new(),
    };
    env.finalize()
}

fn cmd_locate(
    cli: &Cli,
    pattern: &str,
    root: &Path,
    is_regex: bool,
    max_results: usize,
) -> Result<i32> {
    let outcome = locate(root, pattern, is_regex, max_results)?;
    let envelope = locate_envelope(root, pattern, &outcome);
    if cli.json {
        print_json(&envelope);
    } else {
        print_human_envelope(&envelope);
        for f in &outcome.findings {
            println!("{}:{}: {}", f.path, f.line_start, f.excerpt);
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Map (§5 inventory)
// ---------------------------------------------------------------------------

fn cmd_map(cli: &Cli, target: &Path, depth: usize, all: bool, scope: &ScopePolicy) -> Result<i32> {
    let resolved = resolve(target, scope)?;
    if resolved.kind != TargetKind::Directory {
        return Err(Error::AmbiguousTarget {
            detail: format!(
                "`map` expects a directory or repository, got {}",
                resolved.kind.as_str()
            ),
        });
    }
    let opts = InventoryOptions {
        max_depth: depth,
        include_generated: all,
        include_vendored: all,
    };
    let inv = inventory(&resolved.canonical, &opts)?;

    let mut req = ContextRequest::new(
        ReadIntent::Map,
        vec![Target::Directory {
            path: resolved.canonical.clone(),
        }],
    );
    req.fidelity = Fidelity::Structural;

    let mut env = EvidenceEnvelope::new(req.request_id(), TargetIdentity::from_resolved(&resolved));
    env.measurement = MeasurementBlock {
        files_discovered: inv.entries.len() as u64,
        files_considered: inv.files_total,
        files_read: 0, // an inventory reads metadata, not content
        lines_read: 0,
        bytes_read: 0,
        tokens_ingested: None,
        estimation_method: None,
    };
    env.strategy = StrategyBlock {
        classification: "structural_inventory".to_string(),
        language: None,
        ingestion_strategy: "structural_inventory".to_string(),
        reader_model: None,
        consensus_mode: "NONE".to_string(),
        coverage: Coverage::StructurallyExhaustive,
        omissions: inv.omissions.clone(),
    };
    let listing_hash = bookworm_evidence::inventory_hash(&inv);
    env.output.findings = inv
        .entries
        .iter()
        .map(|e| Finding {
            path: e.path.clone(),
            line_start: 1,
            line_end: 1,
            excerpt: if e.size_bytes > 0 {
                format!("{} bytes", e.size_bytes)
            } else {
                String::new()
            },
            kind: e.kind.as_str().to_string(),
        })
        .collect();
    env.output.claims.push(Claim::deterministic(
        "bw-c-0001",
        format!(
            "inventory of {} contains {} entries ({} files, {} bytes)",
            inv.root.display(),
            inv.entries.len(),
            inv.files_total,
            inv.bytes_total
        ),
        vec![bookworm_core::EvidenceSpan {
            path: inv.root.to_string_lossy().into_owned(),
            start_line: 1,
            end_line: 1,
            hash: listing_hash.clone(),
        }],
        vec![
            "walk_conventions".to_string(),
            "inventory_listing_hash".to_string(),
        ],
    ));
    env.identity = IdentityBlock {
        source_hashes: vec![HashEntry {
            path: inv.root.to_string_lossy().into_owned(),
            sha256: listing_hash,
        }],
        result_hash: String::new(),
    };
    let env = env.finalize();

    if cli.json {
        print_json(&env);
    } else {
        print_human_envelope(&env);
        for f in &env.output.findings {
            println!("{:<14} {} {}", f.kind, f.path, f.excerpt);
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Measure / Estimate / Route
// ---------------------------------------------------------------------------

fn cmd_measure(cli: &Cli, target: &Path, scope: &ScopePolicy) -> Result<i32> {
    let resolved = resolve(target, scope)?;
    if resolved.kind != TargetKind::File {
        return Err(Error::AmbiguousTarget {
            detail: "`measure` expects a file target".to_string(),
        });
    }
    let (bytes, m) =
        measure_file(&resolved.canonical).map_err(|e| Error::io(&resolved.canonical, e))?;
    let classification = classify(&resolved.canonical, &bytes, m.encoding);
    let repo = resolved.repository.as_ref().map(|r| {
        serde_json::json!({ "root": r.root, "revision": r.revision, "branch": r.branch, "dirty": r.dirty })
    });
    let value = serde_json::json!({
        "target": resolved.canonical,
        "kind": resolved.kind.as_str(),
        "size_bytes": resolved.size_bytes,
        "encoding": m.encoding.as_str(),
        "language": classification.language.map(|l| l.as_str()),
        "class": classification.class.as_str(),
        "generated": classification.generated,
        "vendored": classification.vendored,
        "repository": repo,
        "measurement": m,
    });
    if cli.json {
        print_json(&value);
    } else {
        println!("target    : {}", resolved.canonical.display());
        println!("size      : {} bytes", m.bytes);
        println!("lines     : {}", m.lines);
        println!("encoding  : {}", m.encoding.as_str());
        println!(
            "language  : {}",
            classification
                .language
                .map(|l| l.as_str())
                .unwrap_or("unknown")
        );
        println!("sha256    : {}", m.sha256);
        println!(
            "tokens    : ~{} ({})",
            m.estimated_tokens.unwrap_or(0),
            m.estimation_method.as_deref().unwrap_or("no estimate")
        );
    }
    Ok(0)
}

fn cmd_estimate(cli: &Cli, target: &Path, model: &str, scope: &ScopePolicy) -> Result<i32> {
    let model = model_or_err(model)?;
    let resolved = resolve(target, scope)?;
    let (bytes, m) =
        measure_file(&resolved.canonical).map_err(|e| Error::io(&resolved.canonical, e))?;
    let classification = classify(&resolved.canonical, &bytes, m.encoding);
    let plan: TierPlan =
        bookworm_budget::plan_lossless(&model, m.estimated_tokens, &Budget::default());
    let value = serde_json::json!({
        "target": resolved.canonical,
        "model": model.name,
        "classification": classification.class.as_str(),
        "estimated_input_tokens": m.estimated_tokens,
        "estimation_method": m.estimation_method,
        "exact_tokens": m.exact_tokens,
        "plan": plan,
    });
    if cli.json {
        print_json(&value);
    } else {
        println!("target    : {}", resolved.canonical.display());
        println!(
            "model     : {} (nominal {} ctx)",
            model.name, model.context_tokens
        );
        println!(
            "est.tokens: ~{} ({})",
            m.estimated_tokens.unwrap_or(0),
            m.estimation_method.as_deref().unwrap_or("no estimate")
        );
        println!("net avail : {}", plan.net_available);
        println!(
            "tier      : {} feasible={}",
            plan.tier.as_str(),
            plan.feasible
        );
        for n in &plan.notes {
            println!("note      : {n}");
        }
    }
    Ok(0)
}

fn cmd_route(cli: &Cli, target: &Path, model: &str, scope: &ScopePolicy) -> Result<i32> {
    let model = model_or_err(model)?;
    let resolved = resolve(target, scope)?;
    let (bytes, m) =
        measure_file(&resolved.canonical).map_err(|e| Error::io(&resolved.canonical, e))?;
    let classification = classify(&resolved.canonical, &bytes, m.encoding);
    let plan = bookworm_budget::plan_lossless(&model, m.estimated_tokens, &Budget::default());
    let value = serde_json::json!({
        "target": resolved.canonical,
        "classification": classification.class.as_str(),
        "language": classification.language.map(|l| l.as_str()),
        "deterministic_plan": plan,
        "planned_checks": ["hash_recompute", "revision_pin"],
        "reader_model": serde_json::Value::Null,
        "consensus_mode": "NONE",
        "routing_note": "model routing (directive section 9) requires reader integration and empirical capability records (ROADMAP P1/P3); v1 performs deterministic strategy selection only",
    });
    if cli.json {
        print_json(&value);
    } else {
        println!("target    : {}", resolved.canonical.display());
        println!(
            "class     : {} ({})",
            classification.class.as_str(),
            classification.language.map(|l| l.as_str()).unwrap_or("?")
        );
        println!(
            "plan      : {} feasible={}",
            plan.tier.as_str(),
            plan.feasible
        );
        println!("reader    : none (reader integration pending, ROADMAP P1)");
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Verify (§13)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cmd_verify(
    cli: &Cli,
    target: &Path,
    text: &[String],
    regex: &[String],
    symbol: &[String],
    line_range: Option<(u64, u64)>,
    dep: &[String],
    hash: Option<&str>,
    revision: Option<&str>,
) -> Result<i32> {
    let mut checks: Vec<Check> = Vec::new();
    for t in text {
        checks.push(Check::TextExists {
            path: target.to_path_buf(),
            needle: t.clone(),
            regex: false,
        });
    }
    for r in regex {
        checks.push(Check::TextExists {
            path: target.to_path_buf(),
            needle: r.clone(),
            regex: true,
        });
    }
    for s in symbol {
        checks.push(Check::SymbolExists {
            path: target.to_path_buf(),
            symbol: s.clone(),
        });
    }
    if let Some((start, end)) = line_range {
        checks.push(Check::LineRangeValid {
            path: target.to_path_buf(),
            start,
            end,
        });
    }
    for d in dep {
        checks.push(Check::DependencyExists {
            manifest: target.to_path_buf(),
            name: d.clone(),
        });
    }
    if let Some(h) = hash {
        checks.push(Check::HashIs {
            path: target.to_path_buf(),
            sha256: h.to_string(),
        });
    }
    if let Some(r) = revision {
        checks.push(Check::RevisionIs {
            repo: target.to_path_buf(),
            revision: r.to_string(),
        });
    }
    if checks.is_empty() {
        return Err(Error::Usage {
            detail: "no checks requested; pass --text/--regex/--symbol/--line-range/--dep/--hash/--revision"
                .to_string(),
        });
    }

    let report = run_checks(&checks);
    if cli.json {
        print_json(&report);
    } else {
        for r in &report.results {
            let mark = if r.passed { "PASS" } else { "FAIL" };
            println!("[{mark}] {} ({}): {}", r.kind, r.method, r.detail);
        }
        println!("{} passed, {} failed", report.passed, report.failed);
    }
    Ok(if report.failed > 0 { 2 } else { 0 })
}

// ---------------------------------------------------------------------------
// Evidence / Claims / Cache
// ---------------------------------------------------------------------------

fn cmd_evidence(cli: &Cli, request_id: &str) -> Result<i32> {
    let cache = cache_for(cli)?.ok_or_else(|| Error::Usage {
        detail: "--no-cache set; nothing to read".to_string(),
    })?;
    let envelope = cache.get(request_id).ok_or_else(|| Error::Cache {
        detail: format!("no cached envelope for {request_id}"),
    })?;
    if cli.json {
        print_json(&envelope);
    } else {
        print_human_envelope(&envelope);
    }
    Ok(0)
}

fn cmd_claims(cli: &Cli, request_id: &str) -> Result<i32> {
    let cache = cache_for(cli)?.ok_or_else(|| Error::Usage {
        detail: "--no-cache set; nothing to read".to_string(),
    })?;
    let envelope = cache.get(request_id).ok_or_else(|| Error::Cache {
        detail: format!("no cached envelope for {request_id}"),
    })?;
    if cli.json {
        print_json(&envelope.output.claims);
    } else {
        for c in &envelope.output.claims {
            println!(
                "[{}] {} {}: {}",
                c.claim_id,
                c.status.as_str(),
                c.confidence.map(|v| v.to_string()).unwrap_or_default(),
                c.statement
            );
        }
    }
    Ok(0)
}

fn cmd_cache(cli: &Cli, cmd: &CacheCommand) -> Result<i32> {
    let cache = cache_for(cli)?.ok_or_else(|| Error::Usage {
        detail: "--no-cache set; cache commands need a cache".to_string(),
    })?;
    match cmd {
        CacheCommand::Status => {
            let entries = cache.entries()?;
            if cli.json {
                print_json(&serde_json::json!({
                    "dir": cache_dir_display(cli),
                    "entries": entries.len(),
                    "items": entries,
                }));
            } else {
                println!("cache dir : {}", cache_dir_display(cli));
                println!("entries   : {}", entries.len());
                for e in &entries {
                    println!(
                        "{}  {}  {}",
                        e.request_id,
                        e.result_hash.get(..12).unwrap_or(&e.result_hash),
                        e.target
                    );
                }
            }
            Ok(0)
        }
        CacheCommand::Invalidate { request_id } => {
            let removed = cache.invalidate(request_id)?;
            if cli.json {
                print_json(&serde_json::json!({ "invalidated": request_id, "existed": removed }));
            } else {
                println!("invalidated {request_id} (existed={removed})");
            }
            Ok(0)
        }
        CacheCommand::Clear => {
            let removed = cache.clear()?;
            if cli.json {
                print_json(&serde_json::json!({ "cleared": removed }));
            } else {
                println!(
                    "cleared {removed} entr{}",
                    if removed == 1 { "y" } else { "ies" }
                );
            }
            Ok(0)
        }
    }
}

fn cache_dir_display(cli: &Cli) -> String {
    cli.cache_dir
        .clone()
        .unwrap_or_else(EvidenceCache::default_dir)
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

fn cmd_doctor(cli: &Cli) -> Result<i32> {
    let mut items: Vec<(String, bool, String)> = Vec::new();
    items.push((
        "version".to_string(),
        true,
        format!("bookworm {VERSION}, envelope {ENVELOPE_VERSION}, read_only={READ_ONLY}"),
    ));
    let git_ok = git_available();
    items.push((
        "git".to_string(),
        git_ok,
        if git_ok {
            "git binary available".to_string()
        } else {
            "git binary missing; repository identity unavailable".to_string()
        },
    ));

    let cache_dir = cli
        .cache_dir
        .clone()
        .unwrap_or_else(EvidenceCache::default_dir);
    let cache_ok = (|| -> Result<()> {
        let cache = EvidenceCache::open(&cache_dir)?;
        cache.entries()?;
        Ok(())
    })()
    .is_ok();
    items.push((
        "cache".to_string(),
        cache_ok,
        format!("writable at {}", cache_dir.display()),
    ));

    let all_ok = items.iter().all(|(_, ok, _)| *ok);
    if cli.json {
        print_json(&serde_json::json!({
            "ok": all_ok,
            "checks": items.iter().map(|(c, ok, d)| serde_json::json!({"check": c, "ok": ok, "detail": d})).collect::<Vec<_>>(),
        }));
    } else {
        for (check, ok, detail) in &items {
            let mark = if *ok { "ok" } else { "FAIL" };
            println!("[{mark}] {check}: {detail}");
        }
    }
    Ok(if all_ok { 0 } else { 1 })
}

// ---------------------------------------------------------------------------
// Eval seed (§21)
// ---------------------------------------------------------------------------

fn cmd_eval(cli: &Cli, fixture: &Path) -> Result<i32> {
    let fixture = fixture.canonicalize().map_err(|_| Error::TargetMissing {
        path: fixture.to_path_buf(),
    })?;
    let sample = fixture.join("src/auth.rs");
    if !sample.exists() {
        return Err(Error::AmbiguousTarget {
            detail: format!(
                "fixture incomplete: expected {} — run from the repository root or pass --fixture",
                sample.display()
            ),
        });
    }

    let mut results: Vec<(String, bool, String)> = Vec::new();

    // 1. Measurement determinism (BW-G01).
    let (_, m1) = measure_file(&sample).map_err(|e| Error::io(&sample, e))?;
    let (_, m2) = measure_file(&sample).map_err(|e| Error::io(&sample, e))?;
    eval_check(
        &mut results,
        "measurement_determinism",
        m1 == m2,
        format!("sha256={}… lines={}", &m1.sha256[..12], m1.lines),
    );

    // 2. Envelope determinism: two assemblies over identical evidence must
    // hash identically (BW-G01).
    let model = bookworm_budget::default_model();
    let request = read_request(&sample, Fidelity::Lossless, None, None);
    let resolved = resolve(&sample, &ScopePolicy::unrestricted())?;
    let (bytes, m) = measure_file(&sample).map_err(|e| Error::io(&sample, e))?;
    let classification = classify(&sample, &bytes, m.encoding);
    let e1 = assemble_read(&resolved, &bytes, &m, &classification, &request, &model);
    let e2 = assemble_read(&resolved, &bytes, &m, &classification, &request, &model);
    eval_check(
        &mut results,
        "envelope_determinism",
        e1.identity.result_hash == e2.identity.result_hash,
        format!("result_hash={}…", &e1.identity.result_hash[..12]),
    );

    // 3. Negative-query correctness: absence reported with exhaustive
    // coverage and explicit skips (§17, §21).
    let loc = locate(&fixture, "zzz_bw_absent_term_zzz", false, 10)?;
    let loc_env = locate_envelope(&fixture, "zzz_bw_absent_term_zzz", &loc);
    let negative_ok = loc.findings.is_empty() && loc_env.strategy.coverage == Coverage::Exhaustive;
    eval_check(
        &mut results,
        "negative_query_coverage",
        negative_ok,
        format!(
            "0 findings, coverage={}, scanned {} text file(s)",
            loc_env.strategy.coverage.as_str(),
            loc.files_considered
        ),
    );

    // 4. Provenance completeness: claims carry evidence spans bound to the
    // measured hash (BW-G03, BW-I06).
    let provenance_ok = e1.output.claims.iter().all(|c| {
        c.evidence
            .iter()
            .all(|s| !s.path.is_empty() && !s.hash.is_empty())
    }) && e1.identity.source_hashes.len() == 1
        && e1.identity.source_hashes[0].sha256 == m.sha256;
    eval_check(
        &mut results,
        "provenance_completeness",
        provenance_ok,
        format!(
            "{} claim(s), {} source hash(es)",
            e1.output.claims.len(),
            e1.identity.source_hashes.len()
        ),
    );

    // 5. Cache invalidation on identity change (BW-G08).
    let tmp = tempfile::tempdir().map_err(|e| Error::io("<tmp>", e))?;
    let cache = EvidenceCache::open(tmp.path())?;
    cache.put(&e1)?;
    let hit = cache.get(&e1.request_id).is_some();
    let tampered = vec![HashEntry {
        path: sample.to_string_lossy().into_owned(),
        sha256: "0".repeat(64),
    }];
    let invalidated = !identity_matches(&e1.identity.source_hashes, &tampered);
    eval_check(
        &mut results,
        "cache_invalidation",
        hit && invalidated,
        format!("hit={hit}, changed-identity rejected={invalidated}"),
    );

    let all_ok = results.iter().all(|(_, ok, _)| *ok);
    if cli.json {
        print_json(&serde_json::json!({
            "fixture": fixture,
            "ok": all_ok,
            "checks": results.iter().map(|(n, ok, d)| serde_json::json!({"check": n, "ok": ok, "detail": d})).collect::<Vec<_>>(),
        }));
    } else {
        for (name, ok, detail) in &results {
            let mark = if *ok { "PASS" } else { "FAIL" };
            println!("[{mark}] {name}: {detail}");
        }
        println!(
            "eval: {} ({} checks)",
            if all_ok { "PASS" } else { "FAIL" },
            results.len()
        );
    }
    Ok(if all_ok { 0 } else { 1 })
}

fn eval_check(results: &mut Vec<(String, bool, String)>, name: &str, ok: bool, detail: String) {
    results.push((name.to_string(), ok, detail));
}

// ---------------------------------------------------------------------------
// Human rendering
// ---------------------------------------------------------------------------

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

fn print_human_envelope(env: &EvidenceEnvelope) {
    println!(
        "{}  {}  cache_hit={}",
        env.version, env.request_id, env.cache_hit
    );
    println!(
        "target    : {} ({})",
        env.target.target, env.target.target_kind
    );
    match (
        &env.target.repository,
        &env.target.revision,
        &env.target.working_tree,
    ) {
        (Some(repo), rev, wt) => println!(
            "repo      : {} @ {} ({})",
            repo,
            rev.as_deref().unwrap_or("unborn"),
            wt.as_deref().unwrap_or("?")
        ),
        _ => println!("repo      : not in a repository"),
    }
    println!(
        "measured  : {} file(s) read, {} lines, {} bytes, tokens ~{}",
        env.measurement.files_read,
        env.measurement.lines_read,
        env.measurement.bytes_read,
        env.measurement
            .tokens_ingested
            .map(|t| t.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "strategy  : {} [{}] coverage={} reader={} consensus={}",
        env.strategy.ingestion_strategy,
        env.strategy.classification,
        env.strategy.coverage.as_str(),
        env.strategy.reader_model.as_deref().unwrap_or("none"),
        env.strategy.consensus_mode
    );
    println!(
        "verify    : {}/{} passed",
        env.verification.passed, env.verification.attempted
    );
    let verified = env
        .output
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Verified)
        .count();
    println!(
        "claims    : {} total, {} verified",
        env.output.claims.len(),
        verified
    );
    for u in &env.output.unknowns {
        println!("unknown   : {u}");
    }
    for o in &env.strategy.omissions {
        println!("omission  : {o}");
    }
    for c in &env.output.conflicts {
        println!("conflict  : {c}");
    }
    println!("identity  : result_hash={}", env.identity.result_hash);
    println!("status    : {}", env.output.status);
}
