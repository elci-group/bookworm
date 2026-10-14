//! Intent executors that stay inside the deterministic pipeline.
//!
//! Explain, summarise, and extract quote source. They do not paraphrase.
//! Compare diffs symbol names. Trace and impact list reference sites.

use bookworm_budget::ModelSpec;
use bookworm_classify::classify;
use bookworm_core::{
    Claim, ConsensusMode, ContextRequest, Coverage, Error, Fidelity, PrivacyPolicy, ReadIntent,
    Result, Target, VerificationPolicy,
};
use bookworm_evidence::{
    ContentPayload, EvidenceEnvelope, Finding, HashEntry, IdentityBlock, MeasurementBlock,
    OutputBlock, StrategyBlock, TargetIdentity,
};
use bookworm_measure::measure_file;
use bookworm_policy::ScopePolicy;
use bookworm_reader::diff_symbols;
use bookworm_resolver::{resolve, ResolvedTarget, TargetKind};
use bookworm_structure::{parse, references, FileStructure, Symbol};
use bookworm_verify::{run as run_checks, Check};
use std::path::Path;

use super::{package_text, record_injections, token_ceiling};

pub struct AcquireOpts<'a> {
    pub model_name: &'a str,
    pub max_tokens: Option<u64>,
    pub consensus: ConsensusMode,
    pub privacy: PrivacyPolicy,
    pub scope: &'a ScopePolicy,
}

struct Loaded {
    resolved: ResolvedTarget,
    measurement: bookworm_measure::Measurement,
    classification: bookworm_classify::Classification,
    text: Option<String>,
    parsed: Option<FileStructure>,
}

pub fn explain_file(
    path: &Path,
    question: Option<&str>,
    opts: &AcquireOpts<'_>,
) -> Result<EvidenceEnvelope> {
    let mut env = structural_quote(
        path,
        ReadIntent::Explain,
        Fidelity::Structural,
        opts,
        question,
    )?;
    env.output.unknowns.push(
        "explain returns structural evidence quoted from the source; Bookworm does not paraphrase"
            .to_string(),
    );
    if let Some(question) = question {
        env.output.unknowns.push(format!(
            "question {question:?} was recorded and was not answered by a model"
        ));
    }
    Ok(restamp(env))
}

pub fn summarise_file(path: &Path, opts: &AcquireOpts<'_>) -> Result<EvidenceEnvelope> {
    let loaded = load_file(path, opts.scope)?;
    let model = model_of(opts)?;
    let mut env = empty_envelope(
        &loaded,
        ReadIntent::Summarise,
        Fidelity::Extractive,
        opts,
        None,
    );
    let plan = bookworm_budget::plan_lossless(
        &model,
        loaded.measurement.estimated_tokens,
        &bookworm_core::Budget {
            max_input_tokens: opts.max_tokens,
            ..bookworm_core::Budget::default()
        },
    );
    let mut omissions = plan.notes.clone();
    let mut output = OutputBlock::default();
    match (&loaded.text, &loaded.parsed) {
        (Some(text), Some(parsed)) => {
            let ceiling = token_ceiling(plan.net_available, opts.max_tokens);
            let fitted = bookworm_reader::extractive_summary(text, parsed, ceiling);
            output.unknowns.extend(fitted.notes.clone());
            if fitted.text.is_empty() {
                output.status = "partial".to_string();
                env.strategy.coverage = Coverage::Unknown;
            } else {
                output.content = Some(ContentPayload::Text {
                    lines: fitted.text.lines().count() as u64,
                    text: package_text(&fitted.text, &opts.privacy),
                });
                env.strategy.coverage = fitted.coverage;
                env.measurement.tokens_ingested = Some(fitted.tokens);
                env.measurement.estimation_method = Some(bookworm_tokenize::METHOD.to_string());
                output.status = if fitted.coverage == Coverage::Targeted {
                    "complete".to_string()
                } else {
                    "partial".to_string()
                };
            }
            push_symbol_claims(&mut output, &loaded, parsed, 64);
            record_injections(&mut output, &path_of(&loaded), text);
        }
        _ => {
            output.status = "partial".to_string();
            output
                .unknowns
                .push("summary requires decodable text".to_string());
            env.strategy.coverage = Coverage::Unknown;
        }
    }
    if !opts.consensus.executable() {
        refuse_consensus(&mut output, opts.consensus);
        env.strategy.coverage = Coverage::Unknown;
    }
    omissions.push(
        "extractive summary quotes signatures and doc lines; nothing was paraphrased".to_string(),
    );
    env.strategy.omissions = omissions;
    env.strategy.ingestion_strategy = bookworm_budget::IngestionTier::Tier2.as_str().to_string();
    env.strategy.reader_model = Some("structural".to_string());
    finish(&loaded, opts, env, output)
}

pub fn extract_file(
    path: &Path,
    symbol: Option<&str>,
    opts: &AcquireOpts<'_>,
) -> Result<EvidenceEnvelope> {
    let loaded = load_file(path, opts.scope)?;
    let mut env = empty_envelope(
        &loaded,
        ReadIntent::Extract,
        Fidelity::Extractive,
        opts,
        symbol,
    );
    let mut output = OutputBlock::default();
    let Some(text) = loaded.text.clone() else {
        output.status = "partial".to_string();
        output
            .unknowns
            .push("extract requires decodable text".to_string());
        env.strategy.coverage = Coverage::Unknown;
        return finish(&loaded, opts, env, output);
    };
    let parsed = loaded.parsed.clone().unwrap_or_else(|| parse(&text, None));
    if let Some(name) = symbol {
        match parsed.symbols.iter().find(|s| s.name == name) {
            Some(symbol) => {
                let slice =
                    bookworm_structure::line_slice(&text, symbol.start_line, symbol.end_line);
                match slice {
                    Some(slice) => {
                        let tokens = bookworm_tokenize::count(&slice);
                        if let Some(cap) = opts.max_tokens {
                            if tokens > cap {
                                output.status = "partial".to_string();
                                env.strategy.coverage = Coverage::Unknown;
                                output.unknowns.push(format!(
                                    "symbol {name} is {tokens} {} tokens and exceeds the caller ceiling {cap}",
                                    bookworm_tokenize::METHOD
                                ));
                            } else {
                                put_quote(&mut output, &mut env, &slice, tokens, &opts.privacy);
                                env.strategy.coverage = Coverage::Targeted;
                            }
                        } else {
                            put_quote(&mut output, &mut env, &slice, tokens, &opts.privacy);
                            env.strategy.coverage = Coverage::Targeted;
                        }
                        output.claims.push(Claim::deterministic(
                            "bw-c-0001",
                            format!(
                                "{} {} at lines {}-{}",
                                symbol.kind.as_str(),
                                symbol.name,
                                symbol.start_line,
                                symbol.end_line
                            ),
                            vec![span_for(&loaded, symbol)],
                            vec!["structural_parse".to_string(), "range_hash".to_string()],
                        ));
                    }
                    None => {
                        output.status = "failed".to_string();
                        output.unknowns.push(format!(
                            "symbol {name} has a range outside the decoded file"
                        ));
                        env.strategy.coverage = Coverage::Unknown;
                    }
                }
            }
            None => {
                output.status = "failed".to_string();
                env.strategy.coverage = Coverage::Unknown;
                output.unknowns.push(format!(
                    "symbol {name:?} was not found by {}",
                    parsed.method
                ));
                output.claims.push(Claim::unknown(
                    "bw-c-0001",
                    format!("symbol {name:?} was not found in {}", path_of(&loaded)),
                ));
            }
        }
    } else {
        let ceiling = opts.max_tokens.unwrap_or(u64::MAX) as i64;
        let fitted = bookworm_reader::extractive_summary(&text, &parsed, ceiling);
        output.unknowns.extend(fitted.notes);
        if fitted.text.is_empty() {
            output.status = "partial".to_string();
            env.strategy.coverage = Coverage::Unknown;
            output
                .unknowns
                .push("no signatures were available to extract".to_string());
        } else {
            put_quote(
                &mut output,
                &mut env,
                &fitted.text,
                fitted.tokens,
                &opts.privacy,
            );
            env.strategy.coverage = fitted.coverage;
        }
        push_symbol_claims(&mut output, &loaded, &parsed, 64);
    }
    record_injections(&mut output, &path_of(&loaded), &text);
    env.strategy.ingestion_strategy = bookworm_budget::IngestionTier::Tier2.as_str().to_string();
    env.strategy.reader_model = Some("structural".to_string());
    env.strategy
        .omissions
        .push("extract quotes source bytes; nothing was paraphrased".to_string());
    finish(&loaded, opts, env, output)
}

pub fn compare_files(
    left: &Path,
    right: &Path,
    opts: &AcquireOpts<'_>,
) -> Result<EvidenceEnvelope> {
    let left_loaded = load_file(left, opts.scope)?;
    let right_loaded = load_file(right, opts.scope)?;
    let left_parsed = left_loaded.parsed.clone().unwrap_or_else(|| FileStructure {
        language: "unknown".into(),
        method: "none".into(),
        complete: false,
        symbols: Vec::new(),
        imports: Vec::new(),
        notes: vec!["left target had no structural parse".into()],
    });
    let right_parsed = right_loaded
        .parsed
        .clone()
        .unwrap_or_else(|| FileStructure {
            language: "unknown".into(),
            method: "none".into(),
            complete: false,
            symbols: Vec::new(),
            imports: Vec::new(),
            notes: vec!["right target had no structural parse".into()],
        });
    let diff = diff_symbols(&left_parsed, &right_parsed);
    let mut req = ContextRequest::new(
        ReadIntent::Compare,
        vec![
            Target::File {
                path: left_loaded.resolved.canonical.clone(),
            },
            Target::File {
                path: right_loaded.resolved.canonical.clone(),
            },
        ],
    );
    req.fidelity = Fidelity::Structural;
    req.consensus = opts.consensus;
    req.privacy = opts.privacy.clone();
    req.budget.max_input_tokens = opts.max_tokens;
    let mut env = EvidenceEnvelope::new(
        req.request_id(),
        TargetIdentity::from_resolved(&left_loaded.resolved),
    );
    env.measurement = MeasurementBlock {
        files_discovered: 2,
        files_considered: 2,
        files_read: 2,
        lines_read: left_loaded.measurement.lines + right_loaded.measurement.lines,
        bytes_read: left_loaded.measurement.bytes + right_loaded.measurement.bytes,
        tokens_ingested: None,
        estimation_method: Some(bookworm_tokenize::METHOD.to_string()),
    };
    let mut report = String::new();
    report.push_str("added:\n");
    for item in &diff.added {
        report.push_str(item);
        report.push('\n');
    }
    report.push_str("removed:\n");
    for item in &diff.removed {
        report.push_str(item);
        report.push('\n');
    }
    report.push_str("unchanged:\n");
    for item in &diff.unchanged {
        report.push_str(item);
        report.push('\n');
    }
    let mut output = OutputBlock::default();
    output.content = Some(ContentPayload::Text {
        lines: report.lines().count() as u64,
        text: package_text(&report, &opts.privacy),
    });
    output.claims.push(Claim::deterministic(
        "bw-c-0001",
        format!(
            "symbol diff: {} added, {} removed, {} unchanged",
            diff.added.len(),
            diff.removed.len(),
            diff.unchanged.len()
        ),
        vec![file_span(&left_loaded), file_span(&right_loaded)],
        vec!["structural_parse".to_string()],
    ));
    let mut claim_no = 1usize;
    for name in diff.added.iter().take(64) {
        claim_no += 1;
        output.claims.push(Claim::deterministic(
            &format!("bw-c-{claim_no:04}"),
            format!("added {name}"),
            vec![file_span(&right_loaded)],
            vec!["structural_parse".to_string()],
        ));
    }
    for name in diff.removed.iter().take(64) {
        claim_no += 1;
        output.claims.push(Claim::deterministic(
            &format!("bw-c-{claim_no:04}"),
            format!("removed {name}"),
            vec![file_span(&left_loaded)],
            vec!["structural_parse".to_string()],
        ));
    }
    let coverage = if left_parsed.complete && right_parsed.complete {
        Coverage::StructurallyExhaustive
    } else {
        Coverage::Partial
    };
    env.strategy = StrategyBlock {
        classification: "structural_diff".to_string(),
        language: None,
        ingestion_strategy: bookworm_budget::IngestionTier::Tier2.as_str().to_string(),
        reader_model: Some("structural".to_string()),
        consensus_mode: opts.consensus.as_str().to_string(),
        coverage,
        omissions: {
            let mut notes = left_parsed.notes.clone();
            notes.extend(right_parsed.notes.clone());
            notes.push(
                "compare reports symbol names and kinds; function bodies were not diffed"
                    .to_string(),
            );
            notes
        },
    };
    if !opts.consensus.executable() {
        refuse_consensus(&mut output, opts.consensus);
        output.content = None;
        env.strategy.coverage = Coverage::Unknown;
    }
    let checks = vec![
        Check::HashIs {
            path: left_loaded.resolved.canonical.clone(),
            sha256: left_loaded.measurement.sha256.clone(),
        },
        Check::HashIs {
            path: right_loaded.resolved.canonical.clone(),
            sha256: right_loaded.measurement.sha256.clone(),
        },
    ];
    env.verification = run_checks(&checks);
    if env.verification.failed > 0 {
        output.status = "failed".to_string();
    }
    env.output = output;
    env.identity = IdentityBlock {
        source_hashes: vec![
            HashEntry {
                path: path_of(&left_loaded),
                sha256: left_loaded.measurement.sha256.clone(),
            },
            HashEntry {
                path: path_of(&right_loaded),
                sha256: right_loaded.measurement.sha256.clone(),
            },
        ],
        result_hash: String::new(),
    };
    Ok(env.finalize())
}

pub fn trace_symbol(symbol: &str, root: &Path, opts: &AcquireOpts<'_>) -> Result<EvidenceEnvelope> {
    scan_symbol(symbol, root, opts, ReadIntent::Trace, false)
}

pub fn impact_symbol(
    symbol: &str,
    root: &Path,
    opts: &AcquireOpts<'_>,
) -> Result<EvidenceEnvelope> {
    scan_symbol(symbol, root, opts, ReadIntent::Impact, true)
}

fn scan_symbol(
    symbol: &str,
    root: &Path,
    opts: &AcquireOpts<'_>,
    intent: ReadIntent,
    impact: bool,
) -> Result<EvidenceEnvelope> {
    let resolved = resolve(root, opts.scope)?;
    let mut findings = Vec::new();
    let mut hashes: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut files = 0u64;
    let mut lines = 0u64;
    let mut bytes = 0u64;
    let mut notes = Vec::new();
    let mut incomplete = false;
    let walk_root = if resolved.kind == TargetKind::File {
        None
    } else {
        Some(resolved.canonical.clone())
    };
    let files_to_scan: Vec<std::path::PathBuf> = if let Some(dir) = &walk_root {
        let mut acc = Vec::new();
        for entry in walkdir::WalkDir::new(dir).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    notes.push(format!("walk error: {err}"));
                    incomplete = true;
                    continue;
                }
            };
            if entry.depth() > 0 && entry.path().components().any(|c| c.as_os_str() == ".git") {
                continue;
            }
            if entry.file_type().is_file() {
                acc.push(entry.path().to_path_buf());
            }
        }
        acc
    } else {
        vec![resolved.canonical.clone()]
    };
    for path in &files_to_scan {
        let Ok((raw, measurement)) = measure_file(path) else {
            notes.push(format!("unreadable {}", path.display()));
            incomplete = true;
            continue;
        };
        files += 1;
        bytes += measurement.bytes;
        hashes.insert(
            path.to_string_lossy().into_owned(),
            measurement.sha256.clone(),
        );
        let Some(text) = bookworm_core::decode_text(&raw, measurement.encoding) else {
            notes.push(format!("skipped non-text {}", path.display()));
            continue;
        };
        lines += text.lines().count() as u64;
        let class = classify(path, &raw, measurement.encoding);
        let lang = class.language.map(|l| l.as_str().to_string());
        let refs = references(&text, lang.as_deref(), symbol);
        for r in refs {
            if findings.len() < 200 {
                findings.push(Finding {
                    path: path.to_string_lossy().into_owned(),
                    line_start: r.line,
                    line_end: r.line,
                    excerpt: r.excerpt,
                    kind: r.kind,
                });
            }
        }
    }
    if findings.len() == 200 {
        notes.push("reference list capped at 200; the scan itself was not sampled".to_string());
    }
    if impact {
        notes.push(
            "impact lists textual and syntactic reference sites; dynamic dispatch is not resolved"
                .to_string(),
        );
    }
    let mut req = ContextRequest::new(
        intent,
        vec![Target::Symbol {
            name: symbol.to_string(),
            scope: Some(resolved.canonical.clone()),
        }],
    );
    req.fidelity = Fidelity::Structural;
    req.consensus = opts.consensus;
    req.privacy = opts.privacy.clone();
    req.budget.max_input_tokens = opts.max_tokens;
    let mut env = EvidenceEnvelope::new(req.request_id(), TargetIdentity::from_resolved(&resolved));
    env.measurement = MeasurementBlock {
        files_discovered: files,
        files_considered: files,
        files_read: files,
        lines_read: lines,
        bytes_read: bytes,
        tokens_ingested: None,
        estimation_method: None,
    };
    let coverage = if incomplete {
        Coverage::Partial
    } else if findings.is_empty() {
        Coverage::Exhaustive
    } else {
        Coverage::StructurallyExhaustive
    };
    env.strategy = StrategyBlock {
        classification: "reference_scan".to_string(),
        language: None,
        ingestion_strategy: bookworm_budget::IngestionTier::Tier0.as_str().to_string(),
        reader_model: Some("structural".to_string()),
        consensus_mode: opts.consensus.as_str().to_string(),
        coverage,
        omissions: notes,
    };
    let statement = if findings.is_empty() {
        format!(
            "symbol {symbol:?} was not referenced in {files} scanned file(s) under {}",
            resolved.canonical.display()
        )
    } else {
        format!(
            "symbol {symbol:?} has {} reference site(s) in {files} scanned file(s)",
            findings.len()
        )
    };
    let mut output = OutputBlock {
        findings: findings.clone(),
        ..OutputBlock::default()
    };
    output.claims.push(Claim::deterministic(
        "bw-c-0001",
        statement,
        findings
            .iter()
            .take(8)
            .map(|f| bookworm_core::EvidenceSpan {
                path: f.path.clone(),
                start_line: f.line_start,
                end_line: f.line_end,
                hash: hashes.get(&f.path).cloned().unwrap_or_default(),
                range_hash: None,
            })
            .collect(),
        vec!["structural_parse".to_string(), "text_scan".to_string()],
    ));
    if !opts.consensus.executable() {
        refuse_consensus(&mut output, opts.consensus);
        env.strategy.coverage = Coverage::Unknown;
    }
    env.output = output;
    env.identity = IdentityBlock {
        source_hashes: Vec::new(),
        result_hash: String::new(),
    };
    Ok(env.finalize())
}

fn structural_quote(
    path: &Path,
    intent: ReadIntent,
    fidelity: Fidelity,
    opts: &AcquireOpts<'_>,
    question: Option<&str>,
) -> Result<EvidenceEnvelope> {
    let loaded = load_file(path, opts.scope)?;
    let model = model_of(opts)?;
    let mut env = empty_envelope(&loaded, intent, fidelity, opts, question);
    let plan = bookworm_budget::plan_lossless(
        &model,
        loaded.measurement.estimated_tokens,
        &bookworm_core::Budget {
            max_input_tokens: opts.max_tokens,
            ..bookworm_core::Budget::default()
        },
    );
    let mut output = OutputBlock::default();
    let mut omissions = plan.notes.clone();
    if !opts.consensus.executable() {
        refuse_consensus(&mut output, opts.consensus);
        env.strategy.coverage = Coverage::Unknown;
    } else if plan.feasible {
        if let Some(text) = &loaded.text {
            output.content = Some(ContentPayload::Text {
                lines: loaded.measurement.lines,
                text: package_text(text, &opts.privacy),
            });
            env.strategy.coverage = Coverage::Exhaustive;
            env.strategy.ingestion_strategy =
                bookworm_budget::IngestionTier::Tier1.as_str().to_string();
            env.strategy.reader_model = Some("deterministic".to_string());
            record_injections(&mut output, &path_of(&loaded), text);
        }
    } else if let (Some(text), Some(parsed)) = (&loaded.text, &loaded.parsed) {
        let ceiling = token_ceiling(plan.net_available, opts.max_tokens);
        let fitted = bookworm_reader::fit_symbols(text, &parsed.symbols, ceiling);
        output.unknowns.extend(fitted.notes);
        if fitted.text.is_empty() {
            output.status = "partial".to_string();
            env.strategy.coverage = Coverage::Unknown;
            output.unknowns.push(
                "full content exceeds the budget and no whole symbol fit inside it".to_string(),
            );
        } else {
            put_quote(
                &mut output,
                &mut env,
                &fitted.text,
                fitted.tokens,
                &opts.privacy,
            );
            env.strategy.coverage = fitted.coverage;
            output.status = "partial".to_string();
        }
        env.strategy.ingestion_strategy =
            bookworm_budget::IngestionTier::Tier2.as_str().to_string();
        env.strategy.reader_model = Some("structural".to_string());
        record_injections(&mut output, &path_of(&loaded), text);
    } else {
        output.status = "partial".to_string();
        env.strategy.coverage = Coverage::Unknown;
        output
            .unknowns
            .push("target is not decodable text".to_string());
    }
    if let Some(parsed) = &loaded.parsed {
        if !parsed.complete {
            omissions.extend(parsed.notes.clone());
        }
        push_symbol_claims(&mut output, &loaded, parsed, 64);
    }
    env.strategy.omissions = omissions;
    finish(&loaded, opts, env, output)
}

fn load_file(path: &Path, scope: &ScopePolicy) -> Result<Loaded> {
    let resolved = resolve(path, scope)?;
    if resolved.kind == TargetKind::Directory {
        return Err(Error::AmbiguousTarget {
            detail: "target is a directory; use `bookworm map` for structural inventories"
                .to_string(),
        });
    }
    let (bytes, measurement) =
        measure_file(&resolved.canonical).map_err(|e| Error::io(&resolved.canonical, e))?;
    let classification = classify(&resolved.canonical, &bytes, measurement.encoding);
    let text = bookworm_core::decode_text(&bytes, measurement.encoding);
    let parsed = text
        .as_ref()
        .map(|body| parse(body, classification.language.map(|l| l.as_str())));
    Ok(Loaded {
        resolved,
        measurement,
        classification,
        text,
        parsed,
    })
}

fn model_of(opts: &AcquireOpts<'_>) -> Result<ModelSpec> {
    bookworm_budget::find_model(opts.model_name).ok_or_else(|| Error::Usage {
        detail: format!("unknown model {:?}", opts.model_name),
    })
}

fn empty_envelope(
    loaded: &Loaded,
    intent: ReadIntent,
    fidelity: Fidelity,
    opts: &AcquireOpts<'_>,
    question: Option<&str>,
) -> EvidenceEnvelope {
    let mut req = ContextRequest::new(
        intent,
        vec![Target::File {
            path: loaded.resolved.canonical.clone(),
        }],
    );
    req.fidelity = fidelity;
    req.consensus = opts.consensus;
    req.privacy = opts.privacy.clone();
    req.verification = VerificationPolicy::Standard;
    req.budget.max_input_tokens = opts.max_tokens;
    req.question = question.map(str::to_string);
    let mut env = EvidenceEnvelope::new(
        req.request_id(),
        TargetIdentity::from_resolved(&loaded.resolved),
    );
    env.measurement = MeasurementBlock {
        files_discovered: 1,
        files_considered: 1,
        files_read: 1,
        lines_read: loaded.measurement.lines,
        bytes_read: loaded.measurement.bytes,
        tokens_ingested: loaded.measurement.estimated_tokens,
        estimation_method: loaded.measurement.estimation_method.clone(),
    };
    env.strategy = StrategyBlock {
        classification: loaded.classification.class.as_str().to_string(),
        language: loaded
            .classification
            .language
            .map(|l| l.as_str().to_string()),
        ingestion_strategy: bookworm_budget::IngestionTier::Tier2.as_str().to_string(),
        reader_model: Some("structural".to_string()),
        consensus_mode: opts.consensus.as_str().to_string(),
        coverage: Coverage::Unknown,
        omissions: Vec::new(),
    };
    env
}

fn finish(
    loaded: &Loaded,
    opts: &AcquireOpts<'_>,
    mut env: EvidenceEnvelope,
    mut output: OutputBlock,
) -> Result<EvidenceEnvelope> {
    if opts.consensus.executable() && output.claims.is_empty() {
        output.claims.push(Claim::deterministic(
            "bw-c-0001",
            format!(
                "{} contains {} lines and {} bytes",
                path_of(loaded),
                loaded.measurement.lines,
                loaded.measurement.bytes
            ),
            vec![file_span(loaded)],
            vec!["byte_measurement".to_string(), "line_count".to_string()],
        ));
    }
    let report = run_checks(&[Check::HashIs {
        path: loaded.resolved.canonical.clone(),
        sha256: loaded.measurement.sha256.clone(),
    }]);
    if report.failed > 0 {
        output.status = "failed".to_string();
    }
    env.verification = report;
    env.output = output;
    env.identity = IdentityBlock {
        source_hashes: vec![HashEntry {
            path: path_of(loaded),
            sha256: loaded.measurement.sha256.clone(),
        }],
        result_hash: String::new(),
    };
    Ok(env.finalize())
}

fn restamp(mut env: EvidenceEnvelope) -> EvidenceEnvelope {
    env.identity.result_hash.clear();
    env.finalize()
}

fn put_quote(
    output: &mut OutputBlock,
    env: &mut EvidenceEnvelope,
    text: &str,
    tokens: u64,
    privacy: &PrivacyPolicy,
) {
    output.content = Some(ContentPayload::Text {
        lines: text.lines().count() as u64,
        text: package_text(text, privacy),
    });
    env.measurement.tokens_ingested = Some(tokens);
    env.measurement.estimation_method = Some(bookworm_tokenize::METHOD.to_string());
    if output.status == "complete" {
        output.status = "complete".to_string();
    }
}

fn push_symbol_claims(
    output: &mut OutputBlock,
    loaded: &Loaded,
    parsed: &FileStructure,
    cap: usize,
) {
    let limit = parsed.symbols.len().min(cap);
    let start = output.claims.len();
    for (i, symbol) in parsed.symbols.iter().take(limit).enumerate() {
        let id = format!("bw-c-{:04}", start + i + 1);
        output.claims.push(Claim::deterministic(
            &id,
            format!(
                "{} {} at lines {}-{}",
                symbol.kind.as_str(),
                symbol.name,
                symbol.start_line,
                symbol.end_line
            ),
            vec![span_for(loaded, symbol)],
            vec!["structural_parse".to_string(), "range_hash".to_string()],
        ));
    }
}

fn span_for(loaded: &Loaded, symbol: &Symbol) -> bookworm_core::EvidenceSpan {
    bookworm_core::EvidenceSpan {
        path: path_of(loaded),
        start_line: symbol.start_line,
        end_line: symbol.end_line,
        hash: loaded.measurement.sha256.clone(),
        range_hash: Some(symbol.range_hash.clone()),
    }
}

fn file_span(loaded: &Loaded) -> bookworm_core::EvidenceSpan {
    bookworm_core::EvidenceSpan {
        path: path_of(loaded),
        start_line: 1,
        end_line: loaded.measurement.lines.max(1),
        hash: loaded.measurement.sha256.clone(),
        range_hash: None,
    }
}

fn path_of(loaded: &Loaded) -> String {
    loaded.resolved.canonical.to_string_lossy().into_owned()
}

fn refuse_consensus(output: &mut OutputBlock, mode: ConsensusMode) {
    output.status = "failed".to_string();
    output.content = None;
    output.unknowns.push(format!(
        "consensus mode '{}' was not executed; no additional reader is configured",
        mode.as_str()
    ));
}
