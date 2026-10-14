//! Loopback service adapter (directive §24).
//!
//! Each POST runs the same deterministic acquisition as the CLI and returns
//! the evidence envelope. There is no investigation stream: a response is one
//! JSON document.

use bookworm_core::{ConsensusMode, Error, Fidelity, PrivacyPolicy, Result, VerificationPolicy};
use bookworm_policy::ScopePolicy;
use bookworm_server::{HttpRequest, ServeError};
use bookworm_verify::{run as run_checks, Check};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{
    explain_file, locate, locate_envelope_with, map_directory, read_acquired, AcquireOpts,
};
use crate::Cli;

pub struct ServiceState<'a> {
    pub scope: &'a ScopePolicy,
    pub model: String,
    pub max_tokens: Option<u64>,
    pub consensus: ConsensusMode,
    pub privacy: PrivacyPolicy,
    pub verification: VerificationPolicy,
    pub cache_dir: Option<PathBuf>,
    pub jobs: Arc<Mutex<HashMap<String, Value>>>,
}

pub fn cmd_serve(cli: &Cli, bind: &str, token: Option<&str>, scope: &ScopePolicy) -> Result<i32> {
    let addr: SocketAddr = bind.parse().map_err(|_| Error::Usage {
        detail: format!("invalid bind address {bind:?}; expected host:port"),
    })?;
    let (listener, bound) = bookworm_server::bind(addr).map_err(serve_err)?;
    eprintln!("bookworm listening on http://{bound}");
    let state = ServiceState {
        scope,
        model: cli.model.clone(),
        max_tokens: cli.max_tokens,
        consensus: super::consensus_or_err(&cli.consensus)?,
        privacy: super::privacy_of(cli),
        verification: VerificationPolicy::parse(&cli.verify)
            .unwrap_or(VerificationPolicy::Standard),
        cache_dir: if cli.no_cache {
            None
        } else {
            Some(
                cli.cache_dir
                    .clone()
                    .unwrap_or_else(bookworm_cache::EvidenceCache::default_dir),
            )
        },
        jobs: Arc::new(Mutex::new(HashMap::new())),
    };
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    bookworm_server::serve(listener, token.map(str::to_string), shutdown, |req| {
        serve_request(&state, req)
    })
    .map_err(serve_err)?;
    Ok(0)
}

pub fn serve_request(state: &ServiceState<'_>, req: &HttpRequest) -> (u16, Value) {
    let path = req.path.split('?').next().unwrap_or(req.path.as_str());
    if req.method == "GET" && path == "/v1/health" {
        return (
            200,
            json!({
                "ok": true,
                "version": crate::VERSION,
                "envelope": bookworm_core::ENVELOPE_VERSION,
                "stream": false,
            }),
        );
    }
    if req.method == "GET" && path == "/v1/metrics" {
        return (
            200,
            serde_json::to_value(bookworm_telemetry::snapshot()).unwrap_or(json!({})),
        );
    }
    if req.method == "GET" {
        if let Some(id) = path.strip_prefix("/v1/jobs/") {
            return stored(state, id, false);
        }
        if let Some(id) = path.strip_prefix("/v1/evidence/") {
            return stored(state, id, false);
        }
        if let Some(id) = path.strip_prefix("/v1/claims/") {
            return stored(state, id, true);
        }
    }
    if req.method != "POST" {
        return (404, json!({"error": "not found"}));
    }
    let body: Value = match serde_json::from_slice(&req.body) {
        Ok(value) => value,
        Err(err) => return (400, json!({"error": format!("invalid JSON: {err}")})),
    };
    let result = match path {
        "/v1/read" => post_read(state, &body),
        "/v1/locate" => post_locate(state, &body),
        "/v1/explain" => post_explain(state, &body),
        "/v1/map" => post_map(state, &body),
        "/v1/verify" => post_verify(&body),
        "/v1/estimate" => post_estimate(state, &body),
        _ => return (404, json!({"error": "not found"})),
    };
    match result {
        Ok(value) => {
            if let Some(id) = value.get("request_id").and_then(|v| v.as_str()) {
                if let Ok(mut jobs) = state.jobs.lock() {
                    jobs.insert(id.to_string(), value.clone());
                }
            }
            (200, value)
        }
        Err(err) => (status_for(&err), json!({"error": err.to_string()})),
    }
}

fn stored(state: &ServiceState<'_>, id: &str, claims_only: bool) -> (u16, Value) {
    if let Ok(jobs) = state.jobs.lock() {
        if let Some(value) = jobs.get(id) {
            if claims_only {
                return (
                    200,
                    value
                        .get("output")
                        .and_then(|o| o.get("claims"))
                        .cloned()
                        .unwrap_or(json!([])),
                );
            }
            return (200, value.clone());
        }
    }
    if let Some(dir) = &state.cache_dir {
        if let Ok(cache) = bookworm_cache::EvidenceCache::open(dir) {
            if let Some(env) = cache.get(id) {
                if claims_only {
                    return (
                        200,
                        serde_json::to_value(&env.output.claims).unwrap_or(json!([])),
                    );
                }
                return (200, serde_json::to_value(&env).unwrap_or(json!({})));
            }
        }
    }
    (404, json!({"error": format!("no evidence for {id}")}))
}

fn post_read(state: &ServiceState<'_>, body: &Value) -> Result<Value> {
    let target = required_str(body, "target")?;
    super::guard_target(Path::new(target))?;
    let fidelity = Fidelity::parse(
        body.get("fidelity")
            .and_then(|v| v.as_str())
            .unwrap_or("lossless"),
    )
    .ok_or_else(|| Error::Usage {
        detail: "unknown fidelity".into(),
    })?;
    let model = bookworm_budget::find_model(&state.model).ok_or_else(|| Error::Usage {
        detail: format!("unknown model {}", state.model),
    })?;
    let revision = body.get("revision").and_then(|v| v.as_str());
    let lines = line_pair(body.get("lines"))?;
    let cache = open_cache(state)?;
    let outcome = read_acquired(
        Path::new(target),
        fidelity,
        &model,
        revision,
        state.max_tokens,
        cache.as_ref(),
        state.scope,
        state.consensus,
        state.privacy.clone(),
        state.verification,
        lines,
    )?;
    serde_json::to_value(&outcome.envelope).map_err(|e| Error::Usage {
        detail: e.to_string(),
    })
}

fn post_locate(state: &ServiceState<'_>, body: &Value) -> Result<Value> {
    let pattern = required_str(body, "pattern")?;
    let root = body.get("root").and_then(|v| v.as_str()).unwrap_or(".");
    super::guard_target(Path::new(root))?;
    let regex = body.get("regex").and_then(|v| v.as_bool()).unwrap_or(false);
    let max_results = body
        .get("max_results")
        .and_then(|v| v.as_u64())
        .unwrap_or(50) as usize;
    let outcome = locate(Path::new(root), pattern, regex, max_results)?;
    let env = locate_envelope_with(Path::new(root), pattern, &outcome, state.consensus);
    serde_json::to_value(&env).map_err(|e| Error::Usage {
        detail: e.to_string(),
    })
}

fn post_explain(state: &ServiceState<'_>, body: &Value) -> Result<Value> {
    let target = required_str(body, "target")?;
    super::guard_target(Path::new(target))?;
    let question = body.get("question").and_then(|v| v.as_str());
    let opts = opts_of(state);
    let env = explain_file(Path::new(target), question, &opts)?;
    serde_json::to_value(&env).map_err(|e| Error::Usage {
        detail: e.to_string(),
    })
}

fn post_map(state: &ServiceState<'_>, body: &Value) -> Result<Value> {
    let target = required_str(body, "target")?;
    super::guard_target(Path::new(target))?;
    let depth = body.get("depth").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
    let all = body.get("all").and_then(|v| v.as_bool()).unwrap_or(false);
    let env = map_directory(Path::new(target), depth, all, state.scope, state.consensus)?;
    serde_json::to_value(&env).map_err(|e| Error::Usage {
        detail: e.to_string(),
    })
}

fn post_verify(body: &Value) -> Result<Value> {
    let target = PathBuf::from(required_str(body, "target")?);
    super::guard_target(&target)?;
    let mut checks = Vec::new();
    for needle in string_list(body, "text") {
        checks.push(Check::TextExists {
            path: target.clone(),
            needle,
            regex: false,
        });
    }
    for needle in string_list(body, "regex") {
        checks.push(Check::TextExists {
            path: target.clone(),
            needle,
            regex: true,
        });
    }
    for symbol in string_list(body, "symbol") {
        checks.push(Check::SymbolExists {
            path: target.clone(),
            symbol,
        });
    }
    for module in string_list(body, "import") {
        checks.push(Check::ImportExists {
            path: target.clone(),
            module,
        });
    }
    for key in string_list(body, "config_key") {
        checks.push(Check::ConfigKey {
            path: target.clone(),
            key,
        });
    }
    if let Some((start, end)) = line_pair(body.get("line_range"))? {
        checks.push(Check::LineRangeValid {
            path: target.clone(),
            start,
            end,
        });
    }
    for name in string_list(body, "dep") {
        checks.push(Check::DependencyExists {
            manifest: target.clone(),
            name,
        });
    }
    if let Some(hash) = body.get("hash").and_then(|v| v.as_str()) {
        checks.push(Check::HashIs {
            path: target.clone(),
            sha256: hash.to_string(),
        });
    }
    if let Some(revision) = body.get("revision").and_then(|v| v.as_str()) {
        checks.push(Check::RevisionIs {
            repo: target,
            revision: revision.to_string(),
        });
    }
    if checks.is_empty() {
        return Err(Error::Usage {
            detail: "no checks requested".into(),
        });
    }
    let report = run_checks(&checks);
    serde_json::to_value(&report).map_err(|e| Error::Usage {
        detail: e.to_string(),
    })
}

fn post_estimate(state: &ServiceState<'_>, body: &Value) -> Result<Value> {
    let target = required_str(body, "target")?;
    super::guard_target(Path::new(target))?;
    let model = bookworm_budget::find_model(&state.model).ok_or_else(|| Error::Usage {
        detail: format!("unknown model {}", state.model),
    })?;
    let resolved = bookworm_resolver::resolve(Path::new(target), state.scope)?;
    let (bytes, measurement) = bookworm_measure::measure_file(&resolved.canonical)
        .map_err(|e| Error::io(&resolved.canonical, e))?;
    let class = bookworm_classify::classify(&resolved.canonical, &bytes, measurement.encoding);
    let budget = bookworm_core::Budget {
        max_input_tokens: state.max_tokens,
        ..bookworm_core::Budget::default()
    };
    let plan = bookworm_budget::plan_lossless(&model, measurement.estimated_tokens, &budget);
    Ok(json!({
        "target": resolved.canonical,
        "model": model.name,
        "classification": class.class.as_str(),
        "estimated_input_tokens": measurement.estimated_tokens,
        "estimation_method": measurement.estimation_method,
        "exact_tokens": measurement.exact_tokens,
        "exact_method": measurement.exact_method,
        "plan": plan,
    }))
}

fn opts_of<'a>(state: &'a ServiceState<'_>) -> AcquireOpts<'a> {
    AcquireOpts {
        model_name: &state.model,
        max_tokens: state.max_tokens,
        consensus: state.consensus,
        privacy: state.privacy.clone(),
        scope: state.scope,
    }
}

fn open_cache(state: &ServiceState<'_>) -> Result<Option<bookworm_cache::EvidenceCache>> {
    match &state.cache_dir {
        Some(dir) => Ok(Some(bookworm_cache::EvidenceCache::open(dir)?)),
        None => Ok(None),
    }
}

fn required_str<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    body.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Usage {
            detail: format!("missing string field {key}"),
        })
}

fn string_list(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn line_pair(value: Option<&Value>) -> Result<Option<(u64, u64)>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or_else(|| Error::Usage {
        detail: "lines must be START:END".into(),
    })?;
    let (a, b) = text.split_once(':').ok_or_else(|| Error::Usage {
        detail: format!("expected START:END, got {text:?}"),
    })?;
    let start = a.trim().parse().map_err(|_| Error::Usage {
        detail: "bad line start".into(),
    })?;
    let end = b.trim().parse().map_err(|_| Error::Usage {
        detail: "bad line end".into(),
    })?;
    Ok(Some((start, end)))
}

fn status_for(err: &Error) -> u16 {
    match err {
        Error::TargetMissing { .. } => 404,
        Error::PermissionDenied { .. }
        | Error::OutsideScope { .. }
        | Error::PolicyDenied { .. } => 403,
        _ => 400,
    }
}

fn serve_err(err: ServeError) -> Error {
    Error::Usage {
        detail: err.to_string(),
    }
}
