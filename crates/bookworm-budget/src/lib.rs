//! Token accounting and ingestion-tier planning (directive §7, §8).
//!
//! Implements B_net(m) = C_m − S_m − R − O − E explicitly and refuses plans
//! that exceed the calculated net context (BW-G04). The model table is an
//! offline nominal-capacity registry: when reader integration lands, the
//! router (§9) replaces nominal numbers with empirical capability records.

use bookworm_core::Budget;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestionTier {
    Tier0,
    Tier1,
    Tier2,
    Tier3,
    Tier4,
    Tier5,
}

impl IngestionTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            IngestionTier::Tier0 => "tier0_deterministic_answer",
            IngestionTier::Tier1 => "tier1_lossless_read",
            IngestionTier::Tier2 => "tier2_selective_structural",
            IngestionTier::Tier3 => "tier3_partitioned",
            IngestionTier::Tier4 => "tier4_hierarchical_synthesis",
            IngestionTier::Tier5 => "tier5_directed_deep_investigation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSpec {
    pub name: String,
    pub context_tokens: u64,
    pub nominal_reserved_output_tokens: u64,
}

/// Offline nominal-capacity registry. Numbers are planning constants only and
/// are labelled as such everywhere they surface (§9 routing remains pending).
pub fn builtin_models() -> Vec<ModelSpec> {
    vec![
        ModelSpec {
            name: "openai-gpt-4o".into(),
            context_tokens: 128_000,
            nominal_reserved_output_tokens: 16_384,
        },
        ModelSpec {
            name: "anthropic-claude-sonnet".into(),
            context_tokens: 200_000,
            nominal_reserved_output_tokens: 8_192,
        },
        ModelSpec {
            name: "google-gemini-flash".into(),
            context_tokens: 1_000_000,
            nominal_reserved_output_tokens: 8_192,
        },
        ModelSpec {
            name: "groq-llama-70b".into(),
            context_tokens: 32_768,
            nominal_reserved_output_tokens: 4_096,
        },
        ModelSpec {
            name: "local-ollama-7b".into(),
            context_tokens: 8_192,
            nominal_reserved_output_tokens: 2_048,
        },
    ]
}

pub fn find_model(name: &str) -> Option<ModelSpec> {
    builtin_models().into_iter().find(|m| m.name == name)
}

pub fn default_model() -> ModelSpec {
    find_model("openai-gpt-4o").expect("builtin registry always contains the default model")
}

/// Planning constants for the envelope overhead (§7: E) and the Bookworm
/// system instructions (§7: S_m) consumed by a future reader call.
pub const DEFAULT_SYSTEM_TOKENS: u64 = 800;
pub const DEFAULT_REQUEST_TOKENS: u64 = 128;
pub const ENVELOPE_TOKENS: u64 = 512;

/// Explicit context accounting for a candidate model (§7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenAccount {
    pub model: String,
    pub context_capacity: u64,
    pub system_tokens: u64,
    pub request_tokens: u64,
    pub reserved_output: u64,
    pub envelope_tokens: u64,
    /// B_net = C − S − R − O − E. Negative means the plan is impossible
    /// before a single evidence token is considered (BW-G04).
    pub net_available: i64,
}

pub fn net_context(
    model: &ModelSpec,
    system_tokens: u64,
    request_tokens: u64,
    reserved_output: u64,
    envelope_tokens: u64,
) -> TokenAccount {
    let net_available = model.context_tokens as i64
        - system_tokens as i64
        - request_tokens as i64
        - reserved_output as i64
        - envelope_tokens as i64;
    TokenAccount {
        model: model.name.clone(),
        context_capacity: model.context_tokens,
        system_tokens,
        request_tokens,
        reserved_output,
        envelope_tokens,
        net_available,
    }
}

/// A tier-1 (lossless) plan against one model and the caller's budget.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TierPlan {
    pub tier: IngestionTier,
    /// True when the deterministic pipeline can execute this plan now.
    pub feasible: bool,
    pub model: String,
    pub net_available: i64,
    pub estimated_input_tokens: Option<u64>,
    pub notes: Vec<String>,
}

/// Plan a lossless (tier 1) read. Fails closed: when the estimate exceeds the
/// net context or the caller's ceiling, the plan is infeasible and a higher
/// tier is *recommended* — never silently chunked (§8: arbitrary fixed-token
/// chunking is a fallback, and semantic tiers require reader integration).
pub fn plan_lossless(
    model: &ModelSpec,
    estimated_input_tokens: Option<u64>,
    budget: &Budget,
) -> TierPlan {
    let reserved_output = budget
        .reserved_output_tokens
        .max(model.nominal_reserved_output_tokens);
    let account = net_context(
        model,
        DEFAULT_SYSTEM_TOKENS,
        DEFAULT_REQUEST_TOKENS,
        reserved_output,
        ENVELOPE_TOKENS,
    );
    let mut notes = Vec::new();

    let feasible = match estimated_input_tokens {
        Some(est) => {
            let fits_net = account.net_available >= est as i64;
            let fits_budget = budget
                .max_input_tokens
                .map(|cap| cap >= est)
                .unwrap_or(true);
            if !fits_net {
                notes.push(format!(
                    "estimated input {} tokens exceeds net context {} on {}",
                    est, account.net_available, model.name
                ));
                notes.push("partitioned read (tier 3) recommended; reader integration pending (ROADMAP P1)".to_string());
            }
            if !fits_budget {
                notes.push(format!(
                    "estimated input {} tokens exceeds caller budget ceiling",
                    est
                ));
            }
            fits_net && fits_budget
        }
        None => {
            notes.push(
                "no token estimate available (binary or unknown encoding); refusing to plan a read"
                    .to_string(),
            );
            false
        }
    };

    let tier = if feasible {
        IngestionTier::Tier1
    } else {
        IngestionTier::Tier3
    };
    TierPlan {
        tier,
        feasible,
        model: model.name.clone(),
        net_available: account.net_available,
        estimated_input_tokens,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_context_math_is_explicit() {
        let m = ModelSpec {
            name: "x".into(),
            context_tokens: 10_000,
            nominal_reserved_output_tokens: 1_000,
        };
        let a = net_context(&m, 800, 128, 1_000, 512);
        assert_eq!(a.net_available, 10_000 - 800 - 128 - 1_000 - 512);
    }

    #[test]
    fn net_context_can_be_negative_and_is_reported() {
        let m = ModelSpec {
            name: "tiny".into(),
            context_tokens: 1_000,
            nominal_reserved_output_tokens: 900,
        };
        let a = net_context(&m, 800, 128, 900, 512);
        assert!(a.net_available < 0);
    }

    #[test]
    fn small_estimate_is_feasible_tier1() {
        let plan = plan_lossless(&default_model(), Some(5_000), &Budget::default());
        assert!(plan.feasible);
        assert_eq!(plan.tier, IngestionTier::Tier1);
    }

    #[test]
    fn oversized_estimate_fails_closed_and_recommends_tier3() {
        let plan = plan_lossless(&default_model(), Some(500_000), &Budget::default());
        assert!(!plan.feasible);
        assert_eq!(plan.tier, IngestionTier::Tier3);
        assert!(plan.notes.iter().any(|n| n.contains("exceeds net context")));
    }

    #[test]
    fn caller_ceiling_is_enforced() {
        let budget = Budget {
            max_input_tokens: Some(100),
            ..Budget::default()
        };
        let plan = plan_lossless(&default_model(), Some(5_000), &budget);
        assert!(!plan.feasible);
        assert!(plan
            .notes
            .iter()
            .any(|n| n.contains("caller budget ceiling")));
    }

    #[test]
    fn unknown_estimate_never_plans() {
        let plan = plan_lossless(&default_model(), None, &Budget::default());
        assert!(!plan.feasible);
        assert!(plan.notes.iter().any(|n| n.contains("no token estimate")));
    }

    #[test]
    fn builtin_registry_has_default() {
        assert!(find_model("openai-gpt-4o").is_some());
        assert!(find_model("nope").is_none());
    }
}
