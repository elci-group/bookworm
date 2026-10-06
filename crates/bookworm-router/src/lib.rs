//! Strategy routing without a model call (directive §8, §9).
//!
//! The router chooses the cheapest deterministic tier that can satisfy the
//! request. It does not invent empirical model scores. Consensus modes that
//! need additional readers are reported as infeasible rather than simulated.

use bookworm_budget::IngestionTier;
use bookworm_core::{ConsensusMode, Fidelity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInput {
    pub fidelity: Fidelity,
    pub estimated_tokens: Option<u64>,
    pub net_available: i64,
    pub max_input_tokens: Option<u64>,
    pub has_structure: bool,
    pub consensus: ConsensusMode,
    pub local_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub tier: IngestionTier,
    pub reader: String,
    pub consensus: String,
    pub feasible: bool,
    pub notes: Vec<String>,
}

impl RouteDecision {
    pub fn tier_name(&self) -> &str {
        self.tier.as_str()
    }
}

/// Select a tier. `feasible` means the deterministic pipeline can produce
/// the evidence package now. A semantic request that also fits losslessly is
/// feasible as a lossless package and records that synthesis was refused.
pub fn route(input: &RouteInput) -> RouteDecision {
    let mut notes = Vec::new();
    let tokens = input.estimated_tokens;
    let fits = match tokens {
        Some(est) => {
            let fits_net = input.net_available >= est as i64;
            let fits_budget = input
                .max_input_tokens
                .map(|cap| cap >= est)
                .unwrap_or(true);
            if !fits_net {
                notes.push(format!(
                    "estimated input {est} tokens exceeds net context {}",
                    input.net_available
                ));
            }
            if !fits_budget {
                notes.push(format!(
                    "estimated input {est} tokens exceeds caller budget ceiling"
                ));
            }
            fits_net && fits_budget
        }
        None => {
            notes.push(
                "no token estimate (binary or unknown encoding); refusing a text read".to_string(),
            );
            false
        }
    };

    if !input.consensus.executable() {
        notes.push(format!(
            "consensus mode '{}' needs additional readers; none are configured",
            input.consensus.as_str()
        ));
    }
    if !input.local_only {
        notes.push(
            "remote reader is not configured; evidence stays local and is not transmitted"
                .to_string(),
        );
    }

    let semantic = matches!(
        input.fidelity,
        Fidelity::Selective | Fidelity::Structural | Fidelity::Extractive | Fidelity::Semantic
    );

    let (tier, reader, feasible) = if tokens.is_none() {
        (IngestionTier::Tier0, "none", false)
    } else if fits && !semantic {
        (IngestionTier::Tier1, "deterministic", true)
    } else if fits && semantic {
        notes.push(
            "requested fidelity needs synthesis; returning lossless evidence and refusing to invent a summary"
                .to_string(),
        );
        (IngestionTier::Tier1, "deterministic", true)
    } else if input.has_structure {
        notes.push(
            "full text does not fit; structural extraction is the executable tier".to_string(),
        );
        (IngestionTier::Tier2, "structural", true)
    } else {
        notes.push(
            "no structural partition is available; refusing fixed-token chunking".to_string(),
        );
        (IngestionTier::Tier3, "none", false)
    };

    let feasible = feasible && input.consensus.executable();

    RouteDecision {
        tier,
        reader: reader.to_string(),
        consensus: input.consensus.as_str().to_string(),
        feasible,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> RouteInput {
        RouteInput {
            fidelity: Fidelity::Lossless,
            estimated_tokens: Some(100),
            net_available: 1_000,
            max_input_tokens: None,
            has_structure: true,
            consensus: ConsensusMode::VerifyOnDisagreement,
            local_only: true,
        }
    }

    #[test]
    fn small_file_is_tier1() {
        let d = route(&base());
        assert_eq!(d.tier, IngestionTier::Tier1);
        assert!(d.feasible);
        assert_eq!(d.reader, "deterministic");
    }

    #[test]
    fn overflow_with_structure_is_tier2() {
        let mut input = base();
        input.estimated_tokens = Some(50_000);
        input.net_available = 100;
        let d = route(&input);
        assert_eq!(d.tier, IngestionTier::Tier2);
        assert!(d.feasible);
    }

    #[test]
    fn dual_consensus_is_not_executable() {
        let mut input = base();
        input.consensus = ConsensusMode::Dual;
        let d = route(&input);
        assert!(!d.feasible);
        assert!(d.notes.iter().any(|n| n.contains("additional readers")));
    }
}
