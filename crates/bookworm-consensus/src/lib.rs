//! Claim-level consensus (directive §10).
//!
//! This is not a vote over prose. Two claim sets are aligned by normalised
//! statement. Where a deterministic verification method supports one side,
//! that side wins. Where both sides are verified and disagree, both are
//! marked conflicting. Modes that require extra models are not simulated.

use bookworm_core::{Claim, ClaimStatus, ConsensusMode};

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimSet {
    pub source: String,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Adjudication {
    pub mode: ConsensusMode,
    pub claims: Vec<Claim>,
    pub conflicts: Vec<String>,
    pub notes: Vec<String>,
}

const MACHINE_METHODS: &[&str] = &[
    "stat",
    "text_scan",
    "regex_scan",
    "line_count",
    "lexical_word_scan",
    "tree_sitter_symbol",
    "manifest_parse",
    "git_rev_parse",
    "sha256",
    "byte_measurement",
    "encoding_sniff",
    "path_convention",
    "structural_parse",
    "range_hash",
];

/// Adjudicate `sets`. An empty list yields no claims.
///
/// `None` returns the first set unchanged. `VerifyOnDisagreement` runs the
/// machine adjudicator. Every other mode returns the first set unmarked and
/// a note that the mode was not executed.
pub fn adjudicate(mode: ConsensusMode, sets: &[ClaimSet]) -> Adjudication {
    if !mode.executable() {
        return Adjudication {
            mode,
            claims: sets.first().map(|s| s.claims.clone()).unwrap_or_default(),
            conflicts: Vec::new(),
            notes: vec![format!(
                "consensus mode '{}' was not executed; no additional reader is configured",
                mode.as_str()
            )],
        };
    }
    if mode == ConsensusMode::None || sets.len() <= 1 {
        return Adjudication {
            mode,
            claims: sets.first().map(|s| s.claims.clone()).unwrap_or_default(),
            conflicts: Vec::new(),
            notes: vec!["single deterministic reader; no disagreement to adjudicate".to_string()],
        };
    }

    let mut notes = vec![
        "disagreements are resolved from verification methods, not from prose voting".to_string(),
    ];
    let mut groups: Vec<Group> = Vec::new();
    for set in sets {
        for claim in &set.claims {
            let key = normalise(&claim.statement);
            if let Some(group) = groups.iter_mut().find(|g| g.key == key) {
                group.members.push((set.source.clone(), claim.clone()));
            } else {
                groups.push(Group {
                    key,
                    members: vec![(set.source.clone(), claim.clone())],
                });
            }
        }
    }

    let mut claims = Vec::new();
    let mut conflicts = Vec::new();
    for group in groups {
        let statuses: Vec<ClaimStatus> = group.members.iter().map(|(_, c)| c.status).collect();
        let all_same = statuses.windows(2).all(|w| w[0] == w[1]);
        if all_same {
            if let Some((_, claim)) = group.members.first() {
                claims.push(claim.clone());
            }
            continue;
        }
        let machine: Vec<&Claim> = group
            .members
            .iter()
            .filter(|(_, c)| is_machine(c))
            .map(|(_, c)| c)
            .collect();
        let machine_verified = machine
            .iter()
            .filter(|c| c.status == ClaimStatus::Verified)
            .count();
        if machine_verified == 1 {
            let winner = *machine
                .iter()
                .find(|c| c.status == ClaimStatus::Verified)
                .expect("count was one");
            let mut kept = (*winner).clone();
            kept.verification.push("adjudicated_by_machine".to_string());
            claims.push(kept);
            conflicts.push(format!(
                "disagreement on '{}' resolved by deterministic verification",
                group.members[0].1.statement
            ));
        } else {
            for (_, claim) in &group.members {
                let mut marked = claim.clone();
                marked.status = ClaimStatus::Conflicting;
                marked.confidence = None;
                claims.push(marked);
            }
            conflicts.push(format!(
                "unresolved disagreement on '{}'",
                group.members[0].1.statement
            ));
            notes.push(
                "no single machine check decided the disagreement; claims marked conflicting"
                    .to_string(),
            );
        }
    }

    Adjudication {
        mode,
        claims,
        conflicts,
        notes,
    }
}

struct Group {
    key: String,
    members: Vec<(String, Claim)>,
}

fn normalise(statement: &str) -> String {
    statement.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase()
}

fn is_machine(claim: &Claim) -> bool {
    claim
        .verification
        .iter()
        .any(|m| MACHINE_METHODS.iter().any(|known| m == known))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bookworm_core::EvidenceSpan;

    fn claim(statement: &str, status: ClaimStatus, method: &str) -> Claim {
        Claim {
            claim_id: "bw-c-0001".into(),
            statement: statement.into(),
            status,
            confidence: Some(1.0),
            evidence: vec![EvidenceSpan {
                path: "a.rs".into(),
                start_line: 1,
                end_line: 1,
                hash: "abc".into(),
                range_hash: None,
            }],
            verification: vec![method.into()],
        }
    }

    #[test]
    fn machine_check_beats_unverified_disagreement() {
        let a = ClaimSet {
            source: "reader-a".into(),
            claims: vec![claim(
                "foo is called by bar",
                ClaimStatus::Verified,
                "tree_sitter_symbol",
            )],
        };
        let b = ClaimSet {
            source: "reader-b".into(),
            claims: vec![claim(
                "foo is called by bar",
                ClaimStatus::Unverified,
                "model",
            )],
        };
        let out = adjudicate(ConsensusMode::VerifyOnDisagreement, &[a, b]);
        assert_eq!(out.claims.len(), 1);
        assert_eq!(out.claims[0].status, ClaimStatus::Verified);
        assert!(!out.conflicts.is_empty());
    }

    #[test]
    fn dual_mode_is_not_simulated() {
        let a = ClaimSet {
            source: "a".into(),
            claims: vec![claim("x", ClaimStatus::Verified, "sha256")],
        };
        let out = adjudicate(ConsensusMode::Dual, &[a]);
        assert!(out.notes[0].contains("not executed"));
    }
}
