//! Deterministic readers (directive §8).
//!
//! Tier 1 is a lossless slice when it fits. Tier 2 keeps whole symbols that
//! fit the budget and refuses to cut a symbol in half. There is no semantic
//! reader: summaries are quotations of signatures and doc lines, and the
//! coverage label says so.

use bookworm_core::Coverage;
use bookworm_structure::{line_slice, FileStructure, Symbol};
use bookworm_tokenize::count;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fitted {
    pub text: String,
    pub included: usize,
    pub total: usize,
    pub tokens: u64,
    pub coverage: Coverage,
    pub notes: Vec<String>,
}

/// Keep whole symbols, in source order, while their token cost stays inside
/// `token_budget`. A symbol larger than the budget is skipped and named in
/// `notes` rather than sliced.
pub fn fit_symbols(source: &str, symbols: &[Symbol], token_budget: i64) -> Fitted {
    if symbols.is_empty() {
        return Fitted {
            text: String::new(),
            included: 0,
            total: 0,
            tokens: 0,
            coverage: Coverage::Unknown,
            notes: vec!["no structural symbols to extract".to_string()],
        };
    }
    if token_budget <= 0 {
        return Fitted {
            text: String::new(),
            included: 0,
            total: symbols.len(),
            tokens: 0,
            coverage: Coverage::Unknown,
            notes: vec!["token budget cannot hold a single symbol".to_string()],
        };
    }
    let mut kept: Vec<String> = Vec::new();
    let mut tokens = 0u64;
    let mut notes = Vec::new();
    let mut omitted = 0usize;
    let mut first_omitted: Option<String> = None;
    for symbol in symbols {
        let Some(slice) = line_slice(source, symbol.start_line, symbol.end_line) else {
            omitted += 1;
            if first_omitted.is_none() {
                first_omitted = Some(format!("{} (range outside the file)", symbol.name));
            }
            continue;
        };
        let cost = count(&slice);
        if tokens as i64 + cost as i64 > token_budget {
            omitted += 1;
            if first_omitted.is_none() {
                first_omitted = Some(format!(
                    "{} {} at lines {}-{}",
                    symbol.kind.as_str(),
                    symbol.name,
                    symbol.start_line,
                    symbol.end_line
                ));
            }
            continue;
        }
        tokens += cost;
        kept.push(slice);
    }
    if omitted > 0 {
        notes.push(format!(
            "omitted {omitted} symbol(s) because the budget was exhausted; first: {}",
            first_omitted.unwrap_or_else(|| "unknown".to_string())
        ));
    }
    let included = kept.len();
    let coverage = if included == 0 {
        Coverage::Unknown
    } else if included == symbols.len() {
        Coverage::StructurallyExhaustive
    } else {
        Coverage::Partial
    };
    Fitted {
        text: kept.join("\n\n"),
        included,
        total: symbols.len(),
        tokens,
        coverage,
        notes,
    }
}

/// Quotation-only summary. Every emitted line is copied from the source
/// (a signature, a `///` doc line, or a markdown heading). No sentence is
/// generated about what the code does.
pub fn extractive_summary(source: &str, parsed: &FileStructure, token_budget: i64) -> Fitted {
    let lines: Vec<&str> = source.lines().collect();
    let mut pieces = Vec::new();
    for symbol in &parsed.symbols {
        if symbol.start_line == 0 {
            continue;
        }
        let idx = (symbol.start_line - 1) as usize;
        if idx > 0 {
            let prev = lines[idx - 1].trim();
            if prev.starts_with("///") || prev.starts_with("#") {
                pieces.push(prev.to_string());
            }
        }
        if !symbol.signature.is_empty() {
            pieces.push(symbol.signature.clone());
        }
    }
    if pieces.is_empty() {
        return Fitted {
            text: String::new(),
            included: 0,
            total: 0,
            tokens: 0,
            coverage: Coverage::Unknown,
            notes: vec!["no signatures or doc lines to quote".to_string()],
        };
    }
    let mut kept = Vec::new();
    let mut tokens = 0u64;
    for piece in &pieces {
        let cost = count(piece);
        if token_budget <= 0 || tokens as i64 + cost as i64 > token_budget {
            break;
        }
        tokens += cost;
        kept.push(piece.clone());
    }
    let coverage = if kept.is_empty() {
        Coverage::Unknown
    } else if kept.len() == pieces.len() {
        Coverage::Targeted
    } else {
        Coverage::Partial
    };
    let mut notes = vec![
        "extractive summary: every line is quoted from the source; nothing was paraphrased"
            .to_string(),
    ];
    if kept.len() != pieces.len() {
        notes.push(format!(
            "quoted {} of {} extractive lines before the budget was exhausted",
            kept.len(),
            pieces.len()
        ));
    }
    Fitted {
        text: kept.join("\n"),
        included: kept.len(),
        total: pieces.len(),
        tokens,
        coverage,
        notes,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
}

/// Compare symbol names. Same name and kind counts as unchanged. This does
/// not diff bodies.
pub fn diff_symbols(left: &FileStructure, right: &FileStructure) -> StructureDiff {
    use std::collections::BTreeSet;
    let key = |s: &Symbol| format!("{} {}", s.kind.as_str(), s.name);
    let l: BTreeSet<_> = left.symbols.iter().map(key).collect();
    let r: BTreeSet<_> = right.symbols.iter().map(key).collect();
    StructureDiff {
        added: r.difference(&l).cloned().collect(),
        removed: l.difference(&r).cloned().collect(),
        unchanged: l.intersection(&r).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bookworm_structure::{parse, SymbolKind};

    fn sym(name: &str, line: u64) -> bookworm_structure::Symbol {
        bookworm_structure::Symbol {
            name: name.into(),
            kind: SymbolKind::Function,
            start_line: line,
            end_line: line,
            signature: format!("fn {name}()"),
            range_hash: String::new(),
        }
    }

    #[test]
    fn fit_stops_on_budget_without_splitting() {
        let source = "fn a() {}\nfn b() {}\nfn c() {}\n";
        let symbols = vec![sym("a", 1), sym("b", 2), sym("c", 3)];
        let fitted = fit_symbols(source, &symbols, 8);
        assert!(fitted.included >= 1, "one short function must fit");
        assert!(fitted.included < 3, "the budget must stop before every symbol");
        assert_eq!(fitted.coverage, Coverage::Partial);
        assert!(!fitted.text.contains("fn c()") || fitted.included == 3);
    }

    #[test]
    fn summary_quotes_signature_only() {
        let source = "/// issues a token\npub fn issue() {}\n";
        let parsed = parse(source, Some("rust"));
        let fitted = extractive_summary(source, &parsed, 10_000);
        assert!(fitted.text.contains("pub fn issue()"));
        assert!(fitted.text.contains("/// issues a token"));
        assert!(!fitted.text.to_ascii_lowercase().contains("this function"));
        assert_eq!(fitted.coverage, Coverage::Targeted);
    }

    #[test]
    fn diff_reports_added_symbol() {
        let left = parse("fn a() {}\n", Some("rust"));
        let right = parse("fn a() {}\nfn b() {}\n", Some("rust"));
        let diff = diff_symbols(&left, &right);
        assert!(diff.added.iter().any(|n| n.contains("b")));
        assert!(diff.unchanged.iter().any(|n| n.contains("a")));
        assert!(diff.removed.is_empty());
    }
}
