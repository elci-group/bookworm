//! Structural extraction (directive §6).
//!
//! Rust is parsed with tree-sitter, so symbol spans are grammar spans rather
//! than a brace scan. Markdown uses heading lines. Every other language gets
//! a lexical outline that is labelled as lexical. A failed parse is reported;
//! it is not replaced with a guess.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Struct,
    Enum,
    Trait,
    Impl,
    Module,
    Const,
    Static,
    Type,
    Heading,
    Outline,
}

impl SymbolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SymbolKind::Function => "function",
            SymbolKind::Struct => "struct",
            SymbolKind::Enum => "enum",
            SymbolKind::Trait => "trait",
            SymbolKind::Impl => "impl",
            SymbolKind::Module => "module",
            SymbolKind::Const => "const",
            SymbolKind::Static => "static",
            SymbolKind::Type => "type",
            SymbolKind::Heading => "heading",
            SymbolKind::Outline => "outline",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub start_line: u64,
    pub end_line: u64,
    pub signature: String,
    /// SHA-256 of the source bytes covering the symbol.
    pub range_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    pub text: String,
    pub line: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub line: u64,
    pub kind: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStructure {
    pub language: String,
    pub method: String,
    pub complete: bool,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub notes: Vec<String>,
}

/// Parse `source` for `language` (`rust`, `markdown`, or anything else).
pub fn parse(source: &str, language: Option<&str>) -> FileStructure {
    match language {
        Some("rust") => parse_rust(source),
        Some("markdown") => parse_markdown(source),
        Some(other) => parse_lexical(source, other),
        None => parse_lexical(source, "unknown"),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Lines `start..=end` (1-based, inclusive). Empty when the range is outside
/// the file.
pub fn line_slice(source: &str, start: u64, end: u64) -> Option<String> {
    if start == 0 || end < start {
        return None;
    }
    let lines: Vec<&str> = source.lines().collect();
    let last = lines.len() as u64;
    if start > last || end > last {
        return None;
    }
    Some(lines[(start as usize - 1)..(end as usize)].join("\n"))
}

/// Identifier and call sites whose text equals `symbol`.
pub fn references(source: &str, language: Option<&str>, symbol: &str) -> Vec<Reference> {
    if language == Some("rust") {
        if let Some(tree_refs) = rust_references(source, symbol) {
            return tree_refs;
        }
    }
    lexical_references(source, symbol)
}

fn rust_language() -> &'static Language {
    static LANG: OnceLock<Language> = OnceLock::new();
    LANG.get_or_init(|| tree_sitter_rust::LANGUAGE.into())
}

fn parse_rust(source: &str) -> FileStructure {
    let mut parser = Parser::new();
    if parser.set_language(rust_language()).is_err() {
        let mut lexical = parse_lexical(source, "rust");
        lexical.notes.push(
            "tree-sitter rust grammar failed to load; lexical outline used instead".to_string(),
        );
        return lexical;
    }
    let Some(tree) = parser.parse(source, None) else {
        let mut lexical = parse_lexical(source, "rust");
        lexical
            .notes
            .push("tree-sitter returned no tree; lexical outline used instead".to_string());
        return lexical;
    };
    let mut out = FileStructure {
        language: "rust".to_string(),
        method: "tree_sitter_rust".to_string(),
        complete: !tree.root_node().has_error(),
        symbols: Vec::new(),
        imports: Vec::new(),
        notes: Vec::new(),
    };
    if !out.complete {
        out.notes
            .push("parse tree contains errors; symbol list may be incomplete".to_string());
    }
    collect_rust(tree.root_node(), source, &mut out);
    out.symbols.sort_by_key(|s| (s.start_line, s.end_line, s.name.clone()));
    out
}

fn collect_rust(node: Node, source: &str, out: &mut FileStructure) {
    match node.kind() {
        "function_item" => push_named(node, source, SymbolKind::Function, out),
        "struct_item" => push_named(node, source, SymbolKind::Struct, out),
        "enum_item" => push_named(node, source, SymbolKind::Enum, out),
        "trait_item" => push_named(node, source, SymbolKind::Trait, out),
        "mod_item" => push_named(node, source, SymbolKind::Module, out),
        "const_item" => push_named(node, source, SymbolKind::Const, out),
        "static_item" => push_named(node, source, SymbolKind::Static, out),
        "type_item" => push_named(node, source, SymbolKind::Type, out),
        "impl_item" => push_impl(node, source, out),
        "use_declaration" => push_use(node, source, out),
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust(child, source, out);
    }
}

fn push_named(node: Node, source: &str, kind: SymbolKind, out: &mut FileStructure) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).to_string();
    if name.is_empty() {
        return;
    }
    out.symbols.push(symbol_from_node(node, source, kind, name));
}

fn push_impl(node: Node, source: &str, out: &mut FileStructure) {
    let name = node
        .child_by_field_name("type")
        .map(|n| node_text(n, source).to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "impl".to_string());
    out.symbols
        .push(symbol_from_node(node, source, SymbolKind::Impl, name));
}

fn push_use(node: Node, source: &str, out: &mut FileStructure) {
    let text = node_text(node, source);
    let line = node.start_position().row as u64 + 1;
    let one_line = text.lines().next().unwrap_or(text).trim().to_string();
    out.imports.push(Import {
        text: one_line,
        line,
    });
}

fn symbol_from_node(node: Node, source: &str, kind: SymbolKind, name: String) -> Symbol {
    let start_line = node.start_position().row as u64 + 1;
    let end_line = node.end_position().row as u64 + 1;
    let bytes = &source.as_bytes()[node.start_byte()..node.end_byte()];
    let signature = node_text(node, source)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(200)
        .collect();
    Symbol {
        name,
        kind,
        start_line,
        end_line,
        signature,
        range_hash: sha256_hex(bytes),
    }
}

fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    let start = node.start_byte().min(source.len());
    let end = node.end_byte().min(source.len());
    if !source.is_char_boundary(start) || !source.is_char_boundary(end) || end < start {
        return "";
    }
    &source[start..end]
}

fn rust_references(source: &str, symbol: &str) -> Option<Vec<Reference>> {
    let mut parser = Parser::new();
    parser.set_language(rust_language()).ok()?;
    let tree = parser.parse(source, None)?;
    let mut refs = Vec::new();
    walk_refs(tree.root_node(), source, symbol, &mut refs);
    refs.sort_by_key(|r| (r.line, r.kind.clone()));
    refs.dedup_by(|a, b| a.line == b.line && a.kind == b.kind && a.excerpt == b.excerpt);
    Some(refs)
}

fn walk_refs(node: Node, source: &str, symbol: &str, out: &mut Vec<Reference>) {
    if node.kind() == "call_expression" {
        if let Some(function) = node.child_by_field_name("function") {
            let name = call_name(function, source);
            if name == symbol {
                out.push(Reference {
                    line: node.start_position().row as u64 + 1,
                    kind: "call".to_string(),
                    excerpt: first_line(node_text(node, source)),
                });
            }
        }
    }
    if matches!(node.kind(), "identifier" | "type_identifier" | "field_identifier")
        && node_text(node, source) == symbol
    {
        out.push(Reference {
            line: node.start_position().row as u64 + 1,
            kind: "identifier".to_string(),
            excerpt: excerpt_line(source, node.start_position().row as u64 + 1),
        });
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_refs(child, source, symbol, out);
    }
}

fn call_name(node: Node, source: &str) -> String {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => node_text(node, source).to_string(),
        "field_expression" => node
            .child_by_field_name("field")
            .map(|n| node_text(n, source).to_string())
            .unwrap_or_default(),
        "scoped_identifier" => node
            .child_by_field_name("name")
            .map(|n| node_text(n, source).to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn parse_markdown(source: &str) -> FileStructure {
    let mut symbols = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('#') {
            let hashes = trimmed.chars().take_while(|c| *c == '#').count();
            if hashes > 0 && hashes <= 6 && rest.starts_with(|c: char| c == '#' || c == ' ') {
                let name = trimmed.trim_start_matches('#').trim().to_string();
                if name.is_empty() {
                    continue;
                }
                let line_no = idx as u64 + 1;
                symbols.push(Symbol {
                    name,
                    kind: SymbolKind::Heading,
                    start_line: line_no,
                    end_line: line_no,
                    signature: trimmed.chars().take(200).collect(),
                    range_hash: sha256_hex(line.as_bytes()),
                });
            }
        }
    }
    FileStructure {
        language: "markdown".to_string(),
        method: "markdown_headings".to_string(),
        complete: true,
        symbols,
        imports: Vec::new(),
        notes: Vec::new(),
    }
}

fn parse_lexical(source: &str, language: &str) -> FileStructure {
    let mut symbols = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(name) = lexical_name(trimmed) {
            let line_no = idx as u64 + 1;
            symbols.push(Symbol {
                name,
                kind: SymbolKind::Outline,
                start_line: line_no,
                end_line: line_no,
                signature: trimmed.chars().take(200).collect(),
                range_hash: sha256_hex(line.as_bytes()),
            });
        }
    }
    FileStructure {
        language: language.to_string(),
        method: "lexical_outline".to_string(),
        complete: false,
        symbols,
        imports: Vec::new(),
        notes: vec![
            "lexical outline only; this is not an AST and may miss or mis-label declarations"
                .to_string(),
        ],
    }
}

fn lexical_name(line: &str) -> Option<String> {
    const PREFIXES: &[&str] = &[
        "pub fn ", "fn ", "pub struct ", "struct ", "pub enum ", "enum ", "class ", "def ",
        "func ", "function ",
    ];
    for prefix in PREFIXES {
        if let Some(rest) = line.strip_prefix(prefix) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn lexical_references(source: &str, symbol: &str) -> Vec<Reference> {
    let mut refs = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        if word_appears(line, symbol) {
            refs.push(Reference {
                line: idx as u64 + 1,
                kind: "lexical".to_string(),
                excerpt: first_line(line.trim()),
            });
        }
    }
    refs
}

fn word_appears(line: &str, symbol: &str) -> bool {
    let mut search = 0usize;
    while let Some(rel) = line[search..].find(symbol) {
        let start = search + rel;
        let end = start + symbol.len();
        let before = line[..start]
            .chars()
            .next_back()
            .map(|c| !c.is_alphanumeric() && c != '_')
            .unwrap_or(true);
        let after = line[end..]
            .chars()
            .next()
            .map(|c| !c.is_alphanumeric() && c != '_')
            .unwrap_or(true);
        if before && after {
            return true;
        }
        search = end;
    }
    false
}

fn first_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(160)
        .collect()
}

fn excerpt_line(source: &str, line: u64) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .map(|l| first_line(l.trim()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUST: &str = "\
use std::fmt;\n\
pub fn issue(user: &str) -> String {\n\
    format!(\"token-for-{user}\")\n\
}\n\
pub struct Token;\n\
impl Token {\n\
    pub fn refresh(&self) {}\n\
}\n";

    #[test]
    fn rust_symbols_come_from_the_grammar() {
        let parsed = parse(RUST, Some("rust"));
        assert_eq!(parsed.method, "tree_sitter_rust");
        assert!(parsed.complete);
        let names: Vec<_> = parsed.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"issue"));
        assert!(names.contains(&"Token"));
        assert!(names.contains(&"refresh"));
        let issue = parsed.symbols.iter().find(|s| s.name == "issue").unwrap();
        assert_eq!(issue.kind, SymbolKind::Function);
        assert_eq!(issue.start_line, 2);
        assert!(!issue.range_hash.is_empty());
        assert!(parsed.imports.iter().any(|i| i.text.contains("std::fmt")));
    }

    #[test]
    fn markdown_headings() {
        let parsed = parse("# Title\n\nbody\n## Next\n", Some("markdown"));
        assert_eq!(parsed.symbols.len(), 2);
        assert_eq!(parsed.symbols[0].name, "Title");
        assert!(parsed.complete);
    }

    #[test]
    fn broken_rust_is_not_marked_complete() {
        let parsed = parse("pub fn {\n", Some("rust"));
        assert!(!parsed.complete || parsed.symbols.is_empty());
        if parsed.method == "tree_sitter_rust" {
            assert!(!parsed.complete);
        }
    }

    #[test]
    fn references_include_calls() {
        let src = "fn issue() {}\nfn main() { issue(); }\n";
        let refs = references(src, Some("rust"), "issue");
        assert!(refs.iter().any(|r| r.kind == "call" && r.line == 2));
    }
}
