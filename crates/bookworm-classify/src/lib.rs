//! Deterministic target classification (directive §6).
//!
//! v1 is parser-free: classification rests on extension mapping, filename
//! conventions, path conventions, shebang sniffing and NUL-byte binary
//! detection. Every decision records its `basis` so a consumer can audit why
//! a class was assigned (BW-I04). Where no deterministic signal exists, the
//! class is `Unknown` rather than guessed (BW-I05).
//!
//! Structural parsing (tree-sitter) is directive-§6's preferred next step and
//! is scheduled on the roadmap; it deliberately does not block this slice
//! because v1 performs no semantic inference at all.

use bookworm_core::{decode_text, Encoding};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    C,
    Cpp,
    Java,
    Json,
    Toml,
    Yaml,
    Xml,
    Html,
    Css,
    Markdown,
    Shell,
    Sql,
    Proto,
    Text,
    Other,
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
            Language::Go => "go",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Java => "java",
            Language::Json => "json",
            Language::Toml => "toml",
            Language::Yaml => "yaml",
            Language::Xml => "xml",
            Language::Html => "html",
            Language::Css => "css",
            Language::Markdown => "markdown",
            Language::Shell => "shell",
            Language::Sql => "sql",
            Language::Proto => "proto",
            Language::Text => "text",
            Language::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    SourceCode,
    StructuredData,
    Configuration,
    Markup,
    NaturalLanguage,
    Log,
    Generated,
    Vendored,
    Binary,
    Mixed,
    Unknown,
}

impl ContentClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentClass::SourceCode => "source_code",
            ContentClass::StructuredData => "structured_data",
            ContentClass::Configuration => "configuration",
            ContentClass::Markup => "markup",
            ContentClass::NaturalLanguage => "natural_language",
            ContentClass::Log => "log",
            ContentClass::Generated => "generated",
            ContentClass::Vendored => "vendored",
            ContentClass::Binary => "binary",
            ContentClass::Mixed => "mixed",
            ContentClass::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    pub class: ContentClass,
    pub language: Option<Language>,
    pub generated: bool,
    pub vendored: bool,
    /// Why this class was assigned: the deterministic signal(s) used.
    pub basis: String,
}

/// Directory components that mark vendored content.
const VENDORED_PARTS: &[&str] = &[
    "node_modules",
    "vendor",
    "third_party",
    "thirdparty",
    "vendored",
    "site-packages",
    ".venv",
    "venv",
];

/// Directory components that mark generated content.
const GENERATED_PARTS: &[&str] = &[
    "target",
    "dist",
    "build",
    "out",
    "__pycache__",
    ".cache",
    ".next",
];

/// Filename suffixes that mark generated files regardless of location.
const GENERATED_SUFFIXES: &[&str] = &[".min.js", ".min.css", ".pb.go", "_pb2.py", ".map", ".lock"];

const GENERATED_FILENAMES: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Cargo.lock",
];

/// Path-level generated/vendored status by directory and filename convention.
pub fn path_flags(path: &Path) -> (bool, bool) {
    let mut generated = false;
    let mut vendored = false;
    for comp in path.components() {
        let Some(name) = comp.as_os_str().to_str() else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        if VENDORED_PARTS.contains(&name.as_str()) {
            vendored = true;
        }
        if GENERATED_PARTS.contains(&name.as_str()) {
            generated = true;
        }
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        if GENERATED_SUFFIXES.iter().any(|s| lower.ends_with(s))
            || GENERATED_FILENAMES.contains(&lower.as_str())
        {
            generated = true;
        }
    }
    (generated, vendored)
}

/// Extension-based language mapping.
pub fn language_for_path(path: &Path) -> Option<Language> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())?;
    let lang = match ext.as_str() {
        "rs" => Language::Rust,
        "py" | "pyi" => Language::Python,
        "js" | "mjs" | "cjs" | "jsx" => Language::JavaScript,
        "ts" | "mts" | "cts" | "tsx" => Language::TypeScript,
        "go" => Language::Go,
        "c" | "h" => Language::C,
        "cpp" | "cc" | "cxx" | "hpp" => Language::Cpp,
        "java" => Language::Java,
        "json" => Language::Json,
        "toml" => Language::Toml,
        "yaml" | "yml" => Language::Yaml,
        "xml" => Language::Xml,
        "html" | "htm" => Language::Html,
        "css" => Language::Css,
        "md" | "markdown" => Language::Markdown,
        "sh" | "bash" | "zsh" => Language::Shell,
        "sql" => Language::Sql,
        "proto" => Language::Proto,
        "txt" => Language::Text,
        _ => return None,
    };
    Some(lang)
}

fn class_for_language(lang: Language) -> ContentClass {
    match lang {
        Language::Rust
        | Language::Python
        | Language::JavaScript
        | Language::TypeScript
        | Language::Go
        | Language::C
        | Language::Cpp
        | Language::Java
        | Language::Shell
        | Language::Sql
        | Language::Proto => ContentClass::SourceCode,
        Language::Json | Language::Toml | Language::Yaml => ContentClass::StructuredData,
        Language::Xml | Language::Html | Language::Css => ContentClass::Markup,
        Language::Markdown | Language::Text => ContentClass::NaturalLanguage,
        Language::Other => ContentClass::Unknown,
    }
}

/// Classify a file target from path, content and sniffed encoding.
pub fn classify(path: &Path, bytes: &[u8], encoding: Encoding) -> Classification {
    let (generated, vendored) = path_flags(path);

    let (class, language, basis) = if encoding == Encoding::Binary {
        (
            ContentClass::Binary,
            None,
            "nul-byte sniff in content window".to_string(),
        )
    } else if let Some(lang) = language_for_path(path) {
        let class = class_for_language(lang);
        let basis = format!(
            "extension mapping -> {} ({})",
            lang.as_str(),
            class.as_str()
        );
        (class, Some(lang), basis)
    } else if let Some(shebang) = shebang_shell(bytes, encoding) {
        let basis = format!("shebang -> {shebang}");
        (ContentClass::SourceCode, Some(Language::Shell), basis)
    } else if is_log_filename(path) {
        (
            ContentClass::Log,
            None,
            "log filename convention".to_string(),
        )
    } else if is_configuration_filename(path) {
        (
            ContentClass::Configuration,
            None,
            "configuration filename convention".to_string(),
        )
    } else if is_manifest_filename(path) {
        (
            ContentClass::StructuredData,
            None,
            "manifest filename convention".to_string(),
        )
    } else if encoding.is_text() {
        // Decodable text with no deterministic language signal: refuse to
        // guess a class (BW-I05).
        (
            ContentClass::Unknown,
            None,
            "decodable text, no deterministic language signal".to_string(),
        )
    } else {
        (
            ContentClass::Unknown,
            None,
            "undecodable content without binary marker".to_string(),
        )
    };

    // Path conventions override the content class, per the directive's class
    // list which treats GENERATED and VENDORED as first-class states.
    let (class, basis) = if vendored {
        (
            ContentClass::Vendored,
            format!("{basis}; path convention -> vendored"),
        )
    } else if generated {
        (
            ContentClass::Generated,
            format!("{basis}; path convention -> generated"),
        )
    } else {
        (class, basis)
    };

    Classification {
        class,
        language,
        generated,
        vendored,
        basis,
    }
}

fn shebang_shell(bytes: &[u8], encoding: Encoding) -> Option<String> {
    let text = decode_text(bytes, encoding)?;
    let first = text.lines().next()?;
    if !first.starts_with("#!") {
        return None;
    }
    let interpreter = first[2..].trim();
    if interpreter.is_empty() {
        return None;
    }
    Some(interpreter.to_string())
}

fn is_log_filename(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("log"))
        .unwrap_or(false)
}

fn is_configuration_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "dockerfile"
            | "makefile"
            | "justfile"
            | ".dockerignore"
            | ".gitignore"
            | ".env"
            | ".editorconfig"
    )
}

fn is_manifest_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(
        name,
        "go.mod" | "go.sum" | "requirements.txt" | "gemfile" | "cmakelists.txt"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> &Path {
        Path::new(s)
    }

    #[test]
    fn source_by_extension() {
        let c = classify(p("src/main.rs"), b"fn main() {}", Encoding::Utf8);
        assert_eq!(c.class, ContentClass::SourceCode);
        assert_eq!(c.language, Some(Language::Rust));
        assert!(!c.generated && !c.vendored);
    }

    #[test]
    fn structured_data_and_markup() {
        assert_eq!(
            classify(p("a.json"), b"{}", Encoding::Utf8).class,
            ContentClass::StructuredData
        );
        assert_eq!(
            classify(p("a.toml"), b"[x]", Encoding::Utf8).class,
            ContentClass::StructuredData
        );
        assert_eq!(
            classify(p("a.md"), b"# hi", Encoding::Utf8).class,
            ContentClass::NaturalLanguage
        );
        assert_eq!(
            classify(p("a.html"), b"<p>", Encoding::Utf8).class,
            ContentClass::Markup
        );
    }

    #[test]
    fn vendored_and_generated_override() {
        let c = classify(p("vendor/lib.c"), b"int x;", Encoding::Utf8);
        assert_eq!(c.class, ContentClass::Vendored);
        assert_eq!(c.language, Some(Language::C));
        assert!(c.vendored);

        let c = classify(p("target/gen.rs"), b"fn f() {}", Encoding::Utf8);
        assert_eq!(c.class, ContentClass::Generated);
        assert!(c.generated);

        let c = classify(p("app.min.js"), b"()", Encoding::Utf8);
        assert_eq!(c.class, ContentClass::Generated);
    }

    #[test]
    fn binary_by_nul_sniff() {
        let c = classify(p("data.bin"), &[0, 1, 2, 3], Encoding::Binary);
        assert_eq!(c.class, ContentClass::Binary);
        assert_eq!(c.language, None);
    }

    #[test]
    fn shebang_without_extension() {
        let c = classify(p("run"), b"#!/bin/bash\necho hi\n", Encoding::Utf8);
        assert_eq!(c.class, ContentClass::SourceCode);
        assert_eq!(c.language, Some(Language::Shell));
        assert!(c.basis.contains("shebang"));
    }

    #[test]
    fn unknown_when_no_signal() {
        let c = classify(p("NOTES"), b"just words\n", Encoding::Utf8);
        assert_eq!(c.class, ContentClass::Unknown);
        assert_eq!(c.language, None);
    }

    #[test]
    fn log_and_config_conventions() {
        assert_eq!(
            classify(p("app.log"), b"x", Encoding::Utf8).class,
            ContentClass::Log
        );
        assert_eq!(
            classify(p("Dockerfile"), b"FROM x", Encoding::Utf8).class,
            ContentClass::Configuration
        );
    }

    #[test]
    fn lockfiles_are_generated() {
        assert_eq!(path_flags(p("Cargo.lock")), (true, false));
        assert_eq!(path_flags(p("crates/x/Cargo.toml")), (false, false));
    }
}
