//! Deterministic measurement (directive §7): bytes, lines, content hashes
//! and explicitly-labelled approximate token estimates.
//!
//! Approximate character-based estimation is permitted for preflight
//! screening but MUST NOT be represented as exact (§7). Accordingly,
//! `estimated_tokens` is always the character approximation and is labelled
//! as such. `exact_tokens` is the `bookworm-ws-v1` count when the bytes are
//! text. That count is exact for Bookworm's tokenizer and is not a
//! third-party model count.

use bookworm_classify::Language;
use bookworm_core::{decode_text, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Approximate characters-per-token calibration by language family. These are
/// screening constants, not model truth. Structural budgets use
/// `bookworm-ws-v1`. These figures stay the preflight estimate.
fn chars_per_token(language: Option<Language>) -> f64 {
    match language {
        Some(Language::Json) | Some(Language::Toml) | Some(Language::Yaml) => 3.2,
        Some(Language::Markdown) | Some(Language::Text) | None => 4.0,
        Some(Language::Other) => 4.0,
        _ => 3.6,
    }
}

pub const APPROX_METHOD: &str = "approximate_chars_per_token";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Measurement {
    pub bytes: u64,
    /// Line count: `str::lines` semantics for text (a trailing terminator
    /// does not open a new line; empty input is 0 lines), raw `0x0A` count
    /// for binary content.
    pub lines: u64,
    pub sha256: String,
    pub encoding: Encoding,
    pub estimated_tokens: Option<u64>,
    pub estimation_method: Option<String>,
    /// Exact token count for [`bookworm_tokenize::METHOD`].
    pub exact_tokens: Option<u64>,
    /// Tokenizer that produced `exact_tokens`. Never a third-party model name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_method: Option<String>,
}

/// Measure already-read bytes. `language` only tunes the token approximation.
pub fn measure_bytes(bytes: &[u8], encoding: Encoding, language: Option<Language>) -> Measurement {
    let digest = hex::encode(Sha256::digest(bytes));
    let decoded = decode_text(bytes, encoding);
    let (lines, chars, exact) = match &decoded {
        Some(text) => (
            text.lines().count() as u64,
            text.chars().count() as u64,
            Some(bookworm_tokenize::count(text)),
        ),
        None => (
            bytes.iter().filter(|b| **b == b'\n').count() as u64,
            0,
            None,
        ),
    };
    let estimated = (chars > 0).then(|| (chars as f64 / chars_per_token(language)).ceil() as u64);
    Measurement {
        bytes: bytes.len() as u64,
        lines,
        sha256: digest,
        encoding,
        estimated_tokens: estimated,
        estimation_method: estimated.map(|_| APPROX_METHOD.to_string()),
        exact_tokens: exact,
        exact_method: exact.map(|_| bookworm_tokenize::METHOD.to_string()),
    }
}

/// Read and measure a file in one step. The sniff runs over the full content,
/// not just the head window, so the recorded encoding is exact for the bytes
/// actually read.
pub fn measure_file(path: &std::path::Path) -> std::io::Result<(Vec<u8>, Measurement)> {
    let bytes = std::fs::read(path)?;
    let encoding = bookworm_core::sniff_encoding(&bytes);
    let language = bookworm_classify::language_for_path(path);
    let measurement = measure_bytes(&bytes, encoding, language);
    Ok((bytes, measurement))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_known_content() {
        // SHA-256 of "hello\n"
        let m = measure_bytes(b"hello\n", Encoding::Utf8, Some(Language::Rust));
        assert_eq!(
            m.sha256,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
        assert_eq!(m.bytes, 6);
        assert_eq!(m.lines, 1);
    }

    #[test]
    fn line_semantics_documented() {
        assert_eq!(measure_bytes(b"", Encoding::Utf8, None).lines, 0);
        assert_eq!(measure_bytes(b"one\n", Encoding::Utf8, None).lines, 1);
        assert_eq!(measure_bytes(b"one\n\n", Encoding::Utf8, None).lines, 2);
        assert_eq!(measure_bytes(b"a\r\nb", Encoding::Utf8, None).lines, 2); // \r\n is one terminator
    }

    #[test]
    fn token_estimate_labelled_approximate_and_never_exact() {
        let m = measure_bytes(
            b"fn main() { println!(\"x\"); }",
            Encoding::Utf8,
            Some(Language::Rust),
        );
        assert!(m.estimated_tokens.unwrap() > 0);
        assert_eq!(m.estimation_method.as_deref(), Some(APPROX_METHOD));
        assert!(m.exact_tokens.unwrap() > 0);
        assert_eq!(m.exact_method.as_deref(), Some(bookworm_tokenize::METHOD));
        assert_ne!(m.estimation_method, m.exact_method);
    }

    #[test]
    fn binary_has_no_token_estimate() {
        let m = measure_bytes(&[0, 1, 2, 0, 3], Encoding::Binary, None);
        assert!(m.estimated_tokens.is_none());
        assert!(m.exact_tokens.is_none());
        assert_eq!(m.lines, 0);
    }

    #[test]
    fn deterministic_repeat() {
        let content = b"line1\nline2\nline3\n".repeat(100);
        let a = measure_bytes(&content, Encoding::Utf8, Some(Language::Text));
        let b = measure_bytes(&content, Encoding::Utf8, Some(Language::Text));
        assert_eq!(a, b);
    }
}
