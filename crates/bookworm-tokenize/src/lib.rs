//! Bookworm's own tokenizer, `bookworm-ws-v1`.
//!
//! Directive §7 requires the actual tokenizer when one is available, and
//! forbids presenting a character estimate as an exact model count. This
//! crate is that tokenizer. Its counts are exact for `bookworm-ws-v1` and
//! are not counts for any third-party model vocabulary.

/// Method label stored beside every count this crate produces.
pub const METHOD: &str = "bookworm-ws-v1";

/// Count tokens in `text`.
///
/// A token is a maximal run of Unicode alphanumeric characters or `_`, or a
/// single non-whitespace character outside such a run. Unicode whitespace is
/// a separator and is not a token. The count is deterministic and exact for
/// this definition.
pub fn count(text: &str) -> u64 {
    let mut total = 0u64;
    let mut in_word = false;
    for c in text.chars() {
        if c.is_whitespace() {
            in_word = false;
            continue;
        }
        if c.is_alphanumeric() || c == '_' {
            if !in_word {
                total += 1;
                in_word = true;
            }
        } else {
            total += 1;
            in_word = false;
        }
    }
    total
}

/// Count tokens in each chunk and sum them. Used when a package is built
/// from several slices that are not yet joined.
pub fn count_pieces<'a>(pieces: impl IntoIterator<Item = &'a str>) -> u64 {
    pieces.into_iter().map(count).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_words_and_punctuation() {
        // fn, main, (, ), {, }
        assert_eq!(count("fn main() {}"), 6);
        assert_eq!(count(""), 0);
        assert_eq!(count("   \n\t"), 0);
        assert_eq!(count("foo_bar"), 1);
        assert_eq!(count("a-b"), 3);
    }

    #[test]
    fn is_stable() {
        let text = "pub fn issue(user: &str) -> String {\n    format!(\"token-for-{user}\")\n}\n";
        assert_eq!(count(text), count(text));
        assert!(count(text) > 0);
    }
}
