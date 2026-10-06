# Bookworm status

Specification: [DIRECTIVE.md](DIRECTIVE.md), status **Proposed**. This file records the implemented process. It does not change the spec.

Version: 0.1.0. Envelope: `BOOKWORM/1`.

## Implemented

- Typed requests: read, locate, explain, summarise, extract, compare, trace, verify, impact, map.
- Targets: file, directory, repository identity on resolved files, symbol, line range, glob filter on locate, and stdin (`read -`, materialized to a temporary file so the cache key cannot collide across different inputs). URL targets are denied. Dependency and configuration targets are verification checks (`--dep`, `--config-key`). Revision pins use the freshness policy.
- Fidelity values are accepted. `raw` and `lossless` can be satisfied by a direct read. `selective`, `structural`, `extractive`, and `semantic` receive deterministic evidence and an explicit statement that Bookworm does not paraphrase.
- Measurement: bytes, lines, SHA-256, encoding sniff, `approximate_chars_per_token`, and `bookworm-ws-v1` exact counts for text. Binary input has no token count.
- Nominal model table for budget math only: `openai-gpt-4o`, `anthropic-claude-sonnet`, `google-gemini-flash`, `groq-llama-70b`, `local-ollama-7b`. `B_net = C − S − R − O − E`.
- Tiers 0–2 execute. Tier 3 is recommended in the plan notes and is not silently chunked. Tiers 4 and 5 are named and not executed.
- Rust structure via tree-sitter (`tree_sitter_rust`). Markdown headings. Other languages: lexical outline labelled incomplete relative to a grammar.
- Verification: path, text, regex, line range, symbol, Rust import, TOML/JSON config key, Cargo dependency, revision, hash.
- Security: transport fence, secret redaction (`pem_private_key`, `aws_access_key`, assigned secrets of length at least 8), injection observations that do not strip or obey the text.
- Consensus: `none` and `verify_on_disagreement` only. One reader. Machine methods adjudicate if a second claim set is supplied to the library. The CLI does not invent that second set.
- Evidence cache with advisory locking. Local PISA JSON store keyed by intent, fidelity, budget, and target.
- Loopback HTTP API. Synchronous JSON. Metrics are process-local counters.
- `bookworm eval` and the `bookworm-eval` crate run one shared check list: measurement determinism, envelope determinism, negative-query coverage, provenance, cache invalidation, structural symbol, injection-as-content, scope, and budget fail-closed.

## Not implemented, on purpose

- Inference, summarisation in generated prose, and provider SDKs.
- Third-party tokenizer counts.
- Multi-model consensus votes.
- Network PISA, Lucid, Rung, and Cortex clients.
- Streaming investigations.
- G09 economic improvement and G10 quality preservation. Those gates need a model and a task suite this process does not have.
- Per-finding file hashes on `locate` spans. The locate claim records the scan. Trace and impact spans do carry the measured file hash.

## Tests

`cargo test --workspace --offline` is the check for this tree. A full run covers the crates above, including a structural read of a file that does not fit the default model budget.

## Operations note

Do not treat a cache hit or a PISA `fresh` lookup as proof by itself. Validity is the live source hash and revision. PISA status is excluded from `result_hash` so a lookup cannot change evidence identity.
