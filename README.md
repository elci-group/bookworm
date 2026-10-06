# Bookworm

Bookworm is the deterministic evidence-acquisition layer for ELCI. It resolves a target, measures it, classifies it, plans a budget, reads or searches it, verifies the measurement, and returns a `BOOKWORM/1` evidence envelope.

This tree is version 0.1.0. The specification in [docs/DIRECTIVE.md](docs/DIRECTIVE.md) stays the spec. What this process actually does is recorded in [docs/STATUS.md](docs/STATUS.md).

## What a response is

A response is an evidence envelope: target identity, measurement, strategy, verification, claims, coverage, and the quoted content that was actually read. Equal requests over equal bytes produce equal request ids and equal result hashes. The hash excludes the wall-clock timestamp, the cache-hit flag, and the local PISA lookup status.

Bookworm does not call a model. It does not paraphrase. `explain`, `summarise`, and `extract` quote source. A question is stored on the request and reported as unanswered.

## What this process refuses

- Model calls, provider clients, and network reads. A URL target is denied. `--allow-remote` fences and redacts a package and still does not transmit it.
- Exact token counts for GPT, Claude, Gemini, or any other third-party vocabulary. `estimated_tokens` is `approximate_chars_per_token`. `exact_tokens` is `bookworm-ws-v1` and is exact only for that tokenizer.
- Consensus modes that need another reader (`dual`, `majority`, `heterogeneous`, `adversarial`). They return an error. `none` and `verify_on_disagreement` run. The default is `verify_on_disagreement`, which checks one deterministic reader and does not invent a second vote.
- Fixed-token chunking. If a lossless read does not fit, Bookworm quotes whole symbols that fit and labels the coverage `partial` or `unknown`. A symbol larger than the budget is skipped, not sliced.
- Economic-improvement and quality-preservation numbers. There is no inference path and no task suite that could measure them.

## Pipeline

`REQUEST → RESOLVE → MEASURE → CLASSIFY → BUDGET → PLAN → ROUTE → READ → VERIFY → PACKAGE → ATTEST`

Rust symbols come from tree-sitter. Markdown uses heading lines. Other languages get a lexical outline that is labelled as lexical. A failed parse is reported.

## CLI

```text
bookworm read|explain|summarise|extract|compare|trace|impact|locate|map
bookworm measure|estimate|route|verify
bookworm evidence|claims|cache|eval|doctor|serve
```

Global flags include `--json`, `--model`, `--budget` (alias of `--max-tokens`), `--consensus`, `--verify`, `--revision` on the commands that pin a revision, `--local-only`, `--allow-remote`, `--provider`, `--no-cache`, `--cache-dir`, and `--root`. `--provider` accepts `local` and `none`.

`read -` reads stdin. `read --lines START:END` is a separate request identity. `locate --glob` filters findings after a whole-scope scan.

`bookworm eval [fixture]` runs the built-in checks. The default fixture is `fixtures/sample-src`.

## Local API

`bookworm serve` binds loopback only (default `127.0.0.1:8741`). An optional `--token` requires `Authorization: Bearer`.

```text
POST /v1/read|locate|explain|map|verify|estimate
GET  /v1/jobs/{id}|/v1/evidence/{id}|/v1/claims/{id}|/v1/health|/v1/metrics
```

Responses are one JSON document. `GET /v1/health` reports `"stream": false`. There is no investigation stream.

## Cache and PISA

The evidence cache is a directory of JSON envelopes, locked with an advisory file lock. A hit is valid only when the source hash and revision still match.

The PISA store is a local JSON directory under the cache (`pisa/`). It is not a network PISA client. A record is fresh only while the source hashes match. A fresh record does not skip rebuilding when the request was not already a cache hit. The lookup status is stored on the envelope and is not part of the result hash.

## Build and test

```text
cargo test --workspace --offline
```

Rust edition 2021, `rust-version` 1.82. The crates are `publish = false`.

## Gates this tree can prove

| Gate | Meaning in this tree |
| --- | --- |
| G01 | Same bytes and same request produce the same result hash. |
| G02 | A pinned revision that does not match fails the envelope. |
| G03 | Read claims carry spans bound to the file SHA-256. Symbol spans also carry a range hash. |
| G04 | A budget that cannot hold the text does not return a lossless read. |
| G05 | Coverage names what was actually covered. A miss is not reported as a hit. |
| G06 | Symbols, imports, and config keys are checked with tree-sitter, manifests, or a labelled lexical scan. |
| G07 | Content is fenced and secret-shaped text is redacted only for a transport package. Instruction-shaped text is recorded and not obeyed. Scope roots are enforced. |
| G08 | A changed file hash invalidates the cache entry. |
| G09, G10 | Not measured. No model is called. |
