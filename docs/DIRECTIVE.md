# ELCI TECHNICAL DIRECTIVE
## BOOKWORM — Deterministic Evidence Acquisition, Reading and Context Resolution Infrastructure

**Directive class:** Core Infrastructure  
**Implementation language:** Rust  
**Status:** Proposed  
**Primary consumers:** Lucid, DreamSequence, `:e`, Daydream, VICO-compatible agents  
**Related systems:** PISA, Rung, Cortex, DreamSequence Preflight, Lucid routing, inference accounting  
**Primary objective:** Minimise the inference cost of acquiring trustworthy context without degrading downstream reasoning quality.

---

# 1. MISSION

Bookworm SHALL provide a deterministic, bounded and auditable context-acquisition layer between agents and information-bearing targets.

Bookworm exists because locating, opening, classifying, reading, partitioning and repeatedly rediscovering source material SHOULD NOT consume the reasoning budget of expensive orchestrator models where those operations can be delegated to cheaper specialised inference and deterministic computation.

The architectural contract is:

> **Bookworm acquires evidence. Orchestrators reason from evidence. Deterministic systems verify what can be verified.**

An orchestrating model SHALL be permitted to request information without independently performing the complete retrieval and reading process.

Example:

```text
READ ~/.bashrc
```

Bookworm SHALL resolve this into an evidence-acquisition operation:

```text
REQUEST
   ↓
RESOLVE
   ↓
MEASURE
   ↓
CLASSIFY
   ↓
BUDGET
   ↓
PLAN
   ↓
ROUTE
   ↓
READ
   ↓
VERIFY
   ↓
PACKAGE
   ↓
ATTEST
```

The result SHALL be sufficiently trustworthy that the caller can ordinarily proceed under:

> **Bookworm has read the target; do not reread it unless its evidence is insufficient, stale, disputed or the task explicitly requires raw source.**

---

# 2. NON-GOALS

Bookworm SHALL NOT become:

- a general-purpose autonomous coding agent;
- a replacement for Lucid;
- a code-generation system;
- an unrestricted semantic RAG service;
- an opaque summarisation layer;
- a second orchestration framework;
- an authority capable of silently inventing repository facts;
- a mechanism for hiding insufficient evidence behind confidence scores.

Bookworm's job ends at **context acquisition, factual extraction, evidence organisation and verification**.

Interpretive decisions remain with the consuming agent unless explicitly delegated.

---

# 3. PRIMARY INVARIANTS

Bookworm SHALL enforce the following invariants.

### BW-I01 — Determinism Before Inference

Anything reliably obtainable without inference MUST be obtained without inference.

Examples include:

- file existence;
- canonical path;
- size;
- encoding;
- MIME type;
- extension;
- repository revision;
- Git status;
- line count;
- byte count;
- hash;
- AST structure;
- symbol tables;
- imports;
- references where statically resolvable;
- dependency metadata;
- tokenizer estimates;
- modification metadata.

Inference SHALL NOT be purchased to rediscover deterministic facts.

### BW-I02 — Lossless Before Lossy

If requested evidence fits within the permitted context budget, Bookworm SHOULD provide the relevant source losslessly.

Summarisation SHALL NOT occur merely because summarisation is cheaper.

Preferred order:

```text
lossless read
    >
lossless selective extraction
    >
structural extraction
    >
extractive compression
    >
semantic summarisation
```

### BW-I03 — Cheapest Sufficient Cognition

Bookworm SHALL select the least expensive execution strategy expected to satisfy the declared quality floor.

It SHALL NOT interpret this as:

> cheapest model available.

It SHALL interpret it as:

> lowest expected total cost of producing an acceptable verified result.

### BW-I04 — Provenance Preservation

Every non-trivial semantic claim SHALL be traceable to its evidence.

### BW-I05 — Explicit Uncertainty

Bookworm MUST distinguish:

```text
known
inferred
ambiguous
conflicting
unverified
unknown
```

Absence of evidence MUST NOT silently become evidence of absence.

### BW-I06 — Immutable Evidence Identity

Evidence SHALL be bound to the state from which it was acquired.

For repositories this SHOULD include:

```text
repository
revision
path
content hash
range
```

A claim derived from revision `A` SHALL NOT silently masquerade as knowledge about revision `B`.

### BW-I07 — No Redundant Discovery

If Bookworm or PISA possesses a valid, sufficiently precise answer against unchanged evidence, inference SHOULD NOT be spent rediscovering it.

---

# 4. REQUEST MODEL

Bookworm SHALL expose a typed request schema.

Conceptually:

```rust
pub struct ContextRequest {
    pub intent: ReadIntent,
    pub targets: Vec<Target>,
    pub question: Option<String>,
    pub fidelity: Fidelity,
    pub budget: Budget,
    pub verification: VerificationPolicy,
    pub privacy: PrivacyPolicy,
    pub freshness: FreshnessPolicy,
}
```

`ReadIntent` SHOULD initially include:

```rust
pub enum ReadIntent {
    Read,
    Locate,
    Explain,
    Summarise,
    Extract,
    Compare,
    Trace,
    Verify,
    Impact,
    Map,
}
```

Targets SHOULD support at minimum:

```text
file
directory
repository
revision
symbol
line range
glob
dependency
configuration
documentation corpus
stdin/blob
URL/resource where policy permits
```

Bookworm MUST reject ambiguous destructive interpretations. Bookworm itself SHOULD be read-only by default.

---

# 5. TARGET RESOLUTION

Before invoking inference, Bookworm SHALL establish exactly what exists.

For filesystem targets it SHOULD resolve:

```text
requested path
canonical path
symlink chain
target type
permissions
repository membership
repository root
Git revision
working-tree state
size
encoding
language candidate
generated status
vendor status
binary status
```

For directories/repositories it SHOULD additionally construct a structural inventory.

The inventory SHOULD preferentially identify:

- source roots;
- manifests;
- workspaces;
- modules;
- tests;
- fixtures;
- generated code;
- vendored dependencies;
- documentation;
- build scripts;
- CI definitions;
- configuration;
- entry points.

This stage SHALL remain inference-free wherever practical.

---

# 6. TARGET CLASSIFICATION

Bookworm SHALL classify content before deciding how to read it.

Initial classes:

```text
SOURCE_CODE
STRUCTURED_DATA
CONFIGURATION
MARKUP
NATURAL_LANGUAGE
LOG
GENERATED
VENDORED
BINARY
MIXED
UNKNOWN
```

Source code SHALL additionally receive a language classification.

Where parsers exist, structural parsing SHOULD precede semantic inference.

For example:

```text
Rust
 ↓
Cargo metadata
 ↓
Tree-sitter / rust-analyzer-compatible structural data
 ↓
symbols/imports/modules
 ↓
semantic reader only where necessary
```

The system SHOULD know the shape of evidence before purchasing cognition about its meaning.

---

# 7. TOKEN ACCOUNTING

Bookworm SHALL maintain explicit context accounting.

For candidate model \(m\):

\[
B_{net}(m)
=
C_m
-
S_m
-
R
-
O
-
E
\]

where:

- \(C_m\) = model context capacity;
- \(S_m\) = Bookworm/system instructions;
- \(R\) = request tokens;
- \(O\) = reserved output capacity;
- \(E\) = required contextual envelope.

The target cost SHALL be estimated using the actual tokenizer where available.

Approximate character-based estimation MAY be used for preflight screening but MUST NOT be represented as exact.

Bookworm SHOULD expose:

```text
raw_bytes
raw_lines
estimated_tokens
exact_tokens
net_context_available
expected_output_tokens
expected_cost
```

where available.

---

# 8. INGESTION STRATEGY

Bookworm SHALL choose an ingestion strategy according to target size, structure and requested fidelity.

### Tier 0 — Direct deterministic answer

No model call.

Example:

```text
"Does Cargo.toml contain dependency X?"
```

If deterministic parsing answers the question, stop.

### Tier 1 — Lossless direct read

Entire relevant evidence fits into the selected reader's context.

```text
TARGET → READER → RESULT
```

### Tier 2 — Selective structural read

Deterministic machinery identifies relevant symbols/files/ranges.

```text
TARGET
  ↓
STRUCTURAL FILTER
  ↓
RELEVANT SOURCE
  ↓
READER
```

### Tier 3 — Partitioned read

Target exceeds practical single-call capacity.

Partition by natural boundaries:

```text
workspace
crate
package
module
file
class
function
section
```

Arbitrary fixed-token chunking SHOULD be a fallback rather than the preferred partitioning strategy.

### Tier 4 — Hierarchical synthesis

For very large targets:

```text
inventory
    ↓
local readers
    ↓
structured findings
    ↓
cross-partition reconciliation
    ↓
evidence package
```

### Tier 5 — Directed deep investigation

Where the request concerns a narrow behaviour in a huge repository:

```text
map
 ↓
candidate identification
 ↓
dependency/reference expansion
 ↓
deep read
 ↓
verification
```

Bookworm MUST NOT ingest millions of irrelevant tokens merely because doing so is technically possible.

---

# 9. ROUTING

Model selection SHALL be treated as constrained optimisation.

Conceptually:

\[
m^* =
\arg\min_m
E[\text{total cost}(m)]
\]

subject to:

\[
P(\text{acceptable result}\mid m,r,t) \ge Q_{min}
\]

and:

```text
context capacity sufficient
privacy policy satisfied
latency policy satisfied
provider available
modality supported
language competence sufficient
verification requirements satisfiable
```

Routing inputs SHOULD include:

```text
task class
target language
target size
structural complexity
required fidelity
required output size
historical model performance
provider price
latency
failure rate
context capacity
cache characteristics
privacy restrictions
```

Routing SHALL be evidence-driven.

Bookworm SHOULD continuously maintain empirical capability records rather than relying solely upon nominal provider claims.

---

# 10. CONSENSUS

Consensus SHALL be selectively available.

Consensus SHOULD NOT mean blindly asking three models for prose and voting on the prose.

Bookworm SHALL prefer **claim-level consensus**.

Example:

```text
Reader A:
CLAIM: foo() is called only by bar()

Reader B:
CLAIM: foo() is called by bar() and baz()

              ↓

DISAGREEMENT DETECTED

              ↓

REFERENCE RESOLVER

              ↓

VERIFIED:
bar()
baz()
```

Where deterministic adjudication is possible, it SHALL dominate model voting.

Consensus modes SHOULD include:

```text
NONE
DUAL
MAJORITY
HETEROGENEOUS
ADVERSARIAL
VERIFY_ON_DISAGREEMENT
```

`VERIFY_ON_DISAGREEMENT` SHOULD be the normal high-assurance default.

---

# 11. CLAIM MODEL

Bookworm SHOULD transform semantic output into atomic claims.

Example:

```json
{
  "claim_id": "bw-c-0187",
  "statement": "refresh tokens are persisted in PostgreSQL",
  "status": "verified",
  "confidence": 0.997,
  "evidence": [
    {
      "path": "src/auth/refresh.rs",
      "start_line": 81,
      "end_line": 103,
      "hash": "..."
    },
    {
      "path": "src/db/tokens.rs",
      "start_line": 24,
      "end_line": 57,
      "hash": "..."
    }
  ],
  "verification": [
    "symbol_resolution",
    "call_graph"
  ]
}
```

Claims SHOULD be sufficiently granular that one disputed assertion does not invalidate an entire summary.

---

# 12. EVIDENCE ENVELOPE

Every substantive Bookworm response SHALL include machine-readable provenance.

Minimum conceptual envelope:

```text
BOOKWORM/1

request_id
timestamp

TARGET
repository
revision
working_tree
target

MEASUREMENT
files_discovered
files_considered
files_read
lines_read
bytes_read
tokens_ingested

STRATEGY
classification
ingestion_strategy
reader_model
consensus_mode

COVERAGE
scope
coverage_ratio
omissions

VERIFICATION
checks_attempted
checks_passed
checks_failed

OUTPUT
claims
citations
unknowns
conflicts

IDENTITY
source_hashes
result_hash
```

The orchestrator SHALL therefore be able to distinguish:

> Bookworm looked at the entire relevant module.

from:

> Bookworm found three apparently relevant files.

Those are epistemically different states and MUST NOT be represented identically.

---

# 13. VERIFICATION ENGINE

Bookworm SHALL deterministically test model assertions whenever economically practical.

Initial verification capabilities SHOULD include:

```text
path existence
text existence
line/range validation
symbol existence
symbol definition
reference search
import resolution
dependency existence
manifest validation
configuration lookup
AST relationship
call-site discovery
test existence
Git revision verification
hash verification
```

Later capabilities MAY include:

```text
type resolution
call graphs
control-flow analysis
data-flow analysis
schema validation
compiler-assisted checks
language-server queries
dependency graphs
cross-repository references
```

The governing rule:

> **Never spend another inference call debating something the machine can directly establish.**

---

# 14. PISA INTEGRATION

Bookworm SHALL be a first-class producer and consumer of PISA knowledge.

Successful resolution:

```text
QUESTION
   ↓
BOOKWORM
   ↓
VERIFIED EVIDENCE
   ↓
PISA
```

Future equivalent request:

```text
QUESTION
   ↓
PISA HIT
   ↓
VALIDATE SOURCE IDENTITY
   ├── unchanged → reuse
   └── changed   → invalidate/refresh
```

PISA entries originating from Bookworm SHOULD retain:

```text
query/intent class
resolved target
claims
evidence ranges
source hashes
repository revision
verification state
creation time
reader/model provenance
```

A valid PISA hit SHOULD be capable of reducing a previously inferential retrieval operation to a deterministic lookup.

---

# 15. CACHE INVALIDATION

Cached knowledge SHALL be evidence-addressed.

A result MUST NOT be considered valid merely because:

```text
path == previous_path
```

Validity SHOULD derive from immutable identity such as:

```text
repository + revision + blob hash
```

Where only part of a file supports a claim, Bookworm MAY use range/AST-level fingerprints to preserve unaffected knowledge across unrelated edits.

This enables fine-grained invalidation.

---

# 16. CODEBASE LOCALITY

Bookworm SHOULD measure how efficiently a repository exposes task-relevant information.

Define a provisional locality metric:

\[
L =
\frac{I_{relevant}}
     {I_{ingested}}
\]

where \(I\) represents an appropriate information/token approximation.

Higher locality indicates that a task can be contextualised without reading large quantities of irrelevant source.

Bookworm SHOULD record locality statistics by:

```text
repository
directory
module
task class
```

DreamSequence MAY consume these statistics as architectural observations.

Examples:

```text
Low locality:
Authentication changes routinely require reading 41 unrelated files.

Suggested intervention:
Separate token lifecycle logic from HTTP middleware.
```

Thus modularity becomes not merely stylistic but **economically observable through inference expenditure**.

---

# 17. COVERAGE SEMANTICS

Bookworm MUST explicitly report coverage.

Suggested classes:

```rust
pub enum Coverage {
    Exhaustive,
    StructurallyExhaustive,
    Targeted,
    Sampled,
    Partial,
    Unknown,
}
```

A targeted search returning no evidence MUST NOT be presented as equivalent to an exhaustive search returning no evidence.

Negative claims require especially strict coverage semantics.

---

# 18. FAILURE BEHAVIOUR

Bookworm SHALL fail closed with respect to certainty.

Failures include:

```text
target missing
permission denied
unsupported encoding
parser failure
token budget impossible
model unavailable
verification disagreement
repository mutation during read
stale cache
ambiguous target
insufficient evidence
```

Bookworm SHALL report the failure state rather than fabricate completion.

If repository state changes during acquisition, Bookworm SHOULD either:

1. restart against the new state; or
2. complete against the frozen original revision;

but MUST NOT silently combine inconsistent states.

---

# 19. SECURITY

Bookworm SHALL assume repository contents can be adversarial.

Source files and documentation MAY contain prompt injection.

Bookworm MUST distinguish:

```text
INSTRUCTIONS FROM CONTROLLER
```

from:

```text
CONTENT BEING READ
```

Content SHALL NEVER gain authority merely because it contains imperative natural language.

Bookworm SHALL:

- sandbox parsers where practical;
- never execute inspected source by default;
- enforce filesystem scope;
- prevent path traversal outside authorised roots;
- redact configured secrets before remote inference;
- support local-only inference policy;
- record provider exposure;
- reject unsupported binary execution;
- maintain strict read-only operation unless another capability explicitly authorises mutation.

---

# 20. OBSERVABILITY

Every operation SHALL emit structured telemetry.

Minimum metrics:

```text
bookworm_requests_total
bookworm_request_latency_ms
bookworm_bytes_scanned
bookworm_lines_scanned
bookworm_tokens_ingested
bookworm_tokens_returned
bookworm_inference_cost
bookworm_cache_hits
bookworm_pisa_hits
bookworm_deterministic_resolutions
bookworm_model_calls
bookworm_consensus_calls
bookworm_verification_passes
bookworm_verification_failures
bookworm_claim_conflicts
bookworm_coverage_ratio
```

Bookworm SHOULD additionally estimate:

```text
orchestrator_tokens_avoided
orchestrator_calls_avoided
estimated_direct_cost
bookworm_cost
net_saving
```

The economic proposition MUST therefore be empirically testable.

---

# 21. EVALUATION

Bookworm SHALL ship with an evaluation harness.

Benchmark classes SHOULD include:

### Retrieval

Given a task, did Bookworm identify the files required to answer it?

### Sufficiency

Could a downstream model successfully perform the task using only the supplied Bookworm package?

### Precision

How much irrelevant evidence was supplied?

### Factuality

Were emitted claims supported by cited evidence?

### Negative-query correctness

Can Bookworm correctly distinguish:

```text
not found
```

from:

```text
not exhaustively searched
```

### Cost

Compare:

```text
A: orchestrator performs its own exploration
B: Bookworm contextualises first
```

Measure:

```text
input tokens
output tokens
model calls
wall time
monetary cost
task success
```

### Regression

Frozen repository/task fixtures MUST make retrieval regressions reproducible.

---

# 22. PROPOSED RUST WORKSPACE

```text
bookworm/
├── Cargo.toml
├── crates/
│   ├── bookworm-core/
│   ├── bookworm-request/
│   ├── bookworm-resolver/
│   ├── bookworm-measure/
│   ├── bookworm-classify/
│   ├── bookworm-tokenize/
│   ├── bookworm-structure/
│   ├── bookworm-budget/
│   ├── bookworm-router/
│   ├── bookworm-reader/
│   ├── bookworm-consensus/
│   ├── bookworm-claims/
│   ├── bookworm-verify/
│   ├── bookworm-evidence/
│   ├── bookworm-cache/
│   ├── bookworm-pisa/
│   ├── bookworm-policy/
│   ├── bookworm-security/
│   ├── bookworm-telemetry/
│   ├── bookworm-eval/
│   ├── bookworm-cli/
│   └── bookworm-server/
├── fixtures/
├── evals/
├── schemas/
└── docs/
```

Crates MUST remain narrowly scoped.

`bookworm-core` SHALL NOT become a miscellaneous dumping ground.

---

# 23. CLI

Initial CLI surface SHOULD include:

```text
bookworm read <target>
bookworm locate <query>
bookworm explain <target>
bookworm map <target>
bookworm verify <claim>
bookworm measure <target>
bookworm estimate <target>
bookworm route <target>
bookworm evidence <request-id>
bookworm claims <request-id>
bookworm cache status
bookworm cache invalidate
bookworm eval
bookworm doctor
```

Useful flags:

```text
--budget
--model
--provider
--fidelity
--consensus
--verify
--revision
--local-only
--no-cache
--raw
--json
```

All major functionality SHALL expose machine-readable JSON.

---

# 24. SERVICE INTERFACE

Bookworm SHOULD expose a local service API suitable for Lucid and VICO.

Conceptual endpoints:

```text
POST /v1/read
POST /v1/locate
POST /v1/explain
POST /v1/map
POST /v1/verify
POST /v1/estimate

GET  /v1/jobs/{id}
GET  /v1/evidence/{id}
GET  /v1/claims/{id}
GET  /v1/health
GET  /v1/metrics
```

Streaming SHOULD be available for large investigations.

The API MUST expose evidence and uncertainty, not merely final prose.

---

# 25. LUCID INTEGRATION

Lucid preflight SHOULD detect evidence-acquisition requirements before primary reasoning.

Example:

```text
USER:
Why does Windows startup fail in Edwardian?
```

Desired flow:

```text
Lucid Preflight
      ↓
extract:
repository = Edwardian
task = diagnose startup failure
realm = repository evidence
      ↓
Bookworm
      ↓
repository map
      ↓
relevant Windows/platform modules
      ↓
relevant tests/configuration
      ↓
verified evidence package
      ↓
Lucid primary model
      ↓
reasoning/response
```

The primary model SHOULD receive:

- the user's original intent;
- the evidence package;
- relevant uncertainty;
- citations;
- sufficient raw source for critical reasoning.

It SHOULD NOT ordinarily receive Bookworm's exploratory transcript.

This is essential.

**The cost of finding context MUST NOT itself become context.**

---

# 26. STEP DEDUPLICATION

Bookworm SHALL integrate with Lucid's step-deduplication mechanisms.

Before performing an acquisition step, Bookworm SHOULD derive an operation identity from:

```text
intent
target
revision/hash
fidelity
verification policy
```

Equivalent completed operations MAY be reused.

Example:

```text
READ src/auth.rs @ blob abc123
```

performed once SHOULD NOT be independently repeated by five agents unless:

- their required fidelity differs;
- verification requires independent reading;
- the evidence has changed;
- policy explicitly prohibits reuse.

This allows swarm execution without swarm-level token multiplication.

---

# 27. RUNG INTEGRATION

Bookworm evidence MAY support Rung invariants.

Where Rung asks:

> Did this revision accidentally remove capability X?

Bookworm MAY provide:

```text
previous implementation evidence
current implementation evidence
symbol/reference comparison
test presence
configuration comparison
```

Rung remains the policy/enforcement system.

Bookworm remains the evidence system.

---

# 28. CORTEX INTEGRATION

Cortex SHOULD be capable of maintaining persistent Bookworm structural indexes for hosted repositories.

A Cortex may continuously maintain:

```text
repository topology
symbol index
dependency graph
file hashes
language metadata
structural summaries
verified PISA entries
```

Consequently Bookworm requests against a warm Cortex SHOULD avoid repeated cold repository analysis.

---

# 29. ECONOMIC SUCCESS CONDITION

Bookworm SHALL NOT be declared successful because it uses cheaper models.

It SHALL be successful only if:

\[
C_B + C_O' < C_O
\]

while:

\[
Q_B \ge Q_O - \epsilon
\]

where:

- \(C_B\) = Bookworm acquisition cost;
- \(C_O'\) = downstream orchestrator cost after Bookworm;
- \(C_O\) = baseline orchestrator cost without Bookworm;
- \(Q_B\) = task quality with Bookworm;
- \(Q_O\) = baseline task quality;
- \(\epsilon\) = permitted degradation.

The preferred outcome is stronger:

\[
C_B + C_O' \ll C_O
\]

and:

\[
Q_B \ge Q_O
\]

Bookworm SHOULD therefore optimise **total workflow economics**, not merely its own call price.

---

# 30. ACCEPTANCE GATES

Bookworm SHALL NOT be considered production-ready until it demonstrates:

**BW-G01 — Deterministic measurement**  
Repeated measurement of unchanged targets produces identical results.

**BW-G02 — Revision integrity**  
Evidence cannot silently cross incompatible repository revisions.

**BW-G03 — Provenance completeness**  
Material semantic claims can be traced to source evidence.

**BW-G04 — Budget compliance**  
No inference request exceeds calculated context constraints.

**BW-G05 — Honest coverage**  
Partial retrieval cannot present itself as exhaustive retrieval.

**BW-G06 — Verification**  
Supported deterministic assertions are automatically checked.

**BW-G07 — Injection resistance**  
Repository text cannot acquire controller authority.

**BW-G08 — Cache correctness**  
Changed evidence invalidates affected cached knowledge.

**BW-G09 — Economic improvement**  
Representative Lucid workloads show measurable reduction in total inference expenditure.

**BW-G10 — Quality preservation**  
Reduced cost does not produce unacceptable task-success regression.

---

# 31. FUNDAMENTAL SYSTEM RULE

Bookworm SHALL embody the following ELCI principle:

> **Do not pay a reasoning model to discover what computation can establish, do not pay a frontier model to read what a smaller model can faithfully read, and do not pay any model twice to learn an unchanged fact already established with sufficient evidence.**

The desired ELCI information hierarchy is therefore:

```text
                USER INTENT
                     │
                     ▼
              LUCID PREFLIGHT
                     │
             evidence required
                     │
                     ▼
                 BOOKWORM
        ┌────────────┼────────────┐
        ▼            ▼            ▼
 deterministic    structural    semantic
  inspection       analysis      readers
        │            │            │
        └────────────┼────────────┘
                     ▼
                 VERIFY
                     │
                     ▼
             EVIDENCE PACKAGE
                │          │
                ▼          ▼
              PISA       LUCID
             memory     reasoning
                │          │
                └────┬─────┘
                     ▼
               :e / AGENTS
                     │
                     ▼
                 EXECUTION
```

Bookworm is therefore not primarily a reader.

It is the **epistemic I/O layer of the ELCI agent stack**.

Its responsibility is to make repository knowledge cheap to acquire, expensive to falsify, straightforward to verify, reusable when unchanged, and sufficiently well structured that high-value models can spend their inference budget on the part of software engineering for which inference is actually required: **reasoning about what should happen next.**