# Diagnostic Architecture Migration Plan

Status: active plan

Baseline branch: `dev`

Baseline commit: `3375b5f`

## 1. Migration rule

The repository will not be rewritten in one pass. Every migration step follows:

```text
characterize current behavior
  -> introduce canonical type or interface
  -> add a one-way compatibility adapter
  -> migrate one producer and its consumers
  -> compare old and new outputs
  -> remove the old representation
  -> remove the adapter
```

Each commit has one purpose, passes the full test suite, and leaves static `SAFE` and
dynamic `TRACE_SAFE` no less strict than the baseline.

## 2. Phase B completion: architecture and contract

Deliverables:

- current repository audit;
- accepted target package/dependency map;
- canonical repository soundness contract;
- this incremental migration plan;
- root architecture index pointing to canonical documents.

No analyzer behavior changes in this phase.

Acceptance:

- documents answer ownership, dependency, Unknown, verdict and certificate questions;
- forbidden dynamic-to-static proof flow is explicit;
- the full existing suite remains unchanged;
- only documentation is committed.

## 3. Phase C: evidence and provenance foundation

Phase C creates the boundary on which diagnostics will depend. It does not yet add
canneal-specific correlation.

### C1 — Characterization and dependency tests

Add test groups for:

- current static certificate JSON and verdict behavior;
- current dynamic certificate JSON and verdict behavior;
- current event/proof/Unknown counts for small synthetic fixtures;
- package dependency DAG;
- no benchmark names in core semantic branches;
- no static import of dynamic or diagnostics.

Commit intent: `Characterize evidence and verdict boundaries`.

Implementation record: `docs/exec-plans/active/c1-characterization.md`. The current
checkpoint covers the static/dynamic certificate shapes, Unknown visibility, bounded
synthetic counts, route import boundaries and benchmark-name checks. It does not yet
claim that the legacy dictionary-based models are the canonical evidence domain.

### C2 — Stable identity types

Introduce `bmo_check_core.identity` with canonical encoders for binary closure, module,
function, block, instruction, memory operand, static event, abstract object, thread
role, trace and evidence IDs.

Property tests must show:

- construction is deterministic across process runs;
- input collection order does not change set/graph IDs;
- JSON round trips preserve identity;
- a changed module hash, operand index or trace digest changes the relevant ID;
- Python object identity and benchmark labels are never inputs.

Commit intent: `Add stable analysis identities`.

Implementation record: `docs/exec-plans/active/c2-identities.md`. The first cut adds
only `bmo_check_core.identity` and property-style tests; route producers and
certificate consumers remain on legacy models until C3/C4 adapters exist.

### C3 — Typed evidence domain and ledger

Introduce strict, frozen variants:

- `ProofFact`;
- `ObservedFact`;
- `DiagnosticHint`;
- `UnknownFact`;
- `UnknownDischarge`;
- `EvidenceLedger`.

Add canonical Unknown kinds and producer identities. Proof premises accept only proof
IDs. The ledger rejects missing parents, ID/content mismatch, duplicate IDs with
different payloads and invalid category edges.

Commit intent: `Introduce typed evidence domain`.

Implementation record: `docs/exec-plans/active/c3-evidence.md`. The canonical ledger
is now available, but legacy route models remain authoritative until C4 adapters and
differential tests are in place.

### C4 — Legacy static adapter

Add a one-way adapter from current static models to canonical identities/evidence. It
exists only to preserve behavior while producers migrate.

The adapter header must state:

- why it exists;
- current callers;
- unsupported legacy payloads;
- deletion condition: all static producers and certificate consumers use canonical
  evidence directly.

Differential tests compare current static JSON/verdicts with adapter-backed output.
The adapter cannot construct ObservedFacts or DiagnosticHints.

Commit intent: `Adapt static facts to canonical evidence`.

Implementation record: `docs/exec-plans/active/c4-static-adapter.md`. The adapter
maps legacy events, proof objects and Unknowns into stable IDs and an append-only
ledger through typed links. It is not used by current verdict construction, cannot
create observations or hints, and rejects payloads whose event/proof references
would otherwise be dropped.

### C5 — Proof-closure certificate verifier

Introduce separate static and trace certificate builders plus a replay verifier. At
first, the current certificate remains the external payload and is translated at the
serialization boundary.

Required negative tests:

- observed or diagnostic evidence reachable from static `SAFE` is rejected;
- removed event without a reachable proof is rejected;
- relevant Unknown without discharge is rejected;
- bounded no-counterexample is rejected as `SAFE`;
- mismatched binary/library/DBT binding is rejected.

Implementation record: `docs/exec-plans/active/c5-certificate-closure.md`. The core
certificate package now provides separate static/trace certificate types, typed
bindings and replay verifiers. The existing legacy certificate builder is still not
wired to this API; C6 must migrate a producer and compare both outputs first.

Commit intent: `Validate static proof closure in certificates`.

### C6 — Migrate Unknown production and removal decisions

Migrate one producer at a time in this order:

1. dependency closure and CFG recovery;
2. thread lifecycle and synchronization;
3. memory-event recovery;
4. address/escape/alias analyses;
5. slicing and event removal;
6. portability checker outcomes.

Each migration replaces `details` keys and string evidence with typed subject and
premise references. Unknown relevance and discharge move out of
`proof.verifier._collect_unknowns` into explicit scope/discharge records.

Implementation record: `docs/exec-plans/active/c6-recovery-unknown.md`. The first
slice adds an opt-in canonical ledger path to dependency-closure recovery while
keeping the legacy manifest API and verdict consumer unchanged. CFG and later
producers remain to be migrated.

Implementation record: `docs/exec-plans/active/c6-cfg-unknown.md`. The second slice
adds the same opt-in path to CFG/indirect-target recovery; backend and incomplete
target Unknowns are emitted canonically while the legacy `ControlFlowReport` remains
unchanged.

Implementation record: `docs/exec-plans/active/c6-thread-sync-unknown.md`. The third
slice adds the opt-in path to thread lifecycle and synchronization recovery. Callback,
role, join, symbol, disassembly and return-path Unknowns are emitted canonically while
legacy reports remain unchanged.

Implementation record: `docs/exec-plans/active/c6-memory-events-unknown.md`. The fourth
slice adds the opt-in path to memory-event recovery, stable legacy-event links and
canonical Unknown emission for address, syscall, opaque-call and extraction gaps.

`SharedStateReport` keeps its current validator until every removal has a canonical
`RemovalDecision`.

Commit intents are subsystem-specific, for example
`Migrate recovery Unknowns to canonical provenance`.

### C7 — Canonical memory and portability ownership

Move shared memory identities, relation vocabulary and DBT contract interpretation to
`bmo_check_core`. Keep static and dynamic event payloads as adapters until differential
relation tests prove the canonical implementation matches both existing routes.

Do not delete either route-specific checker merely because the new checker passes a
few litmus tests. Deletion requires the full relation matrix and historical regression
suite.

Commit intent: `Unify source and target memory-order contracts`.

### C8 — Application services and thin CLIs

Extract one static and one dynamic orchestration service. Move PARSEC orchestration to
`bmo_check_evaluation`. CLIs parse inputs and render outputs only.

Commit intent: `Separate application services from CLI and evaluation`.

### Phase C exit criteria

- canonical evidence and identity types are used by certificate verification;
- static `SAFE` closure rejects observed/diagnostic evidence;
- every removed event has a canonical proof reference;
- relevant Unknowns are conserved or discharged explicitly;
- package dependency tests run in the default suite;
- compatibility adapters have explicit deletion checklists;
- no dynamic-assisted feature has changed static verdicts.

## 4. Phase D: dynamic-assisted static diagnostics

Phase D begins only after Phase C exit criteria pass.

### D1 — Diagnostic snapshots

Expose read-only canonical snapshots:

```text
StaticDiagnosticSnapshot
  UnknownFacts
  instruction/operand/object/thread identities
  provenance graph
  unchanged static verdict

DynamicDiagnosticSnapshot
  ObservedFacts
  trace/execution identity
  module-relative instruction sites
  runtime objects and coverage
```

Neither snapshot exposes mutable analyzer state.

Commit intent: `Expose static and dynamic diagnostic snapshots`.

### D2 — Trace operand identity

Extend the trace schema to record a stable memory-operand discriminator when the same
instruction can generate more than one access. Provide a versioned reader for existing
traces. Old traces remain usable for site-level diagnostics, but a multi-operand match
is explicitly ambiguous.

Commit intent: `Bind runtime accesses to memory operands`.

### D3 — Correlation model

Implement correlation using, in order:

1. binary closure and module hash;
2. module-relative instruction ID;
3. memory operand index/effect discriminator;
4. function and block identity;
5. abstract object and thread role when both routes can support them.

Output variants are `Exact`, `Ambiguous`, and `Unmatched`. Benchmark name, source line,
trace sequence and Python object ID are forbidden keys.

Commit intent: `Correlate static Unknowns with runtime observations`.

### D4 — Diagnostic report and CLI

Add `bmo-check diagnose` to produce a versioned report containing:

- the unchanged static verdict and certificate identity;
- trace/certificate identities;
- every selected static Unknown;
- exact, ambiguous or unmatched correlation;
- observed facts and coverage;
- diagnostic hints and confidence;
- an explicit statement that no hint changed the static proof.

Commit intent: `Report dynamic-assisted static diagnostics`.

### D5 — Generic root-cause registry

Introduce typed classifications incrementally:

```text
MissingInductionVariable
MissingLoopBound
MissingPhiRecurrence
MissingArgumentProvenance
MissingFieldProvenance
MissingGlobalSummary
MissingThreadIdProvenance
MissingLifecycleBound
MissingAliasPrecision
OpaqueCallBoundary
UnresolvedIndirect
UnsupportedAddressNormalization
NotExecutedInObservedTrace
DynamicPatternNotStable
UnknownRootCause
```

Initial classifiers may return `UnknownRootCause`. No classifier changes a verdict.

Commit intent: `Classify static precision gaps without changing verdicts`.

### Phase D exit criteria

- a dynamic trace can locate static Unknowns through stable identities;
- ambiguous matches are preserved;
- observations and hints cannot enter static proof APIs;
- diagnostic reports retain the original static verdict;
- tests prove that adding, removing or changing a trace cannot change static analysis
  output.

## 5. Phase E: UnknownAffineBounds and canneal validation

canneal is a validation case, not a semantic input.

### E1 — Observed affine summaries

For each correlated `UnknownAffineBounds`, aggregate trace-bound observations:

- normalized instruction and operand;
- sample count and coverage;
- observed base candidates;
- observed min/max and stride candidates;
- observed thread IDs and role candidates;
- per-thread address sets and observed overlap;
- repetition stability across loop executions and campaign traces.

The output type is `ObservedAffinePattern`. It cannot be used where
`StaticAffineBounds` or `DisjointProof` is required.

Commit intent: `Diagnose affine-bound Unknowns from observations`.

### E2 — Validate on canneal

Run the unchanged static analyzer and preserve:

```text
static verdict = UNKNOWN
relevant UnknownAffineBounds = 8
```

Then correlate the available canneal traces and report, for example, how many of the
eight sites were exercised, ambiguous or not executed. Do not require all eight to
match before the generic diagnostic system is accepted.

No code may branch on `canneal`, its function names or observed stride/bounds.

### E3 — Improve one generic static capability

Choose the most frequent diagnosed root cause, then implement a generic static
analysis improvement with synthetic positive, negative and Unknown tests. Candidate
first capabilities are:

- PHI recurrence recovery;
- induction-variable bound propagation;
- caller argument provenance;
- field-sensitive heap provenance.

Only a new static `ProofFact` may discharge the corresponding Unknown. Rerun the pure
static analyzer without loading any trace. If closure succeeds, the verdict may change;
otherwise it remains `UNKNOWN`.

Commit intent must name the generic capability, not canneal.

### E4 — Broader evaluation

After synthetic and canneal validation, evaluate the same generic capability on the
PARSEC portfolio. Report:

- Unknown kinds before and after;
- proof closures added;
- unchanged or changed verdicts;
- analysis time and resource failures;
- diagnostic precision and ambiguous-correlation rate.

PARSEC results remain under `.experiments/` unless a deliberately small fixture is
reviewed for version control.

### Phase E exit criteria

- canneal diagnostics identify actionable static gaps without changing the original
  static verdict;
- at least one generic static capability is justified by synthetic tests and produces
  static ProofFacts independently of traces;
- every changed static verdict is replayable from a proof-closed certificate;
- no benchmark-specific semantic branch exists.

## 6. Test migration

Tests move by responsibility, not all at once:

1. add new `invariant`, `contract` and `certificate` directories first;
2. keep old static/dynamic tests in place while adapters exist;
3. copy only when a new canonical interface replaces the old one;
4. use differential tests during overlap;
5. delete the old test only when the old implementation is removed;
6. keep PARSEC tests opt-in and separate from default algorithm tests.

The default suite must stay bounded and runnable without PARSEC. Native DynamoRIO
tests may skip only for a missing declared environment, never because a trace assertion
failed.

## 7. Adapter registry

Every compatibility adapter is listed in a future machine-readable registry with:

```text
adapter ID
source type/version
target type/version
current callers
soundness limitations
owner
introduced commit
deletion condition
```

CI fails if an adapter has no deletion condition. Adapters cannot remain as alternate
business models after all callers migrate.

## 8. Atomic commit sequence

The expected sequence is:

1. `Document repository architecture and soundness boundaries`
2. `Characterize evidence and verdict boundaries`
3. `Add stable analysis identities`
4. `Introduce typed evidence domain`
5. `Adapt static facts to canonical evidence`
6. `Validate static proof closure in certificates`
7. subsystem-specific Unknown/provenance migrations
8. `Unify source and target memory-order contracts`
9. `Separate application services from CLI and evaluation`
10. `Expose static and dynamic diagnostic snapshots`
11. `Bind runtime accesses to memory operands`
12. `Correlate static Unknowns with runtime observations`
13. `Report dynamic-assisted static diagnostics`
14. `Diagnose affine-bound Unknowns from observations`
15. generic static capability commits
16. `Update repository guidance for evidence architecture`

The exact number may change, but a commit must not combine canonical evidence types,
an analyzer migration and a benchmark precision change.

## 9. Per-commit gate

Before each commit:

1. run the full default test suite;
2. run targeted new invariant/property tests;
3. inspect `git diff` and `git diff --check`;
4. run dependency and benchmark-name architecture checks;
5. confirm no experiment or trace artifact is staged;
6. compare old/new serialized outputs when an adapter is involved;
7. state remaining adapters and technical debt in the phase report.

If a gate fails, the migration stops at the last green atomic commit.
