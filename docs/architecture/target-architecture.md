# Target Architecture

Status: accepted design; implementation pending

Applies after: repository baseline `3375b5f`

Canonical soundness rules: `docs/spec/soundness.md`

## 1. Design objective

BMoCheck has two analysis routes and one shared research question:

- static analysis may issue `SAFE` only from static proof closure;
- dynamic analysis may issue `TRACE_SAFE` only for a bound execution trace;
- diagnostics may correlate both routes, but may never alter either proof lattice.

The architecture must make the forbidden flow difficult to express:

```text
ObservedFact -> static lattice -> SAFE             forbidden
DiagnosticHint -> Unknown discharge -> SAFE       forbidden

ObservedFact + UnknownFact -> DiagnosticHint       allowed
DiagnosticHint -> developer change -> static run   allowed
static ProofFact -> Unknown discharge -> SAFE      allowed
```

Correctness and soundness take priority over migration convenience. The migration is
incremental because every intermediate commit must keep the current verifier usable
and auditable.

## 2. Target package map

The existing route packages remain. New shared packages have narrow names and cannot
become a generic `common` directory.

```text
src/
├── bmo_check_core/
│   ├── identity/           stable binary, instruction, operand, object and evidence IDs
│   ├── evidence/           ProofFact, ObservedFact, DiagnosticHint, UnknownFact, ledger
│   ├── memory/             canonical MemoryEvent, AbstractAddress, SharedObject, provenance
│   ├── contracts/          typed DBT/binary/effect contracts and fingerprints
│   ├── portability/        source/target models, communication graph and proof obligations
│   └── certificate/        static/trace schemas, builders, closure verifier and replay
├── bmo_check_static/
│   ├── recovery/           ELF, CFG, indirect targets and thread lifecycle
│   ├── analysis/           escape, readonly, affine, alias and synchronization coverage
│   ├── application.py      one static orchestration service
│   └── adapters/           temporary legacy-model adapters
├── bmo_check_dynamic/
│   ├── capture/            process control and DynamoRIO launcher
│   ├── native/             native client
│   ├── trace/              raw format and ingestion
│   ├── runtime/            normalized events, syscalls, objects and lifecycle
│   ├── storage/            bounded streaming storage
│   ├── application.py      one trace-analysis orchestration service
│   └── adapters/           temporary legacy-model adapters
├── bmo_check_diagnostics/
│   ├── correlation/        exact, ambiguous and unmatched evidence correlation
│   ├── affine/             observed affine-pattern summaries
│   ├── classification/     extensible root-cause classifiers
│   └── report/             diagnostic report schema and explanation
├── bmo_check_evaluation/
│   ├── parsec.py           typed PARSEC harness and aggregation service
│   └── regression/         reproducible experiment drivers
└── bmo_check_cli/
    ├── dynamic.py          capture, analyze, run and campaign commands
    ├── static.py           recover, slice and static analyze commands
    ├── diagnose.py         correlation and diagnostic reporting
    └── explain.py          certificate/report explanation
```

This is the target ownership map, not a command to move every file at once. Existing
entry points remain operational through thin wrappers until their callers and tests
have migrated.

Current migration status: dependency closure, CFG recovery, thread lifecycle,
synchronization and memory-event recovery each expose an explicit
legacy-report-plus-ledger sidecar. Memory events also expose stable identity links.
Shared-state classification now exposes the same sidecar for escape and affine
Unknowns, and slicing exposes typed removal decisions. Portability exposes its
relevant Unknowns, and the static certificate bridge now consumes all of these
sidecars and replays a canonical `StaticCertificate`. The old report and JSON
serializer remain the compatibility surface until differential certificate tests
cover every verdict. `bmo_check_core.contracts` now owns the typed DBT
memory-order contract; route-specific YAML/model classes are input adapters. The
sidecars are not a shortcut to a static `SAFE` verdict. Read-only diagnostic
snapshots now live in `bmo_check_core.diagnostics`; the static route exposes its
replayed certificate through a one-way snapshot adapter, and the dynamic route
streams validated trace files through its matching snapshot adapter. The D4
serialization boundary can read snapshots produced by either adapter without
exposing route internals. These snapshots are the only planned input to a
correlator. The static and dynamic CLIs' primary capture/recover/analyze paths now
construct typed application requests. PARSEC orchestration now lives in
`bmo_check_evaluation`, including its per-benchmark worker and report aggregation;
the static compatibility CLI only converts arguments and renders the returned report.

## 3. Dependency direction

### 3.1 Package-level graph

```text
bmo_check_cli ---------> static / dynamic / diagnostics / evaluation
bmo_check_evaluation --> static / dynamic / diagnostics / core
bmo_check_static ------> core
bmo_check_dynamic -----> core
bmo_check_diagnostics -> core
bmo_check_core --------> no BMoCheck implementation package
```

Forbidden imports:

- `core` must not import static, dynamic, diagnostics, evaluation or CLI;
- static and dynamic must not import each other;
- static and dynamic must not import diagnostics or evaluation;
- diagnostics must consume canonical evidence snapshots, not analyzer internals;
- portability and certificate code must not import PARSEC or benchmark manifests;
- evaluation must never be imported by core analysis.

### 3.2 `bmo_check_core` graph

```text
identity
   ↑
evidence       contracts
   ↑              ↑
memory -----------+
   ↑
portability
   ↑
certificate
```

More precisely:

- `identity` depends only on the standard library;
- `evidence` depends on identity and schema primitives;
- `contracts` depends on identity and schema primitives;
- `memory` depends on identity and evidence references, not analyzers;
- `portability` consumes canonical memory and contract facts and returns a typed check
  result; it never constructs a certificate;
- `certificate` is the only layer that maps a checked result and evidence ledger to a
  serializable verdict.

## 4. Canonical identity model

IDs are immutable value objects with canonical string serialization. They are derived
from semantic identity, not Python addresses, traversal order or benchmark names.

| Identity | Required material |
|---|---|
| `BinaryClosureId` | executable hash, ordered module-role/hash set and ABI |
| `ModuleId` | module content hash and module role |
| `FunctionId` | `ModuleId` plus ELF virtual entry offset |
| `BasicBlockId` | `FunctionId` plus ELF virtual block offset |
| `InstructionId` | `ModuleId` plus ELF virtual instruction offset |
| `MemoryOperandId` | `InstructionId`, normalized operand index and effect discriminator |
| `MemoryEventId` | `MemoryOperandId`, static `ThreadRoleId`, event kind and summary discriminator |
| `AbstractObjectId` | typed origin: global/TLS/frame/allocation/mapping plus origin identity |
| `ThreadRoleId` | parent role, creation site and canonical start-target set |
| `TraceId` | trace format version plus digest of bound manifest, modules, markers and records |
| `ThreadInstanceId` | `TraceId` plus tracer thread-instance identity |
| `EvidenceId` | evidence category, schema version, producer, subject and canonical premises |

Runtime PCs are never identity by themselves. They are normalized through the loaded
module map to `InstructionId`. If the trace format cannot distinguish two memory
operands at one PC, correlation returns `AmbiguousCorrelation`; it does not choose one.

## 5. Canonical evidence model

The in-memory model is a discriminated union, not an untyped JSON dictionary:

```text
EvidenceNode = ProofFact | ObservedFact | DiagnosticHint | UnknownFact
```

### `ProofFact`

- produced only by static recovery/analysis, a static solver, or a validated contract;
- has typed subject, producer, rule and premise IDs;
- may carry a typed set of covered memory-event identities for removal decisions;
- premises may reference only `ProofFact`;
- may discharge an `UnknownFact` through an explicit `UnknownDischarge` record;
- may enter static `SAFE` proof closure.

A solver result whose premises contain runtime observations is not a `ProofFact`. It
is a trace-scoped check result.

### `ObservedFact`

- produced from a validated dynamic trace;
- always carries `TraceId`, execution binding and normalized subject identity;
- records observations such as addresses, ranges, threads, targets and patterns;
- never appears in static proof premises or `SAFE` roots.

### `DiagnosticHint`

- references one or more `UnknownFact` IDs and supporting `ObservedFact` IDs;
- records confidence and a root-cause classification;
- guides a developer or coding agent to improve static analysis;
- cannot discharge Unknowns and cannot enter either verdict constructor.

### `UnknownFact`

- has a stable ID, canonical kind, producer, reason, subject, relevance scope and
  provenance chain;
- remains in an append-only evidence ledger until a `ProofFact` explicitly discharges
  it for a declared scope;
- resource, unsupported and incomplete-recovery causes are separate variants;
- deduplication preserves all origins and contexts rather than dropping differing
  payloads.

### Trace-scoped proof result

`TRACE_SAFE` still needs a formal source-versus-target check. The result is called
`TraceCheckResult`, not `ProofFact`, because its premises include `ObservedFact`. Its
type can enter a trace certificate but is rejected by a static certificate verifier.

## 6. Provenance as a graph

Every derived fact records typed edges to its inputs:

```text
ModuleId
  -> InstructionId
  -> MemoryOperandId
  -> AddressExpression
  -> caller argument / heap field / PHI recurrence
  -> induction variable
  -> missing bound
  -> UnknownFact(UnknownAffineBounds)
```

The graph must answer:

- which executable and module produced the fact;
- which instruction and memory operand it concerns;
- which function, block, object and thread role are affected;
- which pass produced it;
- where provenance became incomplete;
- which proof, if any, later discharged it.

Human-readable strings remain explanations only. They are not proof premises or
correlation keys.

## 7. Static application boundary

The static application service owns orchestration only:

```text
StaticRequest
  -> recovery snapshots
  -> canonical MemoryEvents
  -> analysis passes
  -> EvidenceLedger(ProofFact, UnknownFact)
  -> shared-memory slice plus RemovalDecision records
  -> static portability check
  -> static certificate builder/verifier
```

Each pass receives and returns typed snapshots. It cannot inspect another pass's
private dictionaries. `RemovalDecision` contains exactly one event ID, proof ID and
scope; bulk removal is serialized as multiple decisions even if storage is compacted.

`UnknownFact` relevance is decided before certificate construction by a typed scope
analysis. A change from relevant to discharged must cite a proof ID. The certificate
layer does not rediscover relevance from event metadata.

## 8. Dynamic application boundary

The dynamic application service owns sequencing but not semantics:

```text
TraceRequest
  -> format and completeness validation
  -> canonical TraceId and execution binding
  -> streaming normalized ObservedFacts
  -> runtime objects/lifecycles and communication windows
  -> TraceCheckResult
  -> trace certificate builder/verifier
```

Storage exposes typed queries. Application code cannot issue SQL using numeric event
kinds. Resource-limit and unsupported outcomes are typed `UnknownFact`s bound to the
trace scope.

The raw trace schema must eventually carry a stable memory-operand discriminator.
Until then, PC-only matches are site-level observations and may be ambiguous.

## 9. Portability ownership

Source and target memory-model definitions have one canonical owner in
`bmo_check_core.portability`:

- source x86-TSO preserved program order;
- target DBT6 `mo-off + RVWMO` ordering;
- LOCK/XCHG and explicit Fence contract interpretation;
- communication graph vocabulary;
- target-only execution checks.

Static and dynamic front ends may build different obligations, but they must use the
same relation rules or pass a differential equivalence suite. Route-specific windowing
and recovery stay outside the model owner.

## 10. Certificate boundary

Static and trace certificates are separate discriminated schemas.

### Static `SAFE`

The builder accepts only:

- a static scope binding;
- a static check result;
- `ProofEvidenceId` roots;
- a ledger with no unresolved relevant Unknown.

The verifier traverses every root and rejects the certificate if any reachable node is
missing, not a `ProofFact`, has a dynamic premise, belongs to another binary closure,
or was produced under a mismatched contract.

### Dynamic `TRACE_SAFE`

The builder accepts trace-scoped observations and `TraceCheckResult`. It binds:

- trace ID and trace schema;
- executable and loaded-library hashes;
- argv, selected environment and thread configuration;
- DynamoRIO and native client versions;
- analyzer version;
- DBT revision, contract version and contract hash;
- collection completeness and all resource limits.

Repeated trace certificates remain a campaign conjunction. They cannot be converted
to a static certificate.

## 11. Diagnostics boundary

Diagnostics consumes two immutable snapshots:

```text
StaticDiagnosticSnapshot = UnknownFacts + static identities + provenance graph
DynamicDiagnosticSnapshot = ObservedFacts + trace identities + coverage
```

It produces:

```text
CorrelationResult = Exact | Ambiguous | Unmatched
DiagnosticReport = correlations + DiagnosticHints + unchanged static verdict
```

The D4 report additionally binds both snapshot/certificate identities, selected
Unknowns, observed facts, coverage and trace completeness. Its JSON adapter rebuilds
typed evidence before correlation and has no operation that creates static proof.

The diagnostics package has no API that returns a `ProofFact`, `RemovalDecision`,
static lattice value or static certificate. Its report always prints the original
static verdict.

## 12. CLI and evaluation boundaries

The CLI parses and renders. It calls application services instead of assembling
recovery, slicing and proof stages itself.

The evaluation package owns PARSEC names, input layouts, repetitions and aggregation.
Core analysis receives only binary paths, execution scopes, contracts and typed facts.
Benchmark names never reach a semantic branch.

Existing command names remain during migration:

```text
bmo-check capture|analyze|run|campaign|explain|diagnose
bmo-check-static recover|slice|analyze|explain
```

Thin legacy wrappers may remain temporarily, but they contain no analysis policy.

## 13. Repository test architecture

Target test ownership is:

```text
tests/
├── unit/           identity, evidence, lattice, affine, alias and normalization
├── invariant/      Unknown conservation, proof closure and forbidden evidence flow
├── contract/       schemas, package dependencies and subsystem interfaces
├── regression/     one directory per historical bug
├── integration/    synthetic ELF, pthread/OpenMP and trace pipelines
├── differential/   old/new adapters and static/dynamic relation normalization
├── certificate/    replay and invalid-certificate rejection
└── benchmark/      PARSEC manifests and explicitly opt-in large runs
```

Large PARSEC runs are validation evidence, not the only algorithm test. Native capture
requirements remain explicit skips when the local toolchain is unavailable.

## 14. Repository artifact policy

The following are local experiment products and are not committed:

```text
.experiments/
.tmp*
.bmo-check/
large traces
PARSEC temporary results
DuckDB databases
native build directories
```

Only a deliberately reviewed, small fixture may be versioned. It must have a schema
version, a generating test or command, and a documented reason that synthetic
construction is insufficient.

## 15. Architectural enforcement

The target architecture is complete only when CI checks:

- the package dependency DAG;
- core semantic code contains no benchmark-name branches;
- `ProofFact` premises are proof-only;
- `SAFE` certificates pass proof-closure verification;
- `TRACE_SAFE` certificates contain full trace bindings;
- every removed memory event has a `RemovalDecision` and reachable `ProofFact`;
- relevant Unknowns are present or explicitly discharged;
- unsupported schema versions fail closed;
- ambiguous correlation cannot be serialized as exact;
- legacy adapters are listed with owners and deletion conditions.
