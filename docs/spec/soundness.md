# Repository Soundness Contract

Status: canonical

Version: 1.0

Audience: analyzers, diagnostics, certificate code, tests and evaluation harnesses

## 1. Authority

This document is the repository-level source of truth for evidence and verdict
boundaries. Route-specific documents may describe implementation details, but they
must not weaken these rules. If code, a test, an experiment or another document
conflicts with this contract, the result must fail closed until the conflict is
resolved.

Normative words `MUST`, `MUST NOT`, `MAY` and `UNKNOWN` have their ordinary
requirements meaning.

## 2. Verdict domains

### Static domain

`SAFE` means that the behavior-inclusion claim is proven for the exact static scope
bound by the certificate. The scope may constrain executable closure, DBT revision,
contracts, argv, thread range and application boundary. It does not silently expand
beyond those bindings.

`COUNTEREXAMPLE` means the checker has a target execution accepted by DBT6
`mo-off + RVWMO` and rejected by x86-TSO under the same modeled execution.

`UNKNOWN` means the static proof did not close. It is a valid, conservative result.

### Dynamic domain

`TRACE_SAFE` means the source-versus-target inclusion query closed for one explicitly
bound observed event skeleton. It does not cover unexecuted paths, another input,
another runtime address pattern or a future execution.

Dynamic `COUNTEREXAMPLE` and `UNKNOWN` are trace-scoped and must carry the same trace
binding.

`NoRiskFound`, a successful native exit, a passing test and a collection of
`TRACE_SAFE` runs are not verdicts in the static domain.

## 3. Evidence categories

### `ProofFact`

A `ProofFact` is derived without dynamic observations. Valid sources include closed
binary recovery, a static data-flow proof, a static solver proof and a versioned
contract whose assumptions are in certificate scope. Its premises are other
`ProofFact`s.

### `ObservedFact`

An `ObservedFact` is derived from a concrete trace and carries its trace/execution
identity. It may describe executed targets, addresses, ranges, thread instances and
observed patterns. It is not evidence about unexecuted behavior.

### `DiagnosticHint`

A `DiagnosticHint` correlates Unknowns and observations to propose a likely missing
static capability. It may guide code changes. It is neither proof nor a verdict input.

### `UnknownFact`

An `UnknownFact` records why an obligation is open. It has stable identity, canonical
kind, origin, reason, subject, scope, provenance and supporting context. An Unknown is
never represented by absence, an empty collection, a boolean `False` or an exception
that is silently swallowed.

### Trace check results

A formal solver result over an observed event skeleton is a `TraceCheckResult`. It may
support `TRACE_SAFE`, but it is not a `ProofFact` because its premises contain
`ObservedFact`s.

## 4. Normative rules

### SC-001 — Static proof-only `SAFE`

`SAFE` MUST depend only on `ProofFact`s whose complete premise closure is static and
whose scope matches the certificate. A missing or foreign premise yields `UNKNOWN` or
certificate rejection.

### SC-002 — Trace-bounded `TRACE_SAFE`

`TRACE_SAFE` MUST describe only the concrete trace identity and execution binding in
its certificate. Reports MUST display this limitation.

### SC-003 — Observations never become proof facts

`ObservedFact` MUST NOT be converted, cast, copied or serialized as `ProofFact`.
Static proof premises MUST NOT reference observed evidence IDs.

### SC-004 — Hints never affect verdicts

`DiagnosticHint` MUST NOT change a lattice value, discharge an Unknown, remove a
memory event, select a memory-model relation or enter any verdict constructor.

### SC-005 — Unknown discharge requires proof

An `UnknownFact` may stop blocking a static scope only through an explicit discharge
record that references a valid `ProofFact` and states the affected scope. Merely not
copying an Unknown into a later list is forbidden.

### SC-006 — No-risk screening is not `SAFE`

`NoRiskFound`, an empty heuristic finding set or bounded no-counterexample MUST NOT be
mapped to static `SAFE`.

### SC-007 — Missing observed alias is not `NoAlias`

Failure to observe overlapping addresses MUST NOT produce a static `NoAlias` fact or
remove a static conflict candidate.

### SC-008 — Observed ranges are not affine bounds

Runtime min/max, stride, address range or sample count MUST NOT become a static affine
bound proof. They MAY produce an observed affine pattern and a diagnostic hint.

### SC-009 — Observed thread separation is not static disjointness

Non-overlapping address sets for observed thread instances MUST NOT become a static
`Disjoint` or thread-local proof.

### SC-010 — Unexecuted paths remain in static recovery

Dynamic coverage MUST NOT delete, complete or downgrade an unexecuted static CFG path
or indirect target. An unobserved path MAY be reported as a diagnostic coverage gap.

### SC-011 — Campaigns do not upgrade verdict domains

Any number of `TRACE_SAFE` certificates MUST remain a trace campaign result. There is
no automatic conversion from campaign evidence to static `SAFE`.

### SC-012 — Inputs do not weaken the contract

Changing test, native, `simlarge`, thread-count or other experiment inputs MUST NOT
weaken SC-001 through SC-011. Additional coverage changes observations, not proof
rules.

### SC-013 — Incompleteness propagates explicitly

Resource limits, unsupported operations, incomplete recovery, trace loss, schema
failure and solver timeout MUST produce typed Unknowns or reject the input. They MUST
NOT become an empty result, a skipped obligation or success.

### SC-014 — Certificate binding is mandatory

A certificate is invalid when its executable, loaded-library closure, DBT revision,
contract, analysis configuration or required collection identity differs from the
current subject. Trace certificates additionally bind trace/client/tracer versions,
argv, environment summary, thread configuration and collection completeness.

### SC-015 — Benchmark names have no semantic authority

Benchmark names, suite IDs, source paths and report labels MUST NOT select proof rules,
alias results, event removal, Unknown discharge or verdicts. Benchmark-specific code
belongs only in evaluation manifests and harnesses.

### SC-016 — Removed events require proof closure

Every removed `MemoryEvent` MUST have a `RemovalDecision` referencing a `ProofFact`.
The proof and all its premises must be reachable in the certificate evidence store and
valid for the event's scope.

### SC-017 — Relevant Unknowns are conserved

Every relevant `UnknownFact` MUST either remain visible at verdict construction or
have an explicit valid discharge. Deduplication may coalesce identical payload storage
but MUST preserve every origin and affected subject.

## 5. Required static verdict procedure

The static certificate builder performs these checks in order:

1. validate binary, library, DBT, contract and execution bindings;
2. validate the evidence schema and every referenced evidence ID;
3. verify every removal decision and its proof closure;
4. enumerate all Unknowns relevant to certificate scope;
5. apply only valid proof-backed discharge records;
6. return `UNKNOWN` if any relevant Unknown remains;
7. run the source-versus-target checker on the retained communication graph;
8. issue `SAFE` only for an unbounded structural proof or another explicitly approved
   static proof class;
9. issue `COUNTEREXAMPLE` only with a validated target-only witness;
10. otherwise issue `UNKNOWN`.

The certificate layer does not infer missing proofs from provenance strings or rerun
analysis-specific filtering rules.

## 6. Required trace verdict procedure

The trace certificate builder performs these checks in order:

1. validate trace schema, sequence completeness, dropped-event counters and markers;
2. bind executable, module closure, command, environment, thread configuration,
   DynamoRIO/client versions, analyzer and DBT contract;
3. normalize runtime events and objects without using wall-clock order as guest order;
4. propagate every unsupported or resource-limited operation as trace-scoped Unknown;
5. run the source-versus-target comparison on all retained communication windows;
6. issue `TRACE_SAFE` only when every window closes and no trace-scoped Unknown remains;
7. issue `COUNTEREXAMPLE` only with a validated trace-bound witness;
8. otherwise issue `UNKNOWN`.

Trace analysis never invokes a static Unknown-discharge API.

## 7. Unknown lifecycle

The evidence ledger is append-only for audit purposes:

```text
Unknown produced
  -> propagated with stable ID
  -> classified relevant or irrelevant by a ProofFact-backed scope decision
  -> optionally discharged by ProofFact
  -> visible as unresolved or discharged in the certificate audit trail
```

Required fields for every Unknown are:

```text
evidence_id
kind
originating_analysis
producer_version
reason
subject identity
relevant scope
provenance parents
supporting context
```

`UnknownAffineBounds` additionally identifies the instruction, memory operand,
address expression, abstract object, thread role and the missing lower/upper/induction
component when available.

## 8. Serialization contract

In-memory domain types are authoritative. JSON/YAML is an explicit boundary:

```text
typed domain object
  -> versioned serializer
  -> strict schema envelope
  -> versioned parser
  -> typed domain object
```

Each envelope has an explicit schema family and version. Unknown major versions fail.
Unsupported minor versions fail unless a reviewed migration function exists. Business
logic MUST NOT operate directly on arbitrary decoded dictionaries.

## 9. Certificate verification

Static certificate verification MUST traverse all evidence reachable from `SAFE`:

The executable canonical replay API is `bmo_check_core.certificate.verify_static_certificate`.
It rejects non-`ProofFact` roots, missing removal coverage, omitted or unresolved
Unknowns, bounded `SAFE` results and mismatched certificate bindings. The static
route bridge (`bmo_check_static.proof.certificate_bridge`) is required to invoke this
replay after assembling legacy sidecars; it cannot rewrite a scope or silently drop
an Unknown. The legacy JSON payload remains a compatibility serialization until the
differential migration is complete. The trace API `verify_trace_certificate`
separately checks trace-bound `ObservedFact` roots.

```text
for every reachable evidence node:
    exists
    category == ProofFact
    scope matches
    producer/rule is supported
    all premises recursively pass
```

It also checks that all removed events have valid decisions and no relevant unresolved
Unknown remains. Encountering `ObservedFact` or `DiagnosticHint` rejects the static
certificate.

Trace certificate verification MAY contain `ObservedFact` and `TraceCheckResult`, but
it rejects missing trace bindings, incomplete collection and mismatched closure or DBT
contracts.

## 10. Machine enforcement matrix

| Rule | Type system/model | Schema | Dependency test | Invariant/property test | Certificate verifier |
|---|---:|---:|---:|---:|---:|
| SC-001 | required | required | required | required | required |
| SC-002 | required | required | optional | required | required |
| SC-003 | required | required | required | required | required |
| SC-004 | required | required | required | required | required |
| SC-005 | required | required | optional | required | required |
| SC-006 | required | optional | optional | required | required |
| SC-007 | required | optional | required | required | indirect |
| SC-008 | required | optional | required | required | indirect |
| SC-009 | required | optional | required | required | indirect |
| SC-010 | interface | optional | required | required | indirect |
| SC-011 | required | required | optional | required | required |
| SC-012 | policy | optional | required | property test | indirect |
| SC-013 | required | required | optional | required | required |
| SC-014 | required | required | optional | required | required |
| SC-015 | package ownership | optional | required | required | indirect |
| SC-016 | required | required | optional | required | required |
| SC-017 | required | required | optional | required | required |

`indirect` means the verifier checks the resulting proof closure while the primary
guard is at the producing analysis boundary.

## 11. Mandatory negative tests

The repository must keep explicit failing examples for:

- a `SafeCertificate` whose root is an `ObservedFact`;
- a `ProofFact` whose premise is a diagnostic hint;
- an event removal with no proof;
- a relevant Unknown omitted without discharge;
- a discharge backed by a proof from another scope;
- a campaign incorrectly promoted to `SAFE`;
- a runtime non-overlap incorrectly serialized as `NoAlias`;
- an ambiguous correlation incorrectly marked exact;
- an unsupported schema accepted silently;
- a certificate replayed against a different library or DBT revision;
- a resource-limit path returning an empty successful result;
- a core semantic branch keyed by a PARSEC benchmark name.

## 12. Change control

Changing this contract requires an explicit decision record containing:

- the rule being changed;
- the old and new proof boundary;
- why the change cannot introduce false `SAFE` or `TRACE_SAFE`;
- new negative tests and certificate-verifier checks;
- schema migration and invalidation impact.

Performance, benchmark coverage and reduction in `UNKNOWN` are not sufficient reasons
to weaken a rule.
