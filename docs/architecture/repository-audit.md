# Repository Architecture Audit

Status: current-state record

Baseline: `3375b5f` (`3956a58` contains the latest verifier implementation)

Scope: local repository only; experiment outputs are not architecture inputs

## 1. Executive conclusion

BMoCheck already has two useful safety boundaries:

- `bmo_check_static` and `bmo_check_dynamic` do not import each other;
- static `SAFE` is currently issued only for an unbounded structural proof with no
  relevant `UnknownFact`.

Those boundaries are necessary, and the Phase C closure now adds the missing
certificate boundary: `bmo_check_core` owns typed evidence, stable identities and
static/trace replay, while the static application service must replay a canonical
certificate before returning a revision-bound legacy result. Observations and hints
are rejected by the static verifier rather than separated only by convention.

The legacy report models, open provenance dictionaries and proof text still exist as
compatibility inputs. They are translated at the certificate boundary; they are not
allowed to bypass canonical closure. Dynamic-assisted diagnosis remains a separate
read-only path and cannot modify the static lattice.

The main architectural risk is concentrated in a few orchestration-heavy files.
They recover facts, interpret implicit dictionary protocols, remove Unknowns, build
proofs, select verdicts, and serialize certificates in the same control path. This
works for the current tests but makes every new analysis add another special branch.

The next implementation phase is native producer migration and relation ownership,
not another evidence-model rewrite. Dynamic correlation can consume immutable
snapshots through stable IDs without either analyzer importing the other's internals.

## 1.1 Post-Phase-C implementation delta

On the current `dev` branch, `bmo_check_core` provides stable identities, typed
evidence and separate static/trace certificate replay checks. The static adapter at
`bmo_check_static/adapters/evidence.py` translates legacy events, proof objects and
Unknowns through typed links. `bmo_check_static.application.analyze_with_evidence`
now uses that adapter and the canonical bridge on the real static analyze path;
`analyze` keeps the legacy certificate only as a compatibility serialization.

C6 additionally gives each recovery and analysis producer an opt-in ledger-emission
path. The report bridge preserves all producer Unknowns and only discharges one when
an in-scope ProofFact covers its event. Native producer migration is still a future
cleanup, but it can no longer create an unchecked static SAFE through the application
service.

CFG/indirect-target recovery now has a matching opt-in ledger path. Thread lifecycle,
synchronization recovery now have matching opt-in ledger paths. Memory-event and
memory-event recovery now has a matching opt-in ledger path and stable event links.
Shared-state/escape classification now has a matching opt-in Unknown ledger path;
slicing now has an opt-in ProofFact/RemovalDecision sidecar, and portability has an
opt-in relevant-Unknown ledger sidecar. The canonical bridge consumes the translated
proof/removal sidecar, checks scope and evidence categories, and replays the result
before the legacy verdict is exposed. Legacy JSON remains an adapter, not an
independent proof boundary.

## 1.2 Post-C8 implementation delta

The static and dynamic primary commands now convert their arguments into typed
application requests. PARSEC suite selection, ablations, native-run policy and
per-benchmark resource isolation moved to `bmo_check_evaluation`; the static CLI
keeps only argument adaptation and report rendering. This removes the former
evaluation loop from the CLI, but the route-specific evaluation models remain a
compatibility representation until they are migrated to the evaluation package.

## 1.3 Post-Phase-D implementation delta

The diagnostics boundary is now usable without importing route internals. The
static certificate adapter and the streaming dynamic trace adapter both produce
immutable snapshots; the latter binds module hashes, ELF-relative PCs, operand
identity, indirect targets and trace completeness while retaining bounded
trace-scoped Unknowns. The correlator first uses stable subjects and then a
provenance-location fallback for legacy static Unknowns. D4 reports and D5 root-cause
classifications remain diagnostic-only: they preserve the static verdict and cannot
enter the static proof ledger. Function/block and object/thread-role correlation
remain explicit future extensions because the current snapshots do not carry enough
canonical material to infer them safely.

## 2. Current subsystems

| Subsystem | Current owner | Actual responsibility |
|---|---|---|
| Static binary closure | `bmo_check_static/binary/` | ELF inspection, dependency resolution, module hashes and symbols |
| Static recovery | `bmo_check_static/controlflow/`, `threading/`, `synchronization/` | CFG/call targets, pthread/OpenMP roles, concrete library ordering summaries |
| Static memory analysis | `bmo_check_static/analysis/` | instruction effects, address provenance, escape, lockset, lifecycle and partition analysis |
| Static slicing | `bmo_check_static/slicing/` | conflict candidates, synchronization edges, application scope and proof-carrying event removal |
| Static portability | `bmo_check_static/proof/` | finite memory-model encoding, Unknown collection, verdict and certificate construction |
| Static evaluation | `bmo_check_evaluation/parsec.py` plus `bmo_check_static/evaluation/` adapters | PARSEC manifests, ablations, native comparison and risk screening |
| Dynamic capture | `bmo_check_dynamic/capture/`, `native/` | launch DynamoRIO, collect fixed records, bind modules and report dropped events |
| Dynamic trace ingestion | `bmo_check_dynamic/trace/`, `storage/` | format validation, syscall closure, streaming DuckDB import and object generations |
| Dynamic normalization and slicing | `bmo_check_dynamic/normalize/`, `analysis/` | runtime objects, exact overlaps, lifecycle filtering, application partition and windows |
| Dynamic portability | `bmo_check_dynamic/proof/` | TSO/RVWMO relations, enumeration/Z3 query and candidate validation |
| Dynamic orchestration | `bmo_check_dynamic/pipeline.py` | preflight, storage, resource gates, slicing, verdict choice and certificate construction |
| Reporting and CLI | both package CLIs and dynamic `report/` | command parsing, JSON writing, campaign aggregation and human-readable explanation |

These are real subsystems even where the directory name is only an implementation
accident. In particular, evidence, identity, certificate verification and diagnostics
are not independent subsystems yet.

## 3. Current dependency direction

The top-level package split is currently:

```text
bmo_check_static                 bmo_check_dynamic
       |                                |
       +--------- no imports -----------+
```

Within the packages, the effective directions are less strict:

```text
static cli
  -> binary/controlflow/threading/synchronization
  -> analysis -> slicing -> proof
  -> evaluation

dynamic cli
  -> capture
  -> pipeline -> trace/storage/analysis/proof/model
  -> report
```

The model directories have no backend imports, but they are not a minimal domain
layer. `bmo_check_static.model.__init__` re-exports benchmark/evaluation models, so
every `from bmo_check_static.model import ...` crosses the evaluation namespace even
when the caller only needs `MemoryEvent`.

## 4. Cross-layer access and misplaced ownership

The following dependencies are confirmed architecture leaks, not merely style issues:

1. `bmo_check_dynamic.analysis.partition` imports
   `model.certificate.ApplicationPartitionEvidence`. Analysis therefore depends on a
   certificate payload instead of returning an analysis-domain result.
2. `bmo_check_dynamic.proof.checker` imports `analysis.AnalysisWindow`. The portability
   checker is coupled to the current window builder rather than a stable proof
   obligation interface.
3. `bmo_check_dynamic.pipeline` contains raw SQL, numeric event-kind literals,
   application partition policy, resource fallback, proof invocation, verdict choice,
   and certificate construction. It bypasses the documented rule that only a proof
   boundary owns final verdicts.
4. `bmo_check_static.proof.verifier._collect_unknowns` understands event provenance
   keys, effect-contract strings, application-scope rules, sequential proof reasons,
   and event-removal details. The verdict layer is re-running relevance analysis over
   private encodings from upstream passes.
5. `bmo_check_static.analysis.shared_state` imports angr and Capstone-facing helpers
   while also constructing `ProofObject`s and deciding which events are removed. It
   combines backend access, alias/escape policy, lifecycle policy and proof issuance.
6. `bmo_check_static.analysis.memory_events` combines instruction normalization,
   interprocedural address propagation, function-effect contracts, synchronization
   summaries, Unknown creation and program-order construction.
7. Static PARSEC evaluation models still live under `bmo_check_static.model` even
   though orchestration now lives in `bmo_check_evaluation`; this keeps the legacy
   report schema stable but leaves a documented migration seam.
8. `bmo_check_static.model.evaluation` contains `PartitionHint` and `LifecycleHint`
   alongside core facts. Evaluation inputs can therefore reach analysis through the
   same broad `model` namespace as proof inputs.

## 5. Core concepts with multiple definitions

| Concept | Current definitions | Risk |
|---|---|---|
| Strict serialized model | static `model.common.StrictModel`; dynamic `model.manifest.StrictModel` | validation policy can drift |
| Binary identity | static `ModuleFingerprint`; dynamic `BinaryFingerprint` and trace module TSV | correlation has no canonical module ID |
| Memory event | static `MemoryEvent`; dynamic `TraceEvent` | no typed bridge between instruction operand and runtime access |
| Event kind | separate static string enum and dynamic integer enum | translation rules can diverge silently |
| Object identity | static `SharedObject`; dynamic allocation/mapping generations | no canonical relation between abstract and observed objects |
| Unknown | static typed `UnknownFact`; dynamic `tuple[str, ...]` reasons | dynamic causes cannot be correlated or conserved |
| Verdict/certificate | static and dynamic models | separation is correct, but binding and verification rules are duplicated |
| DBT contract | static config loader; dynamic Pydantic loader | accepted fields and schema policy can drift |
| Source/target ordering | static `proof.encoding`; dynamic `proof.relations/checker` | two memory-model implementations need differential tests or one owner |
| Evidence | static `ProofObject`/string facts; dynamic classes named `*Evidence` | names do not encode whether a fact may enter `SAFE` |

The target architecture should keep static and trace verdicts distinct. It should not
keep two definitions of identity, evidence category, contract binding or memory-model
rules.

## 6. Implicit protocols hidden in dictionaries, strings and booleans

The most consequential implicit protocols are:

- `UnknownFact.details` uses keys such as `event_id`, `event_ids`, `target_symbol`,
  `role` and `expression`. The verifier changes relevance based on those keys.
- `AbstractAddress.provenance` and `MemoryEvent.provenance` encode
  `candidate_bases`, `base_indirect`, `runtime_internal`, `contracted_effect`, call
  arguments, target completeness and address history without a variant type.
- `ProofObject.supporting_facts`, CFG evidence and synchronization evidence are human
  strings. They are not a traversable proof graph.
- `analysis_options: dict[str, object]` carries scope and contract hashes into the
  static verifier.
- Dynamic Unknowns and window results use free-form reasons plus status strings such
  as `safe`, `unknown`, and `counterexample`.
- `ApplicationPartitionEvidence.status` also uses `safe`, although that status is only
  a local trace partition result.
- `complete` booleans appear on manifests, target sets, thread roles,
  synchronization summaries and edges. Each has different prerequisites; callers
  must know the matching reason and evidence conventions.
- Dynamic contract parsing currently allows undeclared YAML fields, while most
  certificate models reject extras.
- Numeric event kinds occur in SQL inside the dynamic pipeline, bypassing the enum.

These values are already APIs. Their schemas are simply undocumented and unenforced.

## 7. Files with excessive responsibility

The largest tracked Python files at the baseline are:

| File | Lines | Responsibility pressure |
|---|---:|---|
| `analysis/address_provenance.py` | 2150 | value lattice, transfer, interprocedural summaries, heap fields and address recovery |
| `analysis/shared_state.py` | 1561 | grouping, alias, escape, lifecycle, locksets, partitions, proof creation and removal |
| `analysis/memory_events.py` | 1405 | normalization, contracts, roles, effects, Unknowns and program order |
| static `cli.py` | 350 | static command parsing, service adaptation and output rendering |
| static `proof/verifier.py` | 600 | Unknown relevance, scope, coverage, verdict, certificate and explanation |
| dynamic `proof/checker.py` | 559 | concrete and symbolic encodings plus witness validation |
| dynamic `pipeline.py` | 477 | all dynamic application-service responsibilities |

Line count alone is not the defect. The defect is that these files own several state
transitions whose invariants are not represented by types.

## 8. Static, dynamic and proof fact isolation

The Phase C boundary now isolates certificate evidence at the type and replay layer:

- `bmo_check_core.evidence` owns frozen `ProofFact`, `ObservedFact`,
  `DiagnosticHint` and `UnknownFact` variants plus the append-only ledger.
- static report events, proof objects and Unknowns receive stable canonical links in
  `bmo_check_static.adapters.evidence`;
- `bmo_check_static.proof.certificate_bridge` rejects observations and hints, checks
  scope, and replays every static certificate through `verify_static_certificate`;
- dynamic snapshots remain trace-bound and cannot enter the static ledger.

The old `ProofObject`, open provenance dictionaries and dynamic `WindowResult` still
exist as route representations. They are compatibility inputs, not canonical proof
nodes. Native producer migration and a shared relation vocabulary remain future work,
but the static application path no longer relies on package convention alone to keep
observations out of `SAFE`.

## 9. Unknown production, propagation and elimination

### Static path

Unknowns are produced by dependency closure, CFG recovery, thread discovery,
synchronization inspection, memory-event recovery, address/escape/shared-state
analysis and the finite checker. They are copied through nested report tuples and
collected again in `proof.verifier`.

`_collect_unknowns` then deduplicates by kind/reason/location and removes some items
when:

- their PC belongs to an event removed by a sequential proof;
- an effect contract is considered to close a call;
- application scope removes a runtime-internal event;
- an Unknown's `details.event_id` or `details.event_ids` points only to removed events;
- an incomplete synchronization edge is considered irrelevant to an empty application
  conflict set.

The surviving set still blocks `SAFE`. At the certificate boundary, report Unknowns
are preserved in the canonical ledger; an Unknown filtered by the legacy scope rules
is discharged only when its event set is covered by an in-scope `ProofFact`. If no
such proof exists, the canonical replay remains unresolved and the application fails
closed instead of silently accepting the legacy filter. Deduplication in the legacy
report still discards differing `details`, which is tracked technical debt for the
future native producer migration.

### Dynamic path

Dynamic Unknown reasons originate in trace validation, syscall effects, storage,
object materialization, communication limits, window construction, solver limits and
candidate validation. They are accumulated and deduplicated as strings in
`pipeline.py`. Early returns preserve the verdict but lose typed origin, affected
event and stable identity.

Dynamic Unknowns are not currently eliminated; a later phase simply avoids generating
one when an alternate path succeeds. That distinction is invisible in the report.

## 10. Current `SAFE` dependency chain

```text
CLI input and contracts
  -> ProgramManifest and binary closure
  -> CFG/call targets
  -> thread roles and concrete synchronization summaries
  -> MemoryEventReport
  -> SharedStateReport with ProofObjects
  -> SharedMemorySlice
  -> optional application-scope removal
  -> legacy verifier Unknown collection/filtering
  -> report adapter creates canonical IDs and proof-backed discharges
  -> canonical static certificate bridge
  -> verify_static_certificate proof-closure replay
  -> legacy PortabilityCertificate compatibility serialization
  -> SAFE only when both verdicts agree
```

If conflicts remain, the current finite checker can find a counterexample but cannot
promote bounded no-counterexample to `SAFE`. That is a sound boundary. The remaining
weak link is the legacy report's non-traversable provenance, which the adapter keeps
visible and the canonical bridge refuses to discharge without an event-covering proof.

## 11. Current `TRACE_SAFE` dependency chain

```text
capture manifest and event files
  -> trace digest and structural validation
  -> supported DBT contract
  -> single-thread shortcut
     OR DuckDB import/object generation
        -> application partition/lifecycle filtering
        -> exact communication edges
        -> bounded windows
        -> TSO/RVWMO inclusion checks
  -> no string Unknown reasons
  -> every WindowResult.status == safe
  -> DynamicCertificate model validation
  -> TRACE_SAFE
```

The trace digest binds the manifest, modules, completion/drop markers and event files.
The certificate exposes executable/library hashes, command, working directory,
contract hash and analyzer version. It does not expose a canonical trace identity,
client/tracer version or DBT revision as typed binding fields, and `explain` validates
only the JSON model rather than replaying those bindings.

## 12. Test coverage versus soundness invariants

Current tests already defend useful invariants:

- static/dynamic packages do not import each other;
- static model files do not import angr, Capstone, ELF tools or Z3;
- only the static verifier constructs `Verdict` values;
- every `SharedStateReport.removed_event_ids` entry has some `ProofObject`;
- incomplete traces, dropped events, resource limits and checker bounds stay Unknown;
- bounded static no-counterexample stays `UNKNOWN`;
- static application `analyze` replays the canonical certificate and compares verdicts;
- report Unknowns remain in the canonical ledger or carry an explicit proof-backed
  discharge;
- implicit legacy operands (`None`/negative index) map to one stable canonical identity;
- static certificate replay rejects observations, hints, missing removal coverage and
  mismatched scopes;
- trace litmus and relation tests compare several source/target ordering cases;
- stale static certificate scope is detected.

The remaining tests are important for the next native-producer and diagnostics work:

- no certificate verifier replays dynamic bindings or rejects foreign evidence kinds;
- no schema migration matrix checks old, current and unsupported evidence versions;
- no test checks that ambiguous static/dynamic correlation remains ambiguous;
- several unit tests import private functions or monkeypatch orchestration modules,
  characterizing the current layout rather than a stable contract.

Passing the existing suite therefore establishes regression compatibility, not the
soundness of the target architecture.

## 13. Extension points that will worsen without refactoring

Adding another analysis today would likely require:

- new keys in `provenance` and `UnknownFact.details`;
- new filtering branches in `_collect_unknowns`;
- new proof text and index-based IDs in `shared_state.py`;
- duplicated static/dynamic memory-model edits;
- more raw status strings in `pipeline.py` and certificate payloads;
- more evaluation hints inside the broad static model package.

Dynamic-assisted diagnosis would be especially unsafe because it would need to read
both packages' private representations and invent correlation rules inside the CLI or
verifier.

## 14. Patch-accumulation indicators

Confirmed indicators include:

- repeated lifecycle, application-scope and effect-contract fallback branches across
  memory extraction, shared-state analysis and Unknown collection;
- magic provenance keys and string status values used as cross-pass protocols;
- proof/object IDs based on sorted enumeration indexes rather than semantic identity;
- separate contract loaders and source/target encodings;
- benchmark-specific concepts in the central model and comments naming particular
  PARSEC failures inside the provenance transfer code;
- a core symbol check for `parsec_barrier_wait`;
- application-specific SQL and numeric event kinds inside the dynamic pipeline;
- schema versions spread across individual models without a repository-level schema
  compatibility policy.

There are no direct `if benchmark == "canneal"` verdict branches. The risk is the
accumulation of generic-looking exceptions whose provenance and removal conditions are
not machine-checkable.

## 15. Handoff readiness

The repository is now ready to hand off the Phase C boundary to a new maintainer:

- README and route-specific documents explain `SAFE` versus `TRACE_SAFE`;
- tests cover many concrete regressions;
- static and dynamic packages are visibly separated;
- the soundness contract names the evidence categories and certificate replay rules;
- the static application path exposes a typed result with the canonical replay;
- checkpoint commits make the current behavior recoverable.

The following are deliberately retained technical debt, not open Phase C criteria:

- native static producers still emit legacy reports before the one-way adapter;
- legacy provenance dictionaries and report-level Unknown deduplication need a
  future typed migration;
- dynamic certificate replay and schema migration need broader negative coverage;
- local experiment artifacts remain intentionally untracked.

The target architecture, soundness contract, migration plan and active phase records
now describe the completed C boundary and the remaining D/E work.
