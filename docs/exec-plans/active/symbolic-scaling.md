# Dynamic symbolic-scaling investigation

## Scope

This work investigates why one complete SB trace forms a 3,709-event
communication window that the dynamic proof encoder cannot finish. The first
phase only characterizes window growth and symbolic formula growth. It must not
change memory-model semantics, verdict meanings, projection rules, or delete
events to make the workload finish.

## Frozen baseline

Baseline branch: `bottleneck/symbolic-scaling`

Baseline commit: `04f4423` (`Model complete mixed-width atomic overlaps`)

The reproducible input is the existing local trace directory
`.experiments/live-litmus-sb-limits100x-20260920`. Its manifest records:

- trace id `439971d2-bce2-4751-86b7-44d8a38073eb`;
- complete capture with zero dropped events;
- 66,579 raw events across three threads (the prior certificate's stored
  event count is 66,581 after two synthetic futex events);
- 3,733 raw communication edges.

The current window builder produces one relevant window with at least 3,709
events when `max_window_events` is raised to 6,400. This is an observed
characterization, not a permission to split the window.

Observed outcomes before this investigation:

| configuration | result |
| --- | --- |
| default window limit | `UNKNOWN`: window contains at least 3,709 events, limit 64 |
| window 4,000, symbolic terms 100,000 | `UNKNOWN`: symbolic formula exceeds 100,000 terms |
| 100x symbolic/solver budgets with external protection | no certificate before the run was stopped |
| no practical external timeout, symbolic terms 10,000,000 | about 15 h 46 min, roughly 6.57 GiB RSS and 13 GiB swap, no certificate; stopped to recover the host |

The last two rows are incomplete runs, not verdicts. They must not be turned
into `SAFE`, `TRACE_SAFE`, or a new `UNKNOWN` reason without a returned
certificate.

## Window characterization checkpoint

The `bmo-check characterize` command now runs the existing trace import,
communication scan, and window builder, then stops before proof encoding. It
uses the same input and configuration as `analyze`, so the report is
observational and cannot change a verdict.

On the frozen SB trace, the report recorded:

- 66,579 raw trace events across three threads; the temporary TraceStore
  materialized 66,581 events because two successful futex waits become
  synthetic `FUTEX_WAIT` memory events;
- 3,733 communication edges, all retained in the scoped edge set;
- one window containing 3,720 events (3,718 memory events);
- 59,060 source-PPO edges and 55,418 target-PPO edges;
- 6,536,166 overlapping event pairs, including 3,739 read/write pairs;
- 3,764 RF candidates, with a maximum of seven candidates for one read;
- no scan incompleteness or window unknown.

Each retained event now carries a diagnostic-only inclusion record. The
current builder distinguishes communication endpoints from ordering-boundary
events (and exposes an explicit `unclassified` value if a future builder path
cannot classify one). These records are provenance for the report only; they
do not authorize removing an event or changing a proof obligation.

The same report now includes a no-AST symbolic encoding estimate for each
window. For the SB window it measured 3,690 read parts, 3,764 RF candidates,
3,817 from-read candidates, 3,969 conditional-edge additions (3,891 unique
edges), and 62,904 cycle edges. The encoder's arithmetic budget was 302,818
initial terms plus 16,397 conditional terms, or 319,215 estimated terms. This
explains why the 100,000-term guard fires before solving; it does not claim
that the Z3 formula is safe to materialize at a larger limit.

## Frozen SB characterization run

The report was regenerated from the complete local trace with the existing
analysis budgets and the `characterize` command. The command stopped after
window construction and arithmetic estimation; it did not write a
certificate, call Z3, or make a verdict. The JSON remains an untracked local
artifact at
`.experiments/live-litmus-sb-characterization-20260921-v3/report.json`.

This closes the initial investigation checkpoint. The observed dominant
costs are now recorded, but no event has been removed and no window has been
split. Any next change must first provide an obligation-preserving boundary
summary and a removal ledger; otherwise the result remains `UNKNOWN`.

The report explains why this input is expensive but does not claim that the
window is safe to split or that the proof has a verdict. The saved JSON is a
local experiment artifact under `.experiments/`.

## P1 graph diagnostics

`WindowDiagnostics.graph` now records the relation graph that was reconstructed
from the existing window contract. Communication, endpoint program-order and
ordering-boundary edges are counted separately; connected components,
biconnected components, articulation nodes, degree percentiles and bounded
top-node/top-address summaries identify hubs without removing any event. The
graph is diagnostic only. It is not passed to `check_window` and an absent
edge in a diagnostic summary is not proof that the relation is absent.

The schema versions are `window-graph-diagnostics-v1`,
`window-diagnostics-v3`, and `window-characterization-v4`. The reconstruction
uses the same endpoint and boundary inclusion records produced by
`build_windows`; hand-built windows without inclusion records are treated
conservatively as having only their explicit communication endpoints.

## P2 obligation-preserving slice contract

`model.slicing` and `analysis.slice_contract` define a typed, diagnostic-only
contract for future slicing. The inventory records event presence,
communication edges, source/target PPO, read-from candidate domains, coherence
domains and ordering boundaries with stable IDs. A `CandidateSlice` must retain
or explicitly account for the complete source event inventory; an approved
removal requires an explicit `proof_fact_id` and a ledger entry. An incomplete
or `candidate-only` object cannot be marked `PROVEN` and is not accepted by the
current checker. This contract records obligations; it does not claim that any
current event can be removed.

## P3 candidate slice report

`bmo-check slice-candidates TRACE --output REPORT` reuses the normal trace
import, communication scan and window construction path. It emits a
`slice-candidate-report-v1` containing the complete source event IDs, the
typed obligation inventory, candidate groups and a removal ledger. The first
candidate heuristic only describes repeated same-thread loads; communication
endpoints are explicitly blocked. Every event remains in
`retained_event_ids`, `removed_event_ids` is empty, and `complete` is false.
The command stops before `check_window`, so the report cannot change a proof
verdict. A future proven slice must satisfy the ledger and obligation contract
before it may be passed to a checker.

## P4 obligation-preserving decomposition

`bmo-check slice-plan TRACE --output REPORT` builds the obligation hypergraph and
uses union-find to find only components whose obligations do not cross a
partition. It never cuts by event count and never passes the proposed partitions
to `check_window`. The report uses `slice-plan-v1`; `NO_SAFE_SPLIT` is returned
when the window is connected by checker obligations, while `SPLIT_PROVEN` only
means that the inventory has independent components and that checker integration
is still pending. Both statuses have `complete=false`.

## P5 validation and regression boundary

Regression fixtures cover a communication hub, mixed-width accesses, a
read-from domain without a precomputed communication edge, incomplete removal
ledgers and the no-proof `CandidateSlice` state. They assert that candidate
reports retain every source event, that mixed-width accesses are not merged by
the heuristic, and that relation obligations prevent an unsafe partition. The
normal `analyze` route remains unchanged; P1--P5 reports are observational and
must not turn a resource-limited or unproved case into a verdict.

### Frozen SB P3/P4 result

On the same complete SB trace, `slice-candidates` found one 3,720-event window
and 125,684 typed obligations. Its largest repeated-load group contained 3,615
loads at one address; all 3,615 were communication endpoints, so the report
proposed zero removals and retained all 3,720 events. `slice-plan` independently
returned `NO_SAFE_SPLIT` with one 3,720-event partition. This is evidence that
the current bottleneck is a connected communication/obligation hub, not a
missing event-count threshold; it is not a verdict about SB.

Large traces and temporary outputs remain local experiment artifacts and are
not versioned by this plan.

## Investigation order

1. Add window-construction diagnostics without changing the returned windows.
   Expose them through the `characterize` application/CLI entry point.
2. Record why each retained event entered a window and report closure growth.
3. Add symbolic-encoding counters and growth statistics without changing the
   formula or solver result.
4. Characterize the frozen SB window and stop for review.
5. Only after the report identifies the dominant source may a separate change
   propose obligation-directed slicing, conservative decomposition, or
   incremental solving. Any such change must preserve a removal ledger and
   return `UNKNOWN` when a boundary summary is not proved.

## Required invariants

- Diagnostics are observational; they cannot alter event membership or edges.
- A missing diagnostic is not evidence that an event or relation is absent.
- No window may be split merely by event count.
- Any future slice must identify the obligation it preserves and record why
  each removed event cannot affect RF, CO, FR, PPO, Fence, RMW, or the target
  cycle query.
- Existing litmus, certificate, and full regression tests must remain green.

## Planned checkpoint commits

1. `chore: preserve large-window solver baseline` (complete)
2. `feat: add window structure diagnostics` (complete)
3. `feat: expose window characterization service` (complete)
4. `feat: record event inclusion provenance` (complete)
5. `feat: add symbolic encoding statistics` (complete)
6. `test: characterize 3709-event SB window` (complete)

The follow-up scaling work is now split into atomic checkpoints:

7. `feat: add relation graph diagnostics` (complete)
8. `feat: define obligation preserving slice contract` (complete)
9. `feat: report conservative slice candidates` (complete)
10. `feat: plan obligation preserving partitions` (complete)
11. P5 adversarial regression fixtures (complete)
12. P6 obligation bottleneck characterization (complete)

The original checkpoint 6 was the review gate. P6 is a second review gate:
`obligation-bottleneck` only reports the relation network and deliberately
stops before `check_window`. No P7 work starts until this report has been
reviewed.

## P6 obligation bottleneck characterization

`bmo-check obligation-bottleneck TRACE --output REPORT` reuses the same trace
import, communication scan and window builder as `analyze`, then emits
`trace-obligation-bottleneck-v1`. It is a diagnostics-only route: it never
creates a solver, changes a window, applies a slice plan, or returns a proof
verdict. A failed preflight or incomplete scan is preserved in `reasons` and
does not become an empty, apparently independent graph.

For every reached window the report contains:

- counts for the typed inventory (`event_presence`, communication, source and
  target PPO, read-from domains, coherence domains, and boundaries);
- derived `from_read` relations using the same read-byte-part/later-write rule
  as the existing symbolic encoder;
- relation and event counts for the largest connected component;
- articulation event IDs, bounded component summaries, and star-expanded graph
  density;
- repeated-load hotspot summaries with RF candidates, from-read exposure,
  source/target PPO internal versus external relations, and communication
  endpoints;
- per-thread and per-address relation contributions.

The graph is an explanatory projection, not a new proof graph. A hyperedge is
expanded as a star around its first stable event ID solely to calculate
connectivity, density and articulation points. `rf_candidate_count` counts
whole-read covering writes; `from_read_candidate_count` counts byte-part
relations and should match `characterize_symbolic_encoding` for the same
window. The distinction is explicit because the symbolic model may split one
read into several overlapping byte parts.

The P6 regression fixture checks those two counts, boundary classification and
that the CLI reaches the report without calling `check_window`. On the frozen
SB trace, the report must be read as a bottleneck characterization only: it can
say which relation families bind the 3,615-load hotspot and how large the
obligation component is, but it cannot justify deleting a load, splitting the
window, or changing `TRACE_SAFE`/`UNKNOWN`. No P7 implementation is included in
this checkpoint.

## P7 cycle relevance characterization

P7 is the next review-gated diagnostic. `bmo-check cycle-relevance TRACE
--output REPORT` records `violation-cycle-semantics-v1` and
`cycle-relevance-v1`, then stops before proof. The semantics object is recovered
from the current finite and symbolic checker rather than from a new model:

- the finite query rejects a target cycle in `target_ppo | communication_relations`
  and requires a source cycle in `source_ppo | communication_relations`;
- the symbolic query constrains `target_rank` over target PPO and conditional
  relations, then selects a non-empty balanced source cycle;
- cross-thread RF, coherence-order and from-read edges are conditional
  communication relations; control-flow closure and value matching are still
  required before a counterexample can be accepted.

Every inventory relation is classified without being removed. Explicit PPO and
from-read edges are `DIRECT_CYCLE_EDGE` unless an alternate PPO path exists;
such edges are reported as `REACHABILITY_SUPPORT` candidates while retaining
the `potentially_transitive_redundant` flag. RF/coherence domains are
`CANDIDATE_DOMAIN_ONLY`; event, communication-endpoint and boundary records are
`ORDERING_SUPPORT`. An unrecognized relation is `UNRESOLVED`. The JSON stores a
bounded sample of per-obligation classifications plus complete class counts.

For each side's PPO graph, the report calculates direct edges, transitive
reachability pairs, transitive-reduction candidates, source-only/target-only/
shared edges, communication-endpoint span relevance, and repeated-load hotspot
contribution. RF, FR and coherence candidates are marked cycle-relevant by an
SCC over-approximation that includes all candidate edges at once; this is a
diagnostic upper bound, not a proof that every candidate occurs in one legal
execution. The same SCC envelope is used only to identify potentially
cycle-capable PPO edges; the separate transitive-reduction result is computed
from the PPO graph alone. The report explicitly labels that estimate and leaves
all checker relations unchanged.

On the frozen 3,720-event SB window, P7 measured:

- primary relation classes: 14,906 direct-cycle relations, 103,389
  reachability-support PPO relations, 3,718 candidate-domain relations, and
  7,488 ordering-support relations; no unresolved relation was observed;
- source PPO: 59,060 direct edges, 6,693,496 reachability pairs, 55,332
  transitive-reduction candidates;
- target PPO: 55,418 direct edges, 153,846 reachability pairs, 48,057
  transitive-reduction candidates;
- source-only/target-only/shared PPO: 3,661 / 19 / 55,399;
- the 3,615-load hotspot contributes 57,841 source and 54,225 target PPO
  edges; 54,224 and 46,995 of those are transitive-reduction candidates;
- RF has 3,764 candidates and FR has 3,817; the SCC diagnostic marks all of
  them potentially cycle-relevant, so this result does not justify RF/FR
  pruning ahead of PPO representation work.
- The purely diagnostic estimate would replace 129,501 explicit relations by
  about 26,112 after removing the two sides' transitive-reduction candidates;
  this number is not a soundness claim and no relation was removed.

The resulting research hypothesis is now explicit but unimplemented:
`full PPO encoding -> cycle-relevant reachability summary`. The large
transitive-reduction estimate supports studying a reachability-summary
encoding before lazy RF/FR generation. A single SB trace cannot establish
cross-workload scalability or soundness; P8 would require a proof-preserving
representation design and independent regression witnesses. P7 ends at this
review point and does not start that work.

## P8 PPO reachability-summary contract

P8 introduces only a shadow representation and a replayable certificate. The
existing checker continues to generate and consume its full source and target
PPO sets. `PpoSemanticContract` records the code-level dependency recovered
from `proof/checker.py`:

- source PPO is an unconditional candidate edge in the selected source-cycle
  query;
- target PPO contributes unconditional rank inequalities for the target
  acyclicity query;
- cross-thread RF, coherence and from-read remain conditional relation edges;
- control-flow closure and value matching remain outside the PPO reduction
  proof and are not weakened by it.

For either side, reachability is summarized only between endpoints that can
connect to a non-PPO relation: communication, RF, FR, coherence, Fence or
RMW. The required set is stored by count and digest with bounded samples, so
the certificate does not pretend that a sampled pair list is complete. A
reduction is eligible only when the independent replay recomputes the original
graph binding, verifies that the reduced graph is an original-edge subset,
checks every removed edge's final witness path, and obtains zero missing,
extra or unresolved relevant pairs. Fence/RMW/FUTEX boundary-incident PPO
edges are protected and cannot be removed by this diagnostic producer.

Fence/RMW/FUTEX events are themselves required reachability endpoints; a
producer may not omit the ordering paths that enter or leave them. The
default producer therefore does not blanket-protect every boundary-incident
edge (which would hide the transitive-reduction question), but replay rejects
any missing boundary endpoint pair.

`PpoReductionCertificate` binds source and target graph digests, semantic
contract digest, removed-edge witnesses and reachability inventories.
`replay_ppo_reduction` reconstructs the reduced graph from the original graph
and certificate; it does not use producer reachability state. The CLI routes
are:

```text
bmo-check ppo-reduction TRACE --output REPORT --certificate CERT
bmo-check ppo-replay TRACE --certificate CERT --output REPLAY
```

The shadow report compares full and certificate-reduced symbolic term
estimates without creating a Z3 formula or passing the reduced graph to
`check_window`. The report and certificate therefore cannot produce SAFE,
TRACE_SAFE or COUNTEREXAMPLE. Missing or unresolved replay facts reject the
reduction and leave the formal checker untouched.

On the frozen 3,720-event SB window, the independently replayed certificate
kept all relevant endpoint reachability pairs:

- source PPO: 59,060 -> 3,728 edges; 55,332 removed edges, 6,693,496 required
  and preserved pairs, zero missing/extra/unresolved pairs;
- target PPO: 55,418 -> 7,361 edges; 48,057 removed edges, 153,846 required
  and preserved pairs, zero missing/extra/unresolved pairs;
- the shadow formula estimate fell from 319,215 to 49,830 terms, a reduction
  of 269,385 terms. This is not a solver result and was not sent to the
  checker.

Large certificates use a digest-bound witness descriptor per removed edge
(path length plus digest); small certificates inline the path. Independent
replay reconstructs the deterministic path from the original/reduced graph
and checks the descriptor, so the producer does not retain tens of thousands
of duplicated long Python tuples.

## P9 shadow solver A/B comparison

P9 adds a diagnostic-only comparison between the existing full-PPO symbolic
encoder and the same encoder supplied with the independently replayed reduced
PPO sets. The two runs share the event window, RF/FR/CO candidate domains,
Fence/RMW/FUTEX relations, source/target queries, solver options and resource
limits. PPO representation is the only semantic input that differs. The
official checker still uses full PPO; no P9 result can produce `SAFE`,
`TRACE_SAFE` or `COUNTEREXAMPLE`.

The route is:

```text
window
  -> PpoReductionCertificate
  -> independent graph replay
  -> full and reduced shadow encoders
  -> optional bounded solver calls
  -> SolverComparisonReport + solver-level certificate
```

`bmo-check ppo-solver-compare` records, for each side, PPO counts, formula
terms, assertion count, asserted AST-node count, build time, solver time, peak
RSS, result and reason. `--encoding-only` builds both assertion sets without
calling Z3. A reduction replay failure leaves both sides `not_run`. A timeout,
`UNKNOWN` or resource limit is recorded as incomplete; it is not reported as a
semantic mismatch. `ppo-solver-replay` recomputes trace/window/contract,
candidate-domain and solver-configuration digests, independently replays the
PPO certificate, reruns both sides and checks the recorded result relation.

The first P9 correctness corpus contains the existing PPO fixtures plus fence,
RMW, FUTEX, mixed-width and RF/FR cases. All 16 targeted tests pass, including
solver-level certificate replay. The full repository regression remains the
required gate before commit.

On the frozen 3,720-event SB trace, the completed encoding-only run measured:

- full PPO: 59,060 source and 55,418 target edges, 334,159 formula terms,
  144,668 assertions, 1,069,733 asserted AST nodes and 19,202 ms build time;
- certified reduced PPO: 3,728 source and 7,361 target edges, 64,774 formula
  terms, 41,308 assertions, 317,171 asserted AST nodes and 5,465 ms build
  time;
- edge reduction was 90.31%, formula-term reduction 80.62%, and measured
  encoding build speedup 3.51x.

`ru_maxrss` is a process high-water mark. Because full and reduced encodings
run sequentially in one process, the two Phase-A RSS fields are not an
independent peak-memory comparison and commonly report the same high-water
value. Future resource experiments must use isolated child processes if peak
RSS reduction is required.

The bounded SB run used identical 30-second and 300,000-term limits. Full PPO
stopped at the explicit resource boundary (302,818 terms); reduced PPO built
the 64,774-term model but Z3 returned `UNKNOWN` for timeout. The comparison is
therefore incomplete (`result_match = null`), not a model mismatch. A separate
30-second reduced-only run had the same timeout. An earlier 1,000,000-term
full run was externally stopped near 1.6 GB RSS before a report could be
produced; it is not a verdict. P9 consequently demonstrates a real reduction
in encoder construction and matching bounded results on the small corpus, but
does not yet demonstrate that the reduced SB model is solver-complete.

P9 stops at this review gate. Formal integration requires a later isolated
solver runner and further bounded A/B evidence; the full-PPO official path and
all verdict semantics remain unchanged.

## P9.5 isolated resource and bounded-scaling measurements

P9.5 remains diagnostic-only and does not enter the official checker. Each
full/reduced point is executed in a fresh Python child process. The child
records wall/user/system CPU, peak RSS, trace/window completion, PPO replay
time, SMT build time, solver time, formula breakdown, constraint breakdown and
variable counts. The parent records process failure separately from a solver
`UNKNOWN`; an external process timeout is never converted into a verdict.

The worker passes the requested budget to the child configuration itself. This
is important because otherwise a 5-second experiment could silently run with
the normal 10-second solver setting. Encoding-only points still use the same
configuration but never call Z3. The new public diagnostic route is:

```text
bmo-check ppo-solver-benchmark TRACE [TRACE ...]
  --phase {encoding,solver}
  --side {full,reduced} ...
```

The report is `solver-benchmark-v1`. `median_*` fields summarize independent
children; formula/constraint/variable maps are medians across repetitions, not
the sum of repeated runs. The four timing regions are exposed as:

```text
trace/window/process preparation = analysis_overhead_ms
PPO certificate replay            = ppo_replay_time_ms
SMT formula construction          = build_time_ms
Z3 solving                       = solver_time_ms
```

The first region includes Python startup and trace import/window analysis; it
is intentionally named overhead rather than being presented as a precise
import-only timer. PPO construction is not rerun in this benchmark: the P8
certificate is replayed and its cost is measured separately.

### Frozen SB encoding-only result

The complete local trace
`.experiments/live-litmus-sb-limits100x-20260920` was run three times per
side in independent processes with the same 1,000,000-term and 60-second
configuration. The valid report is the untracked local artifact
`.experiments/p9.5-sb-20260922-fixed/encoding-report.json`.

| side | median wall | median peak RSS | median SMT build | terms | AST nodes | assertions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| full | 95.917 s | 651.1 MiB | 19.979 s | 334,159 | 1,069,733 | 144,668 |
| certified reduced | 80.745 s | 537.9 MiB | 5.840 s | 64,774 | 317,171 | 41,308 |

The reduced encoding therefore lowers formula terms by 80.62%, AST nodes by
70.35%, assertions by 71.45%, and independent peak RSS by 17.38%. SMT build
time is 3.42x faster in this three-repetition run. Total wall time falls by
less because trace import, window construction and certificate replay remain
outside the SMT build timer.

The formula breakdown shows why the reduction is effective: RF (14,944
terms), FR (15,789), coherence (608) and the base terms (11,160) are
unchanged; source/target PPO terms fall from 236,240/55,418 to
14,912/7,361. Constraint instrumentation shows that the remaining large
family is cycle encoding (74,036 full versus 18,733 reduced), followed by the
unchanged RF/FR ordering families. The reduced model still has 11,292 cycle
edges, 3,690 RF choices and 3,720 cycle nodes. No all-pairs reachability
encoder was added by P9.5.

### Reduced-SB solver budget curve

The reduced frozen SB window was run in separate children at 5, 15, 30, 60,
120 and 300 seconds. The report is
`.experiments/p9.5-sb-20260922-fixed/reduced-scaling-report.json`. The 5-second
point stopped during formula construction; every longer point completed
construction and Z3 returned `UNKNOWN` because its bounded solver timeout
expired. No point produced SAT or UNSAT.

| solver budget | result | build | solver | peak RSS |
| ---: | --- | ---: | ---: | ---: |
| 5 s | encoding timeout | 5.001 s | — | 544.6 MiB |
| 15 s | `UNKNOWN` / timeout | 5.843 s | 9.256 s | 762.8 MiB |
| 30 s | `UNKNOWN` / timeout | 6.093 s | 24.058 s | 805.0 MiB |
| 60 s | `UNKNOWN` / timeout | 5.975 s | 54.183 s | 863.1 MiB |
| 120 s | `UNKNOWN` / timeout | 5.863 s | 114.239 s | 1,134.1 MiB |
| 300 s | `UNKNOWN` / timeout | 5.803 s | 294.332 s | 1,065.2 MiB |

The wall time also includes trace import/window analysis and P8 replay. The
curve is bounded; it is not evidence that the solver would eventually return
UNSAT or SAT with unbounded time.

### Natural workload-size comparison

To avoid treating an arbitrary event-count cut as a proof boundary, the
scaling sample uses two already captured complete SB traces: the small
`.experiments/live-litmus-sb-20260920` trace and the frozen 3,720-event trace.
Both went through the normal importer/window builder and independent P8
certificate replay. The diagnostic report is
`.experiments/p9.5-sb-20260922-fixed/workload-scaling-report-v2.json`.

| trace | side | PPO edges | terms | AST | assertions | peak RSS | SMT build |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| small SB | full | 2,568 | 9,278 | 37,428 | 3,885 | 243.1 MiB | 0.709 s |
| small SB | reduced | 257 | 3,427 | 21,316 | 1,603 | 242.8 MiB | 0.352 s |
| frozen SB | full | 114,478 | 334,159 | 1,069,733 | 144,668 | 645.0 MiB | 20.751 s |
| frozen SB | reduced | 11,089 | 64,774 | 317,171 | 41,308 | 520.4 MiB | 6.190 s |

The PPO edge reduction is stable at about 90.0%/90.3%, while term reduction
grows from 63.1% to 80.6% as repeated-load structure dominates the larger
window. Small-SB RSS is nearly unchanged because process startup and the
small trace dominate; the large trace shows a 19.3% independent-RSS decrease.
The corresponding SMT build speedups are 2.01x and 3.35x. These are shadow
encoding measurements, not formal verdicts.

### P9.5 conclusions and boundary

1. PPO reduction is a real encoding optimization, not only a graph-count
   estimate: it lowers AST/assertion counts, build time and, on the large
   window, peak RSS in isolated children.
2. The remaining SB bottleneck is solver-side. After reduction, RF/FR domains
   remain unchanged and cycle constraints are still the largest instrumented
   family; a 300-second bounded run still returns `UNKNOWN`.
3. No SAT/UNSAT mismatch was found in the P9 correctness corpus, and no
   graph-replay/symbolic-result disagreement was observed. The bounded SB
   runs are incomplete, not semantic results.
4. P9.5 does not justify changing the official full-PPO path, adding heuristic
   pruning, or assigning a verdict to SB. Solver algorithm work (P10) remains
   a separate review-gated task.

The experiments above are local artifacts only. They are not added to Git;
the reproducible commands, report schema and this interpretation are the
versioned research record.

## P10 constraint characterization and graph-first shadow prototype

P10 remains a shadow-only investigation. The official checker still uses the
full PPO representation and no result below is a SAFE, TRACE_SAFE or
COUNTEREXAMPLE verdict.

### Constraint inventory

`SolverConstraintInventory` is attached to every symbolic shadow observation.
It records the variables, assertion families, formula-term categories and a
small dependency map. The dependency map makes the current formulation
explicit:

```text
RF choice -> RF edge -> conditional ordering -> cycle edge -> cycle balance
RF choice -> FR edge -> conditional ordering -> cycle edge -> cycle balance
coherence rank -> CO edge -> conditional ordering -> cycle edge
target PPO -> target rank
source PPO -> source cycle edge
```

The inventory is a characterization of one encoder invocation, not a semantic
proof and not a completeness claim. The profiles used in the experiments are:

| profile | enabled families |
| --- | --- |
| `ppo_fixed_rf` | PPO plus observed-RF fixing; no symbolic RF choice |
| `ppo_rf` | PPO plus symbolic RF choice |
| `ppo_rf_fr` | previous profile plus FR implications |
| `ppo_rf_fr_co` | previous profile plus CO ordering |
| `full` | the existing shadow formulation, including RMW constraints |

`ppo_fixed_rf` is intentionally conservative. It requires known read and
write values for every byte part and records ambiguity; if values are missing,
the profile returns diagnostic `UNKNOWN` instead of selecting a source. The
captured SB traces currently contain no `VALUE_KNOWN` events, so this profile
cannot be interpreted as a completed observed-RF experiment on those traces.

### Reduced-SB ablation result

The frozen large SB trace was run with the same reduced PPO graph, 30-second
child budget, and 1,000,000-term limit. These are diagnostic submodels only:

| profile | terms | AST nodes | assertions | solver result | peak RSS |
| --- | ---: | ---: | ---: | --- | ---: |
| `ppo_fixed_rf` | 33,433 | 0 | 0 | RF unavailable (`VALUE_KNOWN` missing) | 445.5 MiB |
| `ppo_rf` | 48,377 | 215,784 | 33,382 | `UNKNOWN` / timeout | 734.2 MiB |
| `ppo_rf_fr` | 64,166 | 313,852 | 40,914 | `UNKNOWN` / timeout | 822.2 MiB |
| `ppo_rf_fr_co` | 64,774 | 316,396 | 41,215 | `UNKNOWN` / timeout | 817.6 MiB |
| `full` | 64,774 | 317,171 | 41,308 | `UNKNOWN` / timeout | 806.2 MiB |

The important characterization is that `ppo_rf` already times out. Therefore
the first irreducible difficulty in this formulation is the interaction of
symbolic RF choices with global cycle/order constraints; FR increases the
formula and memory footprint, but cannot alone be blamed for the timeout. CO
and RMW add comparatively little at this scale. The fixed-RF row is not a
solver speed result because the trace lacks the observations needed to define
that submodel.

The per-profile JSON files are local experiment artifacts under
`.experiments/p10-*`; they are intentionally not versioned.

### Graph-first candidate-cycle prototype

The new `cycle-prototype` route is a bounded diagnostic path:

```text
window
  -> PPO reduction certificate
  -> independent replay
  -> reduced source PPO + RF/FR/CO candidate graph
  -> bounded SCC/simple-cycle search
  -> induced cycle-local window
  -> shadow SMT with required candidate edges
```

The route refuses to search when the PPO reduction certificate cannot be
independently replayed. It reports the bound, explored states, SCC counts,
relation-family counts, candidate edge labels and local query resources. Each
local query is marked `diagnostic_only`; its `sat_candidate`, `unsat_local` or
`unknown_local` status never enters the certificate or verdict pipeline.

The local query requires the selected candidate edges in the shadow source
cycle. This is a feasibility check for the induced node set, not a proof that
the full window has no other cycle or that the candidate's observed values are
valid. A bounded search limit is reported as `truncated`, never as a negative
result.

Example (small captured SB, encoding-only, two candidates):

```text
event_count                110
source PPO                 1299 -> 119
target PPO                 1269 -> 138
candidate graph edges      608
SCCs / cyclic SCCs         1 / 1
cycles returned            2 (bounded at 2)
local query                65 terms, 60 assertions, 341 AST nodes
formal verdict             none
```

Run it with:

```text
bmo-check cycle-prototype TRACE \
  --reduction-certificate CERT \
  --output graph-first.json \
  --max-cycle-length 12 \
  --max-cycles 32 \
  --max-search-states 100000 \
  --local-timeout-ms 1000 \
  --local-max-symbolic-terms 100000
```

The graph search collapses parallel RF/FR/CO labels with the same endpoint and
relation family for bounded enumeration, and records that collapse in the
report. The underlying symbolic encoder still reconstructs its complete local
candidate domain; this collapse is a search bound, not an event or relation
deletion from the official checker.

### P10 conclusion and review boundary

1. RF choice plus global cycle/order constraints is the smallest tested
   profile that reproduces the reduced-SB timeout.
2. FR materially expands the conditional ordering and cycle encoding, but the
   current data does not justify claiming FR is the primary cause.
3. The graph-first prototype separates bounded candidate-cycle discovery from
   local SMT feasibility and provides the next algorithmic experiment without
   changing formal semantics.
4. No reduced PPO, ablation result or local SAT/UNSAT result is used by the
   official checker.

P10 stops here for review. The next decision is whether to prototype a
   formally replayable graph-first/CEGAR refinement algorithm; it must retain
   the full proof path as the reference and must not turn a bounded candidate
   search into SAFE.

## P11 graph-guided candidate cycles and local feasibility shadow

P11 is implemented as a diagnostic-only prototype. It does not replace the
official full-PPO checker, does not alter `SAFE`, `TRACE_SAFE`,
`COUNTEREXAMPLE` or `UNKNOWN`, and never treats a bounded search that found no
cycle as evidence of safety.

### Candidate and may-graph contracts

`CandidateViolationCycle` is deliberately narrower than an arbitrary graph
cycle. A candidate must contain at least one source PPO reachability summary
and one conditional memory relation (`rf`, `fr` or `coherence`). The PPO part
is represented by a witness path in the certified reduced source graph; the
conditional part retains stable relation labels. A cycle made only of
conditional relations is not emitted because it would be present on both
source and target sides and cannot express a source/target ordering
difference.

`MayViolationGraphContract` defines the over-approximation used by P11:

```text
source reduced PPO (must reachability)
    + cross-thread RF candidates
    + FR candidates
    + overlapping-write CO candidates
```

Parallel labels with the same topology edge are collapsed only for bounded
graph traversal; all labels are retained in the edge and the local RF domain.
Same-thread RF is omitted for the same reason it is omitted from the existing
symbolic conditional-edge builder: it is not a cross-thread communication
edge in this checker. A missing candidate relation is therefore an
`UNKNOWN`/replay failure, not a negative proof.

PPO reachability is queried lazily by `_ReachabilityOracle`. The search first
localizes SCCs, then alternates conditional edges with certified PPO paths.
It never materializes the all-pairs PPO closure and never enumerates all
simple cycles. Search limits are recorded in `CandidateSearchLedger`; when a
limit is reached `not_explored_count` remains `null` and `search_truncated`
is true. Encoding-only runs record `not_run_count` separately from local
`UNKNOWN`, so an intentionally unstarted query is never reported as an
infeasible candidate.

### Local obligations and independent replay

For every candidate, `LocalCycleObligationSet` records:

* selected RF labels and the complete RF candidate domain for each selected
  read;
* required FR and CO labels;
* every PPO witness path;
* fence/RMW/FUTEX boundary events;
* whether the RF exactly-one domain was retained.

The local shadow encoder receives required source endpoints for both PPO and
conditional edges. Its result is only `FEASIBLE`, `INFEASIBLE` or `UNKNOWN`
inside `GraphFirstLocalQuery`; these labels are not verifier verdicts.

`replay_candidate_cycle` is an independent consumer. It replays the PPO
certificate, checks the source/target bindings, verifies witness paths and
cycle closure, checks RF candidate identity and exactly-one coverage, derives
FR from the selected RF plus the witness CO order, validates CO acyclicity,
and checks target acyclicity. A producer-supplied witness or domain that does
not pass those checks is rejected. A local `UNSAT` creates only an exact
candidate blocking record; it does not remove other candidates.

### Small-corpus validation

The synthetic LB fixture now exercises a source-only PPO cycle. The local
query returns `FEASIBLE` and independent replay returns `accepted`, while the
report remains `diagnostic_only`. Additional tests tamper with a PPO witness
and with the RF domain; both are rejected by the independent consumer.

On the complete small captured SB trace, a fresh certificate-bound run with
two candidates produced one may graph of 110 events and 608 topology edges,
one cyclic SCC, and two bounded local candidates. Both candidates were
reported `INFEASIBLE` within the local budget and therefore had no witness;
the ledger records this as local candidate elimination, not `SAFE`.

### Large-workload boundary

The frozen large SB window is only a bounded experiment target for P11. The
first implementation records may-graph/SCC/candidate-search statistics and
uses per-candidate local time and term budgets. It does not run an unbounded
cycle enumeration or unbounded Z3 query. A future large run must report:

```text
may graph nodes/edges and SCCs
generated skeletons and search truncation
local FEASIBLE/INFEASIBLE/UNKNOWN counts
replay acceptance count
peak RSS and wall time
```

No such bounded diagnostic result can create a certificate or a formal
verdict. P11 is complete only as the graph-first/replayable shadow boundary;
CEGAR and complete candidate-space coverage remain P12 work.

## P11.5 PPO certificate generation and replay scalability

P11.5 keeps the P8 reduction contract and official full-PPO checker unchanged.
It adds a `ppo-certificate-profile` diagnostic route, a deterministic
`PpoReachabilityIndex`, shared witness-path/hash construction, and a separate
non-trusted cache artifact. A cache is usable only after the current graph is
bound to the cache key and the existing independent replay accepts the cached
certificate. A cache miss, stale key, corrupt JSON/digest, or replay mismatch
is never treated as a reduction success.

The cache key binds:

```text
trace digest
window digest
event-set digest
source PPO digest
target PPO digest
DBT contract digest
reduction algorithm version
required-pair inventory digest
PPO semantic contract digest
```

The current algorithm version includes the shared witness index, so certificates
created by the pre-index witness strategy cannot be silently reused.

### Frozen large-SB stage profile

The profile was run on the same complete 3,720-event SB window used by P9--P11
with a bounded 300-second external limit. The resulting certificate and its
independent replay both had `accepted=true`.

| stage | wall time |
| --- | ---: |
| window reconstruction (actual `build_windows`) | 6.73 s |
| full PPO generation | 1.05 s |
| reduced PPO computation | 6.35 s |
| required reachability inventories | 11.94 s |
| witness generation (before shared index) | 74.81 s |
| witness generation (shared index, final run) | 37.03 s |
| digest/serialization | 0.26 s |
| independent replay (before shared index) | 59.11 s |
| independent replay (shared index, final run) | 15.44 s |

The final profiled process peak RSS was about 331 MiB. Stage RSS fields report
that cumulative process peak (not an additive per-stage allocation), so they
must not be summed.

The optimized run produced the same graph sizes as P8/P9:

```text
events                 3720
source PPO             59060
target PPO             55418
replay                 accepted
witness records        103389
logical witness nodes  99815233
```

The logical path-node count remains high because the certificate still binds a
digest and length for every removed edge. The improvement comes from traversing
each source's reduced graph once and sharing parent/hash state across its target
edges; it does not delete events or weaken witness checking. The replay uses a
fresh index and recomputes the same path digest/length, rather than trusting the
producer's index or cache.

The profile also records repeated inventory queries. On the large window the
required-inventory stage observed 13,720,724 repeated source queries and
7,001,188 repeated pair queries; these are characterization data, not a license
to omit inventory entries. They identify the next possible optimization target
after the witness bottleneck.

### Cache and reproduction commands

Cold generation can save one cache file per window:

```text
bmo-check ppo-certificate-profile TRACE \
  --dbt-contract specs/dynamic/dbt6-mo-off.yaml \
  --max-window-events 100000 \
  --cache-dir .experiments/ppo-cache \
  --output profile-cold.json
```

Repeating the command reports `cache_status=hit` only after binding checks and
independent replay. `miss`, `stale`, and `corrupt` statuses remain explicit in
the report. The cache files and large profile JSON are experiment artifacts and
are not versioned.

On the frozen large SB, the warm run reported `cache_status=hit`, the same
certificate digest, and `replay_accepted=true`; its `stages` array is empty by
design because generation was skipped, while the cache loader still ran the
independent replay. A bounded `cycle-prototype` launched from that replayed
certificate reached the real 3,720-node may graph:

```text
may graph edges       11433 (source PPO 3728, RF 3736, FR 3817, CO 152)
SCCs / cyclic SCCs    1 / 1
largest SCC            3720 nodes / 11433 edges
search states          10000 (configured bound)
candidate cycles       0 returned; search_truncated=true
formal verdict         none
```

The zero returned candidates is an incomplete bounded search, not a SAFE or
counterexample result. It confirms that a replayed certificate can now start
P11 graph-first analysis reproducibly; it does not justify entering P12 or
claiming the large workload is solved.

P11.5 therefore closes the certificate production/replay scalability boundary,
but it does not make the global solver complete. The reduced SB solver remains a
bounded shadow experiment, and P12 CEGAR is still a separate reviewed decision.

## P12 bounded CEGAR candidate refinement (diagnostic-only)

P12 adds `cegar-prototype` as a separate shadow route.  It keeps the
official full-PPO checker, the P8 reduction contract, and all formal verdict
semantics unchanged.  The route is intentionally unable to emit SAFE,
TRACE_SAFE, or COUNTEREXAMPLE.

The route records a `CandidateSpaceProfile` before local SMT queries.  It
counts raw search states, generated and canonical skeletons, duplicate
skeletons, RF-assignment variants, candidates that differ only in PPO witness
paths, local queries, semantic blocks, repeated infeasible cores, branching,
and depth.  `CanonicalCycleSkeleton` rotates a directed cycle to a stable
identity, keeps RF/FR/CO labels, and omits internal PPO witness paths.

An UNSAT local query can produce a `CandidateBlockingConstraint` only when its
assumptions pass an independent obligation/domain replay.  TIMEOUT and UNKNOWN
never create a block.  RF/CO/FR assumptions are semantic subsets, so an
infeasible combination can prune another PPO-witness variant without merging
different RF or CO choices.  Every block records the source query digest and
is retained in the `CegarSearchLedger`.

The ledger exposes four non-verdict states: `COMPLETE`, `INCOMPLETE`,
`UNKNOWN_REMAINS`, and `TRUNCATED`.  `COMPLETE` means only that the bounded
candidate generator was exhausted; it is not a SAFE proof.  A replay-accepted
local feasible candidate is evidence for later investigation, not a formal
COUNTEREXAMPLE.  The CLI supports independent bounds for search states,
generated candidates, local queries, local timeout, and symbolic terms:

```text
bmo-check cegar-prototype TRACE \
  --output cegar.json \
  --max-search-states 10000 \
  --max-local-queries 1000 \
  --max-generated-candidates 100000
```

P12 stops at this diagnostic boundary.  A future completeness/CEGAR phase
must first establish candidate-space coverage and replay all blocking facts
before any formal checker integration is considered.

## P13 candidate canonicalization and blocking A/B (diagnostic-only)

P13 compares three bounded routes with one replayed PPO certificate and the
same cycle-length, search-state, local-query, and local-timeout budgets:

```text
P11_RAW                 original graph-first search
P12_CANONICAL           canonical skeleton deduplication only
P12_CANONICAL_BLOCKING  canonicalization plus replayed UNSAT blocking
```

The comparison is implemented by `analysis/cegar_experiments.py` and exposed
for a real trace as:

```text
bmo-check cegar-ab TRACE --reduction-certificate CERT --output REPORT.json \
  --max-search-states 10000 --max-local-queries 100
```

The report separates certificate preparation/replay from search time and
records generated/unique/duplicate candidates, RF/PPO-witness variants,
local-query outcomes, blocking counts, truncation, and diagnostic RSS.  The
in-process API explicitly marks its RSS as non-isolated; production resource
comparisons must use independent workers.  The existing isolated worker
harness now has a regression test that treats an external timeout as
`process_timeout`, never as a completed result.

Every blocking record is bound to the candidate digest, local obligation
digest, semantic-context digest, source query digest, and a fixed proof scope.
`replay_blocking_constraint_detail` reconstructs these fields independently.
Only an explicit `unsat` result can create a block; timeout, `unknown`, and
encoding-only queries never create pruning information.

Small-fixture reports are local artifacts:

```text
.experiments/p13-synthetic-lb.json
.experiments/p13-small-sb.json
```

The synthetic LB run (100 DFS states, 8 local queries) produced 2 raw
candidates.  Canonicalization reduced them to 1 and therefore reduced local
queries from 2 to 1; the candidate is feasible and remains diagnostic-only.
The independent bounded enumerator found the same one canonical candidate,
with no unresolved query or invalid block.  The small SB fixture has no source
PPO under the current DBT contract, so all three modes correctly produced an
empty candidate set; this is an observed model boundary, not a SAFE result.

The large-SB reports are generated with the frozen 3,720-event trace and the
P11.5 certificate.  A 1,000-state encoding-only run is stored at
`.experiments/p13-large-1000-encoding.json`; all three modes reached the same
state bound before producing a candidate, so no canonicalization or blocking
benefit can be inferred at that bound.  The 10,000-state run is kept separate
and remains bounded.  Its measured search rows were:

| mode | states | generated | unique | local queries | blocked | status | search ms |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| P11 raw | 10,000 | 0 | 0 | 0 | 0 | truncated | 15,713 |
| P12 canonical | 10,000 | 0 | 0 | 0 | 0 | truncated | 13,790 |
| P12 canonical+blocking | 10,000 | 0 | 0 | 0 | 0 | truncated | 13,954 |

The rows all stop before a candidate is emitted, so the zero duplicate/block
counts are not evidence that the mechanisms are ineffective.  Because these
three rows were intentionally run in one process, the reported 2,314 MiB RSS
is a shared high-water mark, not a per-mode comparison; an isolated-worker
measurement is required before drawing a memory conclusion.  Neither bound
produced a local SMT result or a verdict.

P13 does not change the official full-PPO checker, reduced-PPO shadow
semantics, or any verdict.  Candidate coverage is marked complete only when
the independent bounded enumeration agrees with the normalized set, no local
query is unresolved, and every block replays.  Search truncation, missing
candidates, or any `UNKNOWN` leaves the coverage result incomplete.

## P14 candidate discovery and coverage (diagnostic-only)

P14 adds a fair, structured candidate-discovery scheduler without changing
the may graph, PPO certificate, local memory-model encoding, or official
verdict.  The scheduler starts from RF/FR/CO conditional edges and uses the
certified PPO reachability oracle as a summary edge.  Its round-robin frontier
keeps unvisited seed states explicit; a bound therefore reports `TRUNCATED`
and a remaining frontier instead of treating omitted candidates as absent.

Each graph-first report can carry a `CandidateDiscoveryProfile` with the
conditional seed count, visited seeds, reachability queries/cache hits, path
expansions, rejection reasons, generated/unique skeletons, and frontier size.
`--discovery-only` records this profile without constructing local SMT
queries.  The normal path still performs the same local shadow query and
independent replay as P11/P12.

P14.1 used two explicitly named regression inputs:

* `captured-sb-p11-baseline` is the real 110-event ELF trace from
  `live-litmus-sb-20260920`, with the current certificate digest
  `e0203462...`; under the P11-like bound it produces the same two canonical
  skeleton IDs in `P11_RAW`, `P12_CANONICAL`, and
  `P12_CANONICAL_BLOCKING`.
* `synthetic-sb-p13-fixture` is the four-event hand-written store/load fixture
  used by the earlier P13 script.  It has no source PPO under the current
  contract and therefore intentionally has an empty candidate set.  It is not
  interchangeable with the captured ELF case.

The fair scheduler may expose a different *bounded prefix* on the captured
trace: with two or 100 candidate slots it finds valid shorter
PPO-reachability skeletons before the depth-first baseline reaches the same
conditional choices.  The report records these IDs under
`candidate_set_differences` and leaves the comparison incomplete; it does not
call this a semantic mismatch or claim coverage.  This was diagnosed as a
search-order/bound effect with the same trace and certificate digest, not an
input or contract drift; forcing the prefixes to match would hide the
unexplored frontier.  On Synthetic LB the
structured set agrees with the independent enumerator (missing/unexpected
IDs are empty); encoding-only coverage remains incomplete because no local
query was run.

The reproducible CLI is:

```text
bmo-check cegar-ab TRACE --reduction-certificate CERT --output REPORT.json \
  --include-structured --max-search-states 10000 --max-local-queries 100
```

For per-mode RSS, `scripts/run_p14_isolated_ab.py` launches one worker per
mode and parses `/usr/bin/time -v`.  A worker timeout, OOM/termination, or
missing report is retained as an incomplete resource result; it is never
converted to a verdict.

The first frozen-SB measurements (discovery-only, 3,720 events) were:

| bound | mode | states | candidates | local queries | peak RSS | remaining frontier |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1,000 | P11 raw | 1,000 | 0 | 0 | 629.6 MiB | not exposed by legacy path |
| 1,000 | P12 canonical | 1,000 | 0 | 0 | 637.5 MiB | not exposed by legacy path |
| 1,000 | P12 blocking | 1,000 | 0 | 0 | 648.8 MiB | not exposed by legacy path |
| 1,000 | P14 structured | 1,000 | 53 | 0 | 5,789.1 MiB | 108,458 |

The structured row demonstrates why fair discovery must remain diagnostic:
it reaches conditional candidates early, but retaining a large unexplored
frontier is expensive.  A 10,000-state P12 worker reached its bound at about
2.3 GiB RSS.  Raw 10,000- and 100,000-state preflights were stopped by the
external resource guard before a report was written; the structured 10,000+
state run was not repeated after that guard fired.  Those missing runs are
recorded as resource-limited, not as empty candidate spaces.
No P14 result changes SAFE, TRACE_SAFE, COUNTEREXAMPLE, or UNKNOWN.
