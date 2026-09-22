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
