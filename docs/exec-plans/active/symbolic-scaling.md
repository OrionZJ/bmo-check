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

Stop after checkpoint 6 and review the report before implementing any slicing
or solver optimization.
