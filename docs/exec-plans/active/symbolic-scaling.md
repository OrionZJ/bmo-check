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
- 66,581 events across three threads;
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

- 66,579 imported events across three threads;
- 3,733 communication edges, all retained in the scoped edge set;
- one window containing 3,720 events (3,718 memory events);
- 59,060 source-PPO edges and 55,418 target-PPO edges;
- 6,536,166 overlapping event pairs, including 3,739 read/write pairs;
- 3,764 RF candidates, with a maximum of seven candidates for one read;
- no scan incompleteness or window unknown.

The report explains why this input is expensive but does not claim that the
window is safe to split or that the proof has a verdict. The saved JSON is a
local experiment artifact under `.experiments/`.

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
4. `feat: record event inclusion provenance`
5. `feat: add symbolic encoding statistics`
6. `test: characterize 3709-event SB window`

Stop after checkpoint 6 and review the report before implementing any slicing
or solver optimization.
