# P18：固定候选环的全窗口求解

Status: completed; stop before P19

## Intent and boundary

P18 investigates why six of the ten frozen SB candidates were `UNKNOWN` in P17.
It does not expand candidate discovery, change the formal checker verdict, or
change the DBT6 `mo-off` memory-model contract. The new query is shadow-only.

The only algorithmic change is to stop asking Z3 to discover an arbitrary
source cycle after graph-first has already supplied one concrete candidate
cycle. The query keeps the complete 3,720-event window and all RF/FR/CO, PPO,
target-acyclicity, Fence, and RMW constraints.

## Phase 0: remote and P17 audit

The read-only check of
`https://github.com/OrionZJ/bmo-check.git` returned:

```text
refs/heads/p16-local-witness-closure
60cd84933c4b19ab8dfef1dacfa05c20177a99ff
```

Both P17 commits `7212f9e` and `60cd849` are ancestors of that remote branch
tip. No fetch, push, or other remote write was performed. The local branch was
ahead of that tip during P18 work; subsequent P18 and replay-fix commits remain
local unless separately pushed.

The P17 source audit found these scope safeguards:

- Progressive rounds add RF sources, FR targets, and overlapping-write
  coherence components to a fixed point. A newly added read brings in every
  full-window RF source even if that addition did not also add a new FR/CO
  event. Regression: `test_thread_span_closure_adds_rf_sources_even_without_new_fr_or_co_events`.
- Only `selected == full_event_ids` is recorded as the full-window query.
  Partial SAT/UNSAT results are diagnostic and do not create blocking clauses
  or close a verdict.
- A local-UNSAT candidate is still sent to the full-window query.
  Regression: `test_local_unsat_candidate_is_still_sent_to_full_window_query`.
- The shared incremental solver builds its base from the complete window;
  candidate assumptions are isolated with `push/pop`. Regression:
  `test_incremental_push_pop_does_not_leak_one_candidate_into_the_next`.
- Same-endpoint relation groups retain exact relation IDs and their OR
  semantics. The complete read-part RF domains, including the initial-write
  option, are not replaced by the relation that happened to appear in a local
  witness.

The audit did find and close a progressive-expansion defect before P18: the
thread-span round could add a read without triggering the old FR/CO-only loop
condition, leaving that read's external RF sources out of the partial window.
`_close_rf_fr_co_dependencies` now iterates RF, FR, and CO expansion to a fixed
point. The full-window P17 result and candidate set are unchanged.

## Fixed-cycle query contract

For each frozen candidate, the P17 query already requires the candidate's
closed ring edges and exact conditional relation groups. P18 validates that
the candidate edge set is one simple cycle, then fixes the source-cycle
selectors to that exact ring. This is a query-shape restriction, not a fixed
RF assignment:

- Every read-part RF variable remains symbolic; the full window has 3,690 RF
  choices.
- A same-endpoint RF/FR/CO group remains an `Or` over its recorded relation
  IDs. P18 does not choose one label merely because graph search merged them.
- The full-window RF, FR, CO, source/target PPO, target rank/acyclicity,
  Fence, and RMW constraints still come from the existing symbolic encoder.
- Only the global search for an arbitrary source-cycle selection is replaced
  by the already supplied closed candidate ring. No event or relation is
  removed, and no target constraint is weakened.

For this candidate interface, the required edge set itself is a closed simple
cycle. Any P17 model satisfying all required edge activations therefore has
that ring available as its source-cycle witness; extra selected cycle
components are unnecessary. Conversely, a P18 model satisfies those same
activations and all full-window constraints, so it is a model of the P17
candidate query. An `UNSAT` result applies only to this exact frozen candidate
query; it does not exclude candidates that were not in the frozen set.

The default `fixed_source_cycle_edges=None` path is unchanged. No P18 result is
passed to the official `SAFE`, `TRACE_SAFE`, `COUNTEREXAMPLE`, or `UNKNOWN`
construction.

## Replay identity correction

P18's first run exposed a replay rejection for two SAT models. The producer
compressed consecutive PPO edges into one `ppo_reachability` edge, but built
`cycle_nodes` from the pre-compression edge sequence. Other paths already
arrived as a summarized PPO edge, so the serialized `cycle_nodes` had two
different meanings. Replay expanded the PPO witness path and compared every
interior event with that inconsistent field.

The canonical meaning is now explicit: `cycle_nodes` lists only the endpoints
of the ordered relation-edge skeleton. PPO witness interior events remain in
`ppo_reachability_path`; replay checks that each path starts and ends at the
declared endpoints and that every path edge exists in the independently
replayed reduced PPO graph. A forged endpoint skeleton is still rejected.

Regressions include:

- `test_replay_accepts_ppo_witness_intermediates_outside_cycle_skeleton`;
- `test_replay_rejects_cycle_nodes_not_matching_ordered_edges`;
- `test_merged_fr_labels_are_all_active_when_target_graph_is_acyclic`.

The P18 query now serializes the complete `CandidateCycleReplay` result, rather
than only its status string, so consumers can distinguish full-window symbolic
validation from execution evidence.

## Frozen inputs and run

All ten P16 candidate IDs were reused. No graph-first candidate search was run.
The final artifact is:

```text
.experiments/p18-20260923-fixed-cycle-10c-30s-v3.json
```

Bindings in the report:

| Input | Bound identity |
| --- | --- |
| Trace ID | `439971d2-bce2-4751-86b7-44d8a38073eb` |
| Trace SHA-256 | `7359683baeddfa60f4bd5a03ad09999aa9d4931e3cf1b76ceb32c1160eca969b` |
| DBT contract SHA-256 | `4efd14f5f1f3370c79226dee235cffdcd0e68da0e6240408d673af8d28b877ba` |
| Window | `window-000000`, 3,720 events |
| PPO certificate digest | `67df97ae0fb36515ec16cbc824a9ce704324a6da37ab0c9322c7c056b8762483` |
| Candidate report SHA-256 | `15b1eb2cc230604952cfedaf7a90c32e61458f6c8c3d843a8c0c7359655aa59a` |

The query timeout was 30,000 ms, formula estimate budget 100,000 terms,
outer worker wall limit 1,800 seconds, and worker address-space limit 8,192
MiB. The run completed in 220.433 seconds with worker peak RSS 835.90 MiB.
The 29,912,663-byte report and its progress/log files remain untracked under
`.experiments/`.

## Results

| Candidate | P17 independent | P17 shared | P17 solver ms | P18 fixed | P18 solver ms | Independent replay |
| --- | --- | --- | ---: | --- | ---: | --- |
| cycle-0000 | UNSAT | UNSAT | 8,524 | UNSAT | 926 | not run (no model) |
| cycle-0001 | UNKNOWN | UNKNOWN | 24,184 | SAT | 1,100 | full-window model validated |
| cycle-0002 | UNKNOWN | UNKNOWN | 55,499 | SAT | 1,211 | full-window model validated |
| cycle-0003 | UNKNOWN | UNKNOWN | 47,558 | SAT | 1,317 | full-window model validated |
| cycle-0004 | UNSAT | UNSAT | 8,502 | UNSAT | 1,221 | not run (no model) |
| cycle-0005 | UNKNOWN | UNKNOWN | 24,031 | SAT | 1,286 | full-window model validated |
| cycle-0006 | UNKNOWN | UNKNOWN | 24,069 | SAT | 1,345 | full-window model validated |
| cycle-0007 | UNSAT | UNSAT | 8,591 | UNSAT | 1,178 | not run (no model) |
| cycle-0008 | UNSAT | UNSAT | 8,394 | UNSAT | 1,166 | not run (no model) |
| cycle-0009 | UNKNOWN | UNKNOWN | 23,899 | SAT | 1,257 | full-window model validated |

All four P17 UNSAT results stayed UNSAT. All six P17 UNKNOWN results became
SAT, and all six complete model snapshots independently replayed as
`FULL_WINDOW_MODEL_VALIDATED`. No query timed out. This is strong evidence that
the dominant blocker for these fixed candidates was the solver's global
source-cycle search, not a lack of a full-window RF/FR/CO assignment for the
specific candidate rings.

The six replay records explicitly leave the following unchecked:

```text
trace-completeness
control-flow-closure
read-value-validation
observed-execution-binding
```

Therefore these are **full-window symbolic models only**. No actual execution
counterexample was established, and P18 did not validate an execution witness.

## Cost comparison

The following compares the same ten P17 independent queries with the ten P18
fixed-cycle queries. Formula construction and Z3 solving are reported
separately; P18 worker wall time also includes trace/window preparation,
certificate replay, witness serialization, and report writes.

| Metric across ten queries | P17 independent full query | P17 shared incremental | P18 fixed-cycle |
| --- | ---: | ---: | ---: |
| Formula term estimate | 64,774/query | 64,774 base | 64,774/query |
| Mean Z3 AST nodes | 317,189 | 317,171 base | 159,051 |
| Mean assertions | 41,313 | 41,308 base | 37,592 |
| Formula construction | 62.600 s total | 6.119 s base + 2.668 s candidate constraints + 2.881 s push/pop | 31.653 s total |
| Solver time | 233.251 s total | 180.006 s total | 12.007 s total |
| Worker peak RSS | not isolated per query | 4,251.97 MiB for the P17 worker | 835.90 MiB for the P18 worker |

P18 cut mean AST size by 49.9%, mean assertions by 9.0%, and the sum of the ten
independent solver times by 94.9% (19.43x lower). Its formula construction
time was about 1.98x lower than rebuilding the ten independent P17 formulas.
P17's shared base still has lower formula-construction cost than P18's ten
independent fixed encodings; P18's gain is in avoiding global source-cycle
search during solving.

The RSS figures are **not a controlled per-query memory A/B**: P17's high-water
mark covers progressive checks plus independent and shared batches, while P18
reports one worker for its fixed-cycle batch. P17 did not preserve isolated
independent-query RSS, and P18's per-query RSS fields are cumulative process
high-water marks. The measured P18 worker stayed below 1 GiB, but this does not
prove a 5x per-query memory reduction.

## Phase 3 decision

P18's fixed-cycle solver completed all ten queries in 0.926–1.345 seconds per
query. The six former UNKNOWN queries now have full-window replay-validated
models. The conditional Phase 3 lazy target-cycle checker is therefore not
implemented: there is no remaining P18 timeout on these frozen candidates to
justify adding a second shadow constraint path.

## Validation and stop point

- Focused graph-first, fixed-cycle, and P17 global-validation tests passed.
- Full suite: **704 passed, 10 skipped**. Skips require DynamoRIO/native build
  inputs or the opt-in real ELF profile.
- `python -m compileall -q src tests` passed in WSL.
- `git diff --check` passed.
- The formal checker, DBT6 contract, and official verdict path were not changed.

P18 is complete for the fixed ten-candidate study. Stop at review; do not start
P19 from this report alone. The remaining work is to decide whether the
fixed-candidate shadow query merits a separate correctness/architecture review
before any integration discussion. Any later integration must still preserve
full-window RF domains, relation-ID OR groups, target acyclicity, and the
execution-evidence boundary.
