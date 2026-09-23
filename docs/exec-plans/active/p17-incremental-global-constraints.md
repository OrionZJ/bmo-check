# P17: Incremental Global-Constraint Validation

## Status and scope

P17 is a shadow-only prototype built on the frozen 3,720-event SB window and
the replay-accepted PPO reduction certificate. The formal checker and its
verdict path remain unchanged. Partial-window SAT/UNSAT results are diagnostic
only and cannot create a safety result, counterexample, or candidate blocking
clause. The work stops at review; it does not start P18.

The fixed candidate set is the ten P16 candidate skeletons. Every experiment
must bind the trace digest, contract digest, PPO certificate digest, candidate
IDs, limits, and exact termination reason. Experiment outputs remain local in
`.experiments/` and must not be committed.

## P16 audit question

Graph-first search merges same-endpoint/same-kind edges and retains all
relation IDs as alternatives. The SMT query requires an `Or` over the exact
relation predicates, while replay validates a concrete model. Tests must
separately inspect:

1. all relation labels carried by a merged candidate edge;
2. the byte-part RF assignments or FR consequences selected by the model;
3. the relation(s) required to close the concrete candidate cycle.

The adversarial fixtures include same-endpoint RF and FR edges for distinct
byte parts. No code fix is made unless a model accepted by the encoder is
incorrectly rejected or an invalid model is accepted by independent replay.

## P17 staged design

### Phase A — fixed baseline

- Re-run the frozen ten P16 candidates after the audit tests.
- Preserve the original trace, contract, certificate, discovery budgets, and
  candidate IDs.
- Capture candidate relation IDs, local event count, RF source-domain size,
  symbolic terms/assertions/ASTs, encoding and solver time, model status, and
  independent replay status.
- Re-run full-window closure for every local SAT candidate with the existing
  per-query limit. A timeout/resource cap remains UNKNOWN.

### Phase B — explicit dependency coverage

Add a separate analysis module with stable records for dependency family,
event/relation identity, coverage status, and explanation. Analyze at least:

- complete RF source domains for candidate reads, including initial writes and
  byte slices;
- FR consequences against every later overlapping write;
- overlap-connected CO ranks and same-thread write order;
- source/target PPO paths, Fence/RMW/synchronization boundaries;
- global target acyclicity and any event that may introduce another RF source.

Use four statuses: `covered`, `not_covered`, `proven_irrelevant`, and
`unknown`. A missing proof is `unknown`, never `proven_irrelevant` merely
because an event is far from the candidate cycle.

### Phase C — progressive diagnostic expansion

Start with candidate-cycle events, then add explicit dependency batches. Each
round records added event/relation IDs, event and constraint counts, formula
size, encode/check time, solver result, unresolved dependencies, and stop
reason. The exact existing symbolic encoder and relation builders must be
reused; no second memory-model implementation is introduced.

Each partial query has an explicit `partial_diagnostic` scope. Partial SAT does
not mean the model extends to the full window. Partial UNSAT does not rule out
the full window because removing events can remove legal RF sources or order
constraints. Only the full event universe plus all required constraints and
independent replay can reach `FULL_WINDOW_MODEL_VALIDATED`.

### Phase D — shared formula / incremental candidate assumptions

Prototype a common full-window symbolic base and apply each candidate's exact
relation groups with Z3 `push/pop` or assumptions. Compare against independent
queries on exhaustively checkable small fixtures; candidate constraints must
not leak between checks. Record base construction separately from per-candidate
assumption construction and solver time. Rebuild the solver after a bounded
number of queries or when memory thresholds are reached.

If an incremental SAT model is not independently replayed, it remains a
solver-only diagnostic and cannot be called validated.

### Phase E — correctness tests

Cover local SAT followed by global UNSAT; local UNSAT with a legal source
outside the reduced scope; partial-byte RF; initial writes; parallel relation
labels; long-distance same-thread order; Fence/RMW/synchronization dependencies;
and candidate isolation under push/pop. Exhaustively enumerable fixtures must
agree with the independent complete check.

Compare the official checker behavior before/after P16 on existing fixtures;
the default checker path must remain unchanged.

### Phase F — bounded frozen-SB A/B

With the same candidate IDs, full window, certificate, and resource caps,
compare the independent full query, progressive diagnostic rounds, and shared
base incremental queries. Report construction time separately from Z3 solve
time, plus peak RSS, included-event ratio, unresolved dependency count, and
termination reason. The number of candidates is fixed; no search-space growth.

## Evidence boundary

Only an exact full-window query over every required constraint, followed by
independent replay, may be labeled `FULL_WINDOW_MODEL_VALIDATED`. That label is
a symbolic model fact, not an execution counterexample. Missing event coverage,
unknown dependencies, solver timeout, formula/resource cap, or unreplayed model
remain diagnostic/UNKNOWN. No experimental result is wired into the formal
checker.

## Final review checklist

- [x] P16 RF/FR audit tests pass; no source fix was needed because the minimal
      merged-byte witnesses confirmed the encoder/replay interpretation.
- [x] Frozen Phase A IDs and bindings match; every query has metrics/status.
- [x] Dependency statuses and progressive-round termination are explicit.
- [x] Incremental queries match independent queries on the frozen workload;
      a small synthetic LB fixture checks the same candidate query and
      push/pop isolation. It is not an exhaustive candidate-space proof.
- [x] Full-window A/B records exact resource limits and termination causes.
- [x] Full `pytest`, `compileall`, and `git diff --check` pass.
- [x] No experiment output, user-owned untracked file, or frozen baseline is
      overwritten or committed.
- [x] Stop at review; do not start P18.

## Execution report

### P16 relation-merge audit

The fixed-endpoint RF adversarial test confirms that a merged edge represents
alternative byte-part relations: the symbolic query may select one matching
part, and independent replay accepts that selection. The FR test confirms that
a one-part FR activation is UNSAT under the target-acyclicity condition, while
the complete small-window model replays. No P16 encoder/replay behavior was
changed for this audit; the two cases are preserved as regressions in
`tests/dynamic/test_graph_first.py`.

### Frozen inputs and Phase A

The corrected run used the same trace, candidate report, PPO certificate, and
DBT contract throughout:

| Binding | Value |
| --- | --- |
| Trace ID | `439971d2-bce2-4751-86b7-44d8a38073eb` |
| Trace SHA-256 | `7359683baeddfa60f4bd5a03ad09999aa9d4931e3cf1b76ceb32c1160eca969b` |
| Contract SHA-256 | `4efd14f5f1f3370c79226dee235cffdcd0e68da0e6240408d673af8d28b877ba` |
| Window | `window-000000`, 3,720 events |
| PPO certificate digest | `67df97ae0fb36515ec16cbc824a9ce704324a6da37ab0c9322c7c056b8762483` |
| Fixed-candidate report SHA-256 | `15b1eb2cc230604952cfedaf7a90c32e61458f6c8c3d843a8c0c7359655aa59a` |

All ten frozen candidate IDs and their relation identities were reloaded. Their
local classifications remained six `FEASIBLE` and four `INFEASIBLE`. The full
candidate baseline retains complete byte-part RF source domains, including the
initial-write option; the candidate set was not filtered by its old local
classification.

### Phase B/C: dependencies and progressive expansion

Each candidate used five recorded stages: candidate core (inventory only), RF
source/overlap closure, FR/CO closure, thread-order/boundary span, then the full
3,720-event window. The first stage did not run SMT. The next three partial
stages produced six SAT and four UNSAT results each; those are strictly
diagnostic. The full-window stage produced four UNSAT and six UNKNOWN results.

The final, full-window dependency inventories contain 74,425 covered entries:

| Dependency family | Entries |
| --- | ---: |
| Candidate core | 10 |
| RF source domains | 36,900 |
| FR later-write domains | 36,900 |
| Coherence components | 590 |
| Source PPO witness paths | 10 |
| Fence/RMW/FUTEX boundaries | 5 |
| Full-window/target-acyclicity closure | 10 |

All final-scope entries are `covered`; this records that the required event and
relation inventory was present in the full-window query. It does not turn a
partial result into proof, nor resolve a solver UNKNOWN. An initial report
iteration misclassified PPO relation IDs as absent because it compared them
only with the RF/FR/CO inventory; the inventory now validates source-PPO IDs
against the certified reduced PPO edges. That classification fix has a
synthetic regression. The superseded report is retained locally and is not used
for the results below.

### Phase D/F: independent versus shared full formula

The final shadow run is
`.experiments/p17-20260923-bounded-global-validation-10c-30s-v5.json`.
It completed with worker exit code 0 in 533.384 seconds and peak RSS 4,251.97
MiB. The worker was limited to 1,800 seconds and an 8,192 MiB address space;
each partial check used a 1,000 ms solver setting, each full check 30,000 ms,
and formulas were capped at 100,000 terms. These are diagnostic limits only.

| Measurement across ten candidate queries | Independent full queries | Shared incremental session |
| --- | ---: | ---: |
| Base formula terms | 64,774 each | 64,774 once |
| Base assertions | 41,313–41,314 | 41,308 |
| Base AST nodes | 317,183–317,204 | 317,171 |
| Encoding/build time | 62.600 s total | 6.119 s base |
| Candidate constraint build | included in each query | 2.668 s total |
| Push/pop overhead | n/a | 2.881 s total |
| Solver time | 233.251 s total | 180.006 s total |
| Results | 4 UNSAT, 6 UNKNOWN | 4 UNSAT, 6 UNKNOWN |

All ten shared results match the independent result. Reusing the base formula
reduced base-encoding time by about 90.2%. Including candidate-constraint and
push/pop construction, summed query work was 295.851 s independent versus
191.674 s shared (about 35.2% lower in this run). Solver time also fell by
about 22.8%, but this is one bounded run and not evidence of a generally faster
solver. The P17 worker's 533.384 s wall time includes progressive checks as
well as both A/B query sets; it must not be compared directly with either
summed query-work number.

Some independent full-query calls took longer than the configured 30,000 ms
solver timeout (maximum observed 55.499 s). The timeout is therefore recorded
as a solver setting, not a hard per-query wall-clock guarantee; the enforced
hard bound for this campaign was the outer 1,800-second worker limit.

### Phase E: correctness and verdict boundary

The full suite passed: **699 passed, 10 skipped**. The skips require the native
DynamoRIO client or the opt-in real ELF profile. The focused checker
characterization suite passed at both the pre-P16 checkpoint `6be15be` and the
current tree: **12 passed** at each. The same assertions cover LB counterexample,
fenced LB SAFE, incomplete-control-flow UNKNOWN, and mixed-width cases.

No candidate produced a full-window SAT model, so no full-window witness replay
was accepted and no execution counterexample was established. The six UNKNOWN
results remain unresolved; the four UNSAT results only close their exact
candidate queries. None of these shadow results changes `SAFE`,
`TRACE_SAFE`, `COUNTEREXAMPLE`, or `UNKNOWN` in the official checker.

### Local artifacts and remaining boundary

The reproducible experiment reports and logs stay under `.experiments/` and are
not versioned. The P17 CLI runs only in WSL/Linux, binds the exact fixed report,
trace, DBT contract, and PPO certificate, and refuses to overwrite output paths.
P17 is complete as a bounded progressive/incremental validation prototype; it
does not yet prove a full-window counterexample for the large SB, and it does
not provide a SAFE conclusion. Stop here for review; P18 is not started.
