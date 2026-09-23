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

- [ ] P16 RF/FR audit tests pass; any source fix has a reproducer.
- [ ] Frozen Phase A IDs and bindings match; every query has metrics/status.
- [ ] Dependency statuses and progressive-round termination are explicit.
- [ ] Incremental queries match independent queries on exhaustive small cases.
- [ ] Full-window A/B records exact resource limits and termination causes.
- [ ] Full `pytest`, `compileall`, and `git diff --check` pass.
- [ ] No experiment output, user-owned untracked file, or frozen baseline is
      overwritten or committed.
- [ ] Stop at review; do not start P18.

## Execution report

Results will be appended here as each phase completes.
