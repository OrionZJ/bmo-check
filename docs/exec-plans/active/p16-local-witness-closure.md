# P16: Local Witness Closure

## Status and scope

P16 is a shadow-only investigation of graph-first local SMT results. It does not
change the official checker, memory-model verdicts, or certificate semantics.
An accepted local query is not a whole-window result: it must be closed against
the full analyzed window before it can be described as a complete witness.

The frozen reproduction input is the P15 large-SB trace/window, its replayed
PPO reduction certificate, the `dbt6-mo-off` contract, and the same bounded
P15 search/query budgets. Experiment reports remain under `.experiments/` and
must not be committed.

## Local Witness Closure Contract

A witness is independently checkable only when all of the following are bound
to the exact query/window and can be reconstructed without trusting producer
intermediate state:

1. The symbolic-model snapshot is complete, has the expected variable count,
   and its canonical digest matches its serialized variables.
2. The query event set and candidate skeleton are identified. A local query
   covering only a subset of the analyzed window is diagnostic evidence, not a
   complete window witness.
3. Every read part has exactly one RF choice from its complete candidate domain;
   the initial write is a real domain member, not a missing assignment.
4. FR is derived per read part from the selected RF source and all later
   overlapping writes in the relevant coherence order. The initial write may
   induce FR; it does not require a regular source-store event.
5. Coherence ranks form a legal total order for overlapping-connected writes,
   preserve required same-thread store order, and agree with the compact witness.
   Consecutive entries in a total rank order need not overlap; only semantic
   coherence relations require overlap.
6. Source-cycle selectors and target-order ranks satisfy their respective
   contract constraints. Candidate relation labels, RMW adjacency, and the
   source/target bindings are independently checked.
7. A complete-window claim requires the query event set to equal the complete
   analyzed window event universe. Missing constraints, unsupported relations,
   failed decoding, or incomplete coverage remain diagnostic/UNKNOWN.

The full-window closure query uses the same trace, window, reduction
certificate, contract, candidate-required source edges, and bounded symbolic
solver configuration. If the local candidate becomes UNSAT after full-window
constraints are restored, classify it as a spurious local SAT. If closure is
SAT, still require independent replay. A timeout/resource limit is unresolved;
it is neither infeasible nor a witness.

## Replay failure taxonomy

Failures should identify the failed obligation and its witness/model location,
not collapse to a generic rejection. The typed categories are:

- RF assignment incomplete or outside the read-part domain;
- FR/CO inconsistency;
- invalid PPO reachability witness;
- source/target constraint conflict;
- omitted Fence/RMW/FUTEX or other boundary condition;
- trace/window/contract/candidate binding mismatch;
- malformed or digest-invalid witness serialization;
- local model does not close over the full analyzed window.

## Candidate-coverage check

P14 and P15 bounded prefixes are not equivalent merely because they use the
same numeric state budget: their fair seed scheduling can visit a different
prefix. Compare complete candidate sets on exhaustively enumerable small
fixtures, including rotation and alternate PPO witnesses; record unvisited
seeds/frontier on large SB. Never infer semantic equivalence from raw candidate
counts in a truncated prefix.

## Frozen-SB reproduction results (2026-09-23)

The same 3,720-event `window-000000` and replay-accepted reduction certificate
were used for P15 reproduction and closure. Bindings:

- trace digest: `7359683baeddfa60f4bd5a03ad09999aa9d4931e3cf1b76ceb32c1160eca969b`
- DBT contract SHA-256: `4efd14f5f1f3370c79226dee235cffdcd0e68da0e6240408d673af8d28b877ba`
- PPO reduction certificate: `67df97ae0fb36515ec16cbc824a9ce704324a6da37ab0c9322c7c056b8762483`

The fixed P15 query set reproduced as 10 local queries: 6 FEASIBLE and 4
INFEASIBLE. The historical replay rejected all six FEASIBLE models. Five were
rejected because the RF model selected the initial write (`rf_choice = -1`),
but replay incorrectly demanded an ordinary source store overlapping the later
write to validate FR. The sixth had the same FR issue plus a candidate-edge
membership check that incorrectly treated an unrelated RF choice elsewhere in
the local query as if it had to belong to the candidate cycle. These are replay
interpretation bugs, not proof that the six candidates are valid executions.

After correcting those replay rules, all six small-query snapshots pass their
variable-integrity checks but are rejected for the proper reason:
`LOCAL_MODEL_INCOMPLETE`. Each covers only 3 or 4 of the 3,720 window events.
Thus none is a complete execution witness.
All 10 canonical candidate IDs match the saved P15 run exactly, and all six
FEASIBLE candidates now retain complete local symbolic-model snapshots; across
them, 12 read-part assignments select the initial write.

The per-candidate timing capture on the same fixed 10-query set measured local
encoding at 6–62 ms and local Z3 checking at 3–22 ms. Witness serialization
rounded below 1 ms. Obligation materialization took 75–82 ms. Independent replay
took 7.94–8.27 seconds per candidate; that replay includes rechecking the PPO
reduction certificate, so it is not just the cost of reading the RF/CO model.
The four local UNSAT candidates have no SAT witness to construct, but their
candidate replay path still revalidates the certificate.

Each of the six bounded full-window closure queries encoded 64,774 formula
terms and approximately 271k–317k AST nodes. Encoding took 5.44–5.93 seconds;
Z3 then timed out after 24.19–27.73 seconds within the 30-second per-query
budget. All six are `CLOSURE_QUERY_UNKNOWN`: zero became UNSAT, zero produced
an independently replayable full-window witness, and replay was not attempted
because no full-window SAT model was returned. A separate 5-second trial
timed out during formula construction and was not used for the final
classification.

For the bounded search, the same 10 canonical skeleton IDs were reproduced.
P15 visited 4,068 of 7,705 conditional seeds, left 11,757 frontier states, and
stopped at the 10-candidate limit. The search is therefore truncated; the
matching prefix does not prove large-SB candidate-space equivalence. On the
small Synthetic LB fixture, P14/P15 candidate IDs match the independent
bounded enumerator with no missing/unexpected candidates and no truncation.

Experiment JSON and captured models are kept locally at
`.experiments/p16-large-local10-captured.json`,
`.experiments/p16-large-local10-timed.json`, and
`.experiments/p16-large-local10-closed30s.json`; they are not versioned.

## Acceptance and stopping rules

- Synthetic LB must produce a candidate whose full model independently replays.
- The fixed P15 set must reproduce six local FEASIBLE and four INFEASIBLE
  queries before closure classification.
- Every local FEASIBLE must be classified by a bounded full-window closure
  query and independent replay; unresolved results stay diagnostic. In the
  current frozen-SB run, all six remain UNKNOWN due to solver timeout.
- Small-fixture candidate coverage must match an independent bounded exhaustive
  enumerator with no missing/unexpected candidates and no truncation.
- Large-SB candidate coverage must report visited conditional seeds, frontier,
  truncation, and limits; no completeness claim is made for a truncated search.
- Full tests and diff review pass before an isolated P16 commit. No P16 result
  is wired into official SAFE/TRACE_SAFE/COUNTEREXAMPLE verdicts.

The final full regression on this implementation passed: 673 passed, 10
environment/opt-in skips.
