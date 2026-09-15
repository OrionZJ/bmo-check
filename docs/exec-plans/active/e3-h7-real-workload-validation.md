# E3-H7 — Real-workload hybrid workflow validation

Status: complete; validation only, no checker or verdict changes

## Intent

Validate that the H6 one-workload command runs the existing static route, captures and
analyzes one dynamic execution, correlates their evidence, and writes a versioned
hybrid report for ordinary ELF inputs. These runs characterize integration and
coverage limits; they do not turn an `UNKNOWN` into `SAFE` or `TRACE_SAFE`.

The frozen E2.5 litmus baseline and 2,595-ELF static measurement were not rerun or
modified. Every manifest used the existing DBT6 `mo-off` contract, application scope,
and the same static provenance budget. No workload name selects analysis semantics.

## Runs and results

The local manifests are under `.experiments/hybrid-workloads/`. Final reports,
certificates, DuckDB files and traces are on E: under
`E:\bmo-check-e3-hybrid\runs\`; they are local experiment artifacts and are not
committed. Each successful command wrote separate static and dynamic certificates and
one `hybrid-workflow-report-v2`; there is no combined verdict.

| Input | Static result | Dynamic result and captured events | D4 correlation: Exact / Ambiguous / Unmatched | E1 affine coverage: exercised / not-executed / unmatched |
|---|---|---|---:|---:|
| Real `SB.exe` | `UNKNOWN`, 462 blocking Unknowns | `UNKNOWN`; 64,169 events, 3 threads; clean process exit, no drops | 131 / 1 / 330 | 28 / 0 / 86 |
| Real `MP+mfence+po.exe` | `UNKNOWN`, 466 blocking Unknowns | `UNKNOWN`; 60,588 events, 3 threads; 5 explicit-fence observations; clean exit, no drops | 134 / 1 / 331 | 31 / 0 / 86 |
| PARSEC canneal, 10-element `10.nets` | `UNKNOWN`, 189 blocking Unknowns | `UNKNOWN`; 1,091,344 events, 5 threads; clean exit, no drops | 82 / 0 / 107 | 13 / 0 / 3 |
| PARSEC blackscholes, `in_64K.txt`, 2 workers | `UNKNOWN`, 81 blocking Unknowns | `UNKNOWN`; 750,000 events, 3 threads; process exited 0, but each thread hit the 250,000-event cap | 4 / 0 / 77 | 4 / 0 / 3 |

For SB, MP+MFENCE and canneal, the trace manifests and dynamic certificates report a
complete collection, but each D4 diagnostic snapshot is incomplete because the loaded
`[vdso]` module has no bound fingerprint. Their dynamic certificates remain `UNKNOWN`
because `application-only scope requires a safe main-module partition`. These are
different completeness checks; a clean process exit does not make the application
partition or D4 snapshot complete.

For blackscholes, the process exits normally and the completion marker is present, but
the manifest records three `resource_limit` markers—one per capped thread. The actual
number of omitted events is unknown; `dropped_events=3` counts the markers, not three
individual missing accesses. Structural trace validation therefore fails closed and
the dynamic result remains `UNKNOWN`.

The H7 rerun exposed an E1 reporting gap: an incomplete diagnostic snapshot could count
an unmatched affine site as `not_executed`. Commit `971b0a9` now requires complete
traces, a matching verified cross-route binding, and a stable site identity before
incrementing that count. All four final reports consequently show zero
`not_executed_count` when their coverage is incomplete or unmatched. `NotObserved`
remains an observation status, never a static proof.

The static blocker mix is still substantial. In canneal the 189 blockers include 66
`IncompleteInstructionFact`, 50 `UnknownEscape`, 42 `UnknownMemoryEffect`, 16
`UnknownAffineBounds`, 8 `IncompleteIndirectTarget`, 6 `UnknownSynchronization` and 1
`UnknownJoinRelation`. In blackscholes the 81 blockers include 66
`IncompleteInstructionFact`, 7 `UnknownAffineBounds`, 3 `IncompleteIndirectTarget`, 3
`UnknownSynchronization`, 1 `UnknownJoinRelation` and 1 `UnknownMemoryEffect`.
D5 classifications remain diagnostic candidates with unresolved causal relations; they
do not discharge any of these obligations.

The litmus harness's own `Allowed`/`Never` output is not a BMoCheck verdict. The
independent herd7 oracle and the fixed-execution correctness baseline remain separate
from workflow diagnostics and static proof closure.

## Storage and reproducibility

The four final H7 output directories occupy about 344 MiB combined on E:. An initial
uncapped blackscholes run produced an incomplete trace of about 24 GB before it was
stopped; that artifact remains on E: and was not copied to D: or deleted. The final
blackscholes run used the explicit 250,000-event-per-thread limit and produced a
bounded report instead of allowing trace growth to continue.

The manifests and reports are local experiment material. They are intentionally not
added to the repository; this record captures the workload parameters, bindings,
results and limitations needed to interpret them.

## Validation and next step

After the E1 guard and its positive/negative regression were added, the full WSL test
suite passed: `438 passed, 10 skipped`. Nine skips require the native-capture test
environment; one is the opt-in real-ELF recovery profile. E2.5 regression files were
not changed.

H7 validates the one-workload integration path, but none of these reports claims a
safe program: every static and dynamic verdict is `UNKNOWN`. The next step is a
separate priority review combining the hybrid diagnostics, canneal evidence and the
frozen 2,595-ELF root-blocker measurement. Select one or two generic static precision
capabilities only after that review. The paused thread/lifecycle E3.1 implementation
does not resume automatically, and policy-parameterized/Box64 support remains deferred.
