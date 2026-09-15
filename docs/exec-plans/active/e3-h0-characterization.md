# E3-H0 — Hybrid evidence binding characterization

Status: complete; characterization only, no production behavior changed

## Scope

H0 records the existing boundary behavior before workflow composition. It does not
change a checker, certificate schema, verdict, contract, or experiment baseline. The
tests use small typed fixtures only; no ELF, benchmark, or trace campaign was run.

## Confirmed current paths

| Route | Current entry and output | Existing diagnostic seam |
|---|---|---|
| Static | `bmo_check_static.application.analyze_with_evidence(StaticRequest)` returns a legacy report plus replayed canonical static certificate, or an explicit canonical error when DBT revision is absent. | `static_snapshot_from_certificate` replays the canonical certificate and exposes its static evidence, scope, verdict, closure and discharge records. |
| Dynamic | `bmo_check_dynamic.application.capture(CaptureRequest)` returns a trace manifest; `analyze(AnalyzeRequest)` independently returns `DynamicCertificate`. | `dynamic_snapshot_from_trace` independently validates and streams the trace into observations and trace-scoped Unknowns. |
| Diagnostics | `build_diagnostic_report(static_snapshot, dynamic_snapshot)` correlates snapshots and preserves the static verdict. | The CLI accepts a saved static snapshot and either a dynamic snapshot or trace; it does not call the static or dynamic analysis services. |
| Affine diagnostics | `build_affine_validation_report` summarizes observations and correlation for `UnknownAffineBounds`. | The `diagnose --affine-output` option writes a second artifact; affine patterns are not fields of the D4 report. |

## Characterized gaps

1. A dynamic certificate stores the launcher manifest's string `trace_id` and a
   trace digest. The diagnostic adapter derives a typed `TraceId` from trace format,
   manifest, module identity and record digest. H0 pins that these are distinct
   identity representations; equality of their string values is not a valid binding
   check. There is not yet a typed bridge that verifies both represent the same trace.
2. Static and dynamic snapshots carry route-local scope strings. The current
   correlator can report `Exact` from matching subject and binary closure even when
   those scope labels differ. This is a site-identity result only, not proof that
   workload, DBT contract or analyzed scope is compatible.
3. The D4 report carries `static_verdict` and `trace_complete`, but no dynamic
   certificate verdict. It therefore cannot distinguish `TRACE_SAFE`, dynamic
   `COUNTEREXAMPLE` and dynamic `UNKNOWN`.
4. The static snapshot preserves discharge records, but D4 currently selects every
   `UnknownFact` node, including one with a valid discharge. It does not yet report
   only the static certificate's unresolved/relevant obligations.
5. E1 affine patterns are emitted through a separate `AffineValidationReport`; users
   must currently join that artifact to D4 by evidence IDs themselves.
6. There is no shared application service that composes the static service, dynamic
   capture/analyze services, route snapshot adapters, diagnostics and E1. The current
   CLI is a file-level adapter over already prepared snapshots/trace data.

## Characterization tests

`tests/contract/test_hybrid_workflow_characterization.py` pins current scope,
report-field, affine-output and discharged-Unknown behavior. The dynamic adapter test
pins the manifest-ID versus typed `TraceId` distinction. These tests are migration
markers: H1–H5 should replace a characterization assertion when the corresponding
typed binding/report behavior is implemented, without changing static proof rules.

An initial sandboxed WSL invocation was denied with `E_ACCESSDENIED`. The configured
WSL environment then ran the focused contract set successfully: `49 passed`. The
repository default suite passed with `386 passed, 10 skipped, 0 failed`. The skips
were the opt-in real-ELF profile and native-capture cases without a built DynamoRIO
client. No workload, ELF profile, or corpus campaign was executed.

## Workflow-service ownership decision

The eventual orchestration owner is a neutral `bmo_check_workflow` application
package, rather than `bmo_check_diagnostics`, `bmo_check_evaluation`, or either route
package:

```text
CLI -> bmo_check_workflow
bmo_check_workflow -> static + dynamic + diagnostics + core
```

The package will only pass typed requests/results between existing services and
adapters. It will not own a second checker, evidence ledger, Unknown registry,
correlator or certificate verifier. Static, dynamic and diagnostics must not import
the workflow package; evaluation remains a workload-manifest and campaign owner.
Update dependency tests and architecture guidance before the package is introduced in
H4.

## Next atomic change

H1 classifies correlation misses conservatively. It must distinguish a complete,
compatible trace with no matching site from closure mismatch, missing identity and
incomplete trace. Until that typed reason is available, a missing observation must
not be labeled `NotExecutedInObservedTrace`.
