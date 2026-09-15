# E3-H4 — Compose existing route services

Status: implementation complete; one-workload CLI/report remain for H5–H6

## Service boundary

`bmo_check_workflow.application.analyze_workload` accepts one typed
`HybridWorkflowRequest`. The request contains the existing `StaticRequest`, dynamic
capture locations and limits, one trace output directory, and a `DynamicConfig`.
The service derives the capture command, arguments and environment from the same
static request; it does not accept a second independently editable workload command.

The service calls the routes in this order:

```text
static analyze_with_evidence
    -> static certificate snapshot adapter, when a canonical certificate exists
    -> dynamic capture
    -> dynamic analyze
    -> certificate-to-trace binding adapter
    -> D4 diagnostic report
    -> E1 affine observation report
```

The dynamic binding adapter reopens the captured trace, so H4 also compares its
verified manifest with the manifest returned by capture. A changed manifest fails the
workflow instead of allowing observations from another artifact to join the result.
If the static application result has no replayed canonical certificate, H4 still
retains the static result and completes the dynamic route; it returns no cross-route
diagnostic products and records the static service's explicit reason.

## Cross-route binding

The workflow fills the existing typed `CorrelationBinding` from three checks:

- `binary_closure`: compare the static and dynamic snapshot closure IDs. Missing IDs
  are `Unverified`; different IDs are `Mismatch`.
- `translation_policy`: hash the DBT contract before and after static analysis, then
  compare the unchanged hash with the hash bound by the dynamic certificate. A file
  changed during static analysis is `Unverified`; different static/dynamic bytes are
  `Mismatch`.
- `analysis_scope`: compare the static snapshot scope with the dynamic certificate's
  `full` or `application` scope.

The existing correlator turns any mismatch into `Unmatched`, and any unverified
dimension prevents `Exact`. This check is about whether observations may be joined to
the static sites; it does not alter either route verdict. Capture, analysis, I/O and
binding failures raise a stage-labelled `HybridWorkflowError`. A route-level resource
limit or incomplete trace remains that route's ordinary typed `UNKNOWN` result.

## Tests and validation

`tests/contract/test_workflow_application.py` stubs the native/route boundaries and
checks service order, shared workload arguments/environment, exact binding, scope
mismatch, contract mutation, missing static canonical certificate, and explicit
capture failure. The focused workflow and architecture tests pass `12` cases; the
full default suite passes `410 passed, 10 skipped, 0 failed`.
`tests/contract/test_repository_boundaries.py` prevents workflow from importing
analyzer internals, evaluation or CLI, and prevents routes, diagnostics, core and
evaluation from importing workflow.

No DynamoRIO workload, PARSEC program, litmus ELF or corpus campaign was run for H4.
The real-workload validation remains H7. H4 adds no analyzer, memory-model rule,
certificate verdict path or Unknown discharge route.
