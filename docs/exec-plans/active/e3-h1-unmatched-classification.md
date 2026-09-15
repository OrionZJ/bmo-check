# E3-H1 — Conservative unmatched diagnostics

Status: complete; diagnostic-only behavior change

## Change

An unmatched correlation with no observations now produces `UnknownRootCause` at
zero confidence instead of `NotExecutedInObservedTrace`. The hint rationale preserves
the known reason:

- binary closure mismatch;
- no stable static site identity;
- incomplete trace;
- or no matching site in a complete trace whose workload/scope binding is not yet
  verified.

The existing `CorrelationStatus`, `CorrelationKey`, correlation report schema and D5
registry remain unchanged. This is diagnostic-only; it adds no proof rule and cannot
change the static verdict.

## Why the positive “not observed” classification is deferred

The current static and dynamic snapshots contain route-local scope labels, but no
shared typed binding for workload arguments, selected static/dynamic scope, executable
and library closure, and DBT contract. A complete trace plus an absent PC therefore
does not establish that the trace covered the same analysis scope as the static
Unknown. H1 deliberately leaves `NotExecutedInObservedTrace` unused by the current
snapshot-only workflow. H3 may enable it only after a typed bridge validates the
certificate, trace, closure, contract and scope bindings.

## Tests and acceptance

Contract tests cover closure mismatch, missing stable location, incomplete trace and
a complete trace without verified workload/scope binding. They require an unmatched
record to remain `UnknownRootCause` with zero confidence, while retaining the original
correlation reason. A report-level test checks that a complete trace with no observed
site does not claim that the site was not executed. Focused tests passed: `27 passed`;
the default suite passed: `390 passed, 10 skipped, 0 failed`.

Focused validation command:

```text
uv run pytest -q tests/contract/test_diagnostic_classification.py tests/contract/test_diagnostic_correlation.py tests/contract/test_diagnostic_report.py tests/contract/test_hybrid_workflow_characterization.py
```

No static/dynamic analysis, checker, certificate verdict, E2.5 fixture or experiment
baseline changes. The default-suite skips remain the opt-in real-ELF profile and
native-capture tests without the required native client/environment.
