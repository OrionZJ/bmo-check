# E3-H5 — Emit one versioned hybrid report

Status: implementation complete; one-workload CLI and real-workload validation remain
for H6–H7.

## Scope

H5 adds an output adapter at `bmo_check_workflow.report`. It consumes the immutable
`HybridWorkflowResult` from H4 and creates `hybrid-workflow-report-v2`. It does not run
recovery, a checker, capture, correlation, or classification, and it does not create
or discharge evidence.

The report keeps the route results independent:

- `static` contains the legacy static verdict, input scope, recovery/checker coverage,
  canonical certificate identity and replayed ProofFact closure IDs, still-open
  obligations, DBT contract digests sampled immediately before/after static analysis,
  and hashed environment values from the static recovery manifest.
- `dynamic` contains the original trace-bound `DynamicCertificate`, the capture
  manifest summary, content-derived `TraceId`, trace digest, DBT contract digest,
  dynamic checker budgets, capture/snapshot limits, and trace directory.
- `diagnostics` is present only if H4 has a replayed canonical static certificate. It
  retains the D4 `diagnostic-report-v3` and E1 `affine-validation-report-v1` payloads,
  plus a D5 candidate and an explicit unresolved causal status for every static
  blocker.
- `proof_boundary` states that observations and hints cannot enter the static proof,
  discharge Unknowns, or produce a combined verdict.

There is deliberately no top-level verdict. `TRACE_SAFE` remains a statement about
the bound trace; it does not upgrade static `UNKNOWN` to `SAFE`.

## Validation at the report boundary

The report uses frozen, extra-forbid typed models. Reading rejects unknown top-level
or nested report schema versions, undeclared fields, mismatched route verdicts or
trace identities, incomplete cross-route bindings, dangling evidence references,
and D4/E1 coverage counts that disagree with their records. A D4 `Exact` record is
rejected when the binary/contract/scope binding is not a full match. Static proof
closure IDs are checked against both ObservedFact and DiagnosticHint IDs.
The translation-policy status is recomputed from the two recorded static hashes and
the dynamic certificate's DBT-contract digest; a report cannot claim `Match` after
the contract changed during analysis or when the two routes used different bytes.
Static and dynamic argv and environment digests must match as well.

The builder also checks that the supplied static replay refers to the same canonical
certificate and that every closure node is a `ProofFact`. This report is an audit
summary, not a replacement for replaying either route's certificate; loading JSON
does not independently recreate the evidence ledger or prove its listed closure IDs.

Environment values are represented by SHA-256 digests rather than copied into the
report. A digest is not encryption: predictable values may still be guessed. The
trace manifest remains the source artifact containing original capture metadata.
Large trace chunks are not embedded in the report.
The v2 bump adds argv/environment cross-checks, dynamic budget recording, and the
trace-directory locator. Readers reject v1 rather than treating missing fields as
equivalent.

## API

H5 adds these exports from `bmo_check_workflow`:

```python
report = build_hybrid_workflow_report(result)
save_hybrid_workflow_report(report, output_path)
report = load_hybrid_workflow_report(output_path)
```

`hybrid_report_from_dict` and `hybrid_report_from_json` provide the same strict
validation for in-memory input. H6 exposes the H4/H5 path through the generic
`bmo-check hybrid` one-workload CLI; H5 itself does not launch a workload.

## Tests and validation

`tests/contract/test_workflow_report.py` uses synthetic typed route results. It checks
JSON round-trip and save/load, preservation of D4/E1 child payloads, schema and field
rejection, separate static/dynamic verdicts, cross-trace/scope/binary binding,
observation and hint isolation from static proof closure, D5 unresolved-cause
linkage, legacy Unknown presentation when canonical replay is unavailable, and
environment-value redaction.

The focused H5/workflow/dependency suite is:

```text
uv run pytest tests/contract/test_workflow_report.py \
  tests/contract/test_workflow_application.py \
  tests/contract/test_repository_boundaries.py
```

No workload, PARSEC binary, litmus ELF, or frozen 2,595-file corpus was run for H5.
That remains H7 work. H5 changes no static/dynamic checker, memory-model rule, DBT6
contract, verdict semantics, or E2.5 oracle.
