# E3-H6 — One-workload hybrid CLI

Status: implementation complete. H7 real-workload validation is complete; see
`e3-h7-real-workload-validation.md` for run results and limits.

## Intent

Let a user provide one ordinary x86-64 ELF workload and receive the existing static
result, one trace-bound dynamic result, the cross-route diagnostics, and a versioned
hybrid report. H6 is an input/output adapter around `bmo_check_workflow`; it adds no
recovery, memory-model, correlation, proof, or verdict rules.

The static and dynamic verdicts remain independent. Exit status `0` means the workflow
completed and emitted its outputs, not that either route returned a safe verdict.
Configuration, tool, workflow, and output failures return `3`. The command does not
define a combined verdict.

## Input contract

The CLI accepts a `hybrid-workload-v1` YAML mapping:

```yaml
schema_version: hybrid-workload-v1
workload:
  executable: ./app
  argv: [--input, ./case.dat]
  working_directory: .
  environment:
    WORKERS: "4"
static:
  dbt_contract: ./dbt6-mo-off.yaml
  pthread_spec: ./pthread-api.yaml
  function_effects: ./library-effects.yaml
  library_roots: []
  dbt_revision: 0123456789abcdef0123456789abcdef01234567
  dbt_root: null
  scope: full
  threads: [1, 8]
  provenance_instruction_limit: null
  checker_limits:
    max_events: 24
    max_threads: 8
    max_executions: 4096
    timeout_ms: 10000
dynamic:
  dynamorio_home: /home/user/.local/opt/dynamorio
  client_path: /path/to/libbmo_trace.so
  max_thread_events: null
  max_snapshot_sites: 100000
  analysis:
    max_window_events: 64
    max_executions: 20000
    max_communication_edges: 100000
    max_communication_active_events: 100000
    max_object_events: 5000000
    max_pages_per_access: 16
    batch_size: 50000
    solver_timeout_ms: 10000
    max_symbolic_terms: 100000
    database_memory_limit_mb: 512
    database_path: dynamic-analysis.duckdb
    application_only: false
```

Unknown and duplicate YAML keys, unsupported schema versions, malformed values, and
non-string mapping keys are rejected. Paths in `workload` and `static` resolve from the
manifest's directory. `working_directory` follows the same rule. `dynamic.database_path`
is different: a relative database filename resolves inside `--output-dir`; the result
must be a direct child of that directory and cannot collide with workflow outputs.
Absolute input paths are accepted. There is no shell interpolation or benchmark-name
branching.

`dbt_revision` may be omitted. That is not a CLI input error: the static route keeps its
existing unbound `UNKNOWN` behavior, and the workflow may still collect/analyze a trace.
The report then records that canonical static evidence/diagnostics are unavailable.
Missing executable, static contracts, library roots, DynamoRIO launcher, or native
client are preflight errors; they are detected before allocating the output directory.

## Run and outputs

```bash
bmo-check hybrid --workload workload.yaml --output-dir /mnt/e/bmo-check/run-001
```

The output directory must not already exist. This avoids overwriting an earlier run.
The command creates it exclusively after preflight, then calls the existing H4
`analyze_workload` service and H5 report builder. Expected outputs are:

```text
run-001/
├── hybrid-workflow-report.json
├── static-certificate.json       # existing static compatibility-certificate format
├── dynamic-certificate.json      # existing trace route certificate format
├── dynamic-analysis.duckdb       # or configured direct-child filename
└── trace/
    ├── manifest.json
    └── event chunks and trace metadata
```

The static application service replays its canonical proof ledger before returning;
the CLI persists the established static compatibility-certificate format. The dynamic
route certificate is persisted separately in its existing format. The hybrid report
is an audit summary; it does not substitute for route certificate replay. If the
workflow fails after capture starts, the CLI keeps partial trace artifacts and reports
their location instead of deleting them. If report persistence fails after analysis,
already written certificates and trace artifacts are likewise retained for inspection.

The user sees separate `Static verdict` and `Dynamic verdict` lines plus the report and
trace locations. `TRACE_SAFE` remains scoped to the captured trace; neither it nor
dynamic observations/hints can discharge static Unknowns or upgrade static `UNKNOWN`
to `SAFE`.

## Implementation boundary

- `bmo_check_dynamic.cli` registers the `hybrid` command using the existing local
  adapter pattern used by `diagnose`.
- `bmo_check_cli.hybrid` parses no analysis semantics; it calls the workflow API,
  stores route outputs and renders route verdicts.
- `bmo_check_workflow.manifest` owns the strict versioned YAML input schema and maps it
  to existing `StaticRequest`, `DynamicConfig`, and `HybridWorkflowRequest` types.
- The DBT6 canonical contract remains the only policy input. H6 does not introduce
  policy selection or alter E2.5, static recovery, dynamic analysis, or verdicts.

## Tests and acceptance

Run the focused checks:

```text
uv run pytest tests/contract/test_workflow_manifest.py \
  tests/contract/test_hybrid_workflow_cli.py \
  tests/contract/test_workflow_report.py \
  tests/contract/test_workflow_application.py
```

The CLI tests mock the H4 service and do not execute an ELF, start DynamoRIO, or create
a real DuckDB database. They cover strict manifest parsing, relative path rules,
default/resource mapping, missing DBT revision as static-Unknown input, preflight
failure before output allocation, refusal to overwrite, separate route outputs,
operational exit codes, and preservation of partial artifacts after output failure.
Real canneal, litmus and PARSEC workflow runs belong to H7.

H6 validation on WSL2: the focused manifest/CLI suite passed `18/18`; the complete
default suite passed `434` tests with `10` environment/opt-in skips and no failures.
The skipped cases require a built DynamoRIO client or explicit real-litmus opt-in.

## Remaining constraints

- The current static CLI format is retained for its route certificate; H5 remains the
  authoritative versioned combined report, with no combined verdict.
- Environment values are summarized in the report but may remain in the trace manifest;
  users should not put secrets in a captured workload environment.
- H6 does not guarantee crash-atomic writes across the complete multi-file run. Output
  directories are exclusive and partial evidence is intentionally preserved.
- No actual workload, corpus, or native tracer execution is part of H6 validation.
