# BMoCheck — Agent Entry Guide

## Read before changing code

Read these repository-local documents in order:

1. `docs/spec/soundness.md`
2. `docs/architecture/target-architecture.md`
3. `docs/architecture/migration-plan.md`
4. `docs/architecture/repository-audit.md`
5. the route-specific document under `docs/static/` or `docs/dynamic/`

The repository-level soundness contract wins if an older route-specific document or
comment conflicts with it.

## What the project proves

- Static `SAFE` is allowed only from a closed static proof for the certificate scope.
- Dynamic `TRACE_SAFE` covers only one certificate-bound execution trace.
- `COUNTEREXAMPLE` requires a validated target-only execution.
- Incomplete recovery, unsupported input, resource limits and missing evidence produce
  `UNKNOWN`.

Passing a program, adding inputs or collecting many `TRACE_SAFE` runs never proves
static `SAFE`.

## Evidence boundary

The canonical categories are:

- `ProofFact` — may enter static `SAFE` proof closure;
- `ObservedFact` — bound to a trace and never becomes a static proof;
- `DiagnosticHint` — helps locate a precision gap and never affects a verdict;
- `UnknownFact` — remains visible until an explicit `ProofFact` discharges it.

Dynamic-assisted diagnosis follows:

```text
static Unknown + dynamic observation -> diagnostic hint
diagnostic hint -> analyzer improvement -> fresh static proof
```

Never write a direct observation-to-proof conversion or mutate the static lattice from
a trace.

## Package direction

The accepted target graph is:

```text
static / dynamic / diagnostics -> bmo_check_core
evaluation -> static / dynamic / diagnostics / core
workflow -> static / dynamic / diagnostics / core
CLI -> application services
```

Forbidden:

- static importing dynamic or diagnostics;
- dynamic importing static or diagnostics;
- static, dynamic, diagnostics, evaluation or core importing workflow;
- workflow importing route internals, evaluation or CLI;
- core importing any implementation, evaluation or CLI package;
- proof/certificate code importing PARSEC manifests;
- core semantic branches on benchmark names.

During migration, existing `bmo_check_static` and `bmo_check_dynamic` models remain in
place behind explicit one-way adapters. Do not create an untracked second business
model or a generic `common` dumping ground.

`bmo_check_core.contracts` is the canonical DBT memory-order interpretation. The
read-only snapshot types in `bmo_check_core.diagnostics` are the only allowed
boundary for future static/dynamic correlation; they do not change verdicts.

`bmo_check_workflow` is the neutral owner for one-workload orchestration. It may call
the static and dynamic application services and pass their immutable snapshots to
diagnostics, but it must not implement recovery, checking, correlation or proof rules.
The static and dynamic routes remain independently usable and do not import workflow.

The recovery producers expose opt-in canonical ledgers as migration seams. The static
application service's `analyze_with_evidence` translates the complete legacy report,
replays a canonical certificate and compares its verdict before `analyze` returns the
legacy JSON-compatible result. Keep the report models and sidecars compared until the
remaining native producer migration is complete; never add a second verdict path.

## Change discipline

Use the sequence in `docs/architecture/migration-plan.md`:

1. characterize current behavior;
2. add a canonical type or interface;
3. add a documented one-way adapter;
4. migrate one producer and its consumers;
5. run differential checks;
6. remove the old representation and adapter only after all callers migrate.

Every commit has one purpose, passes the full default suite and keeps verdicts at least
as conservative as the baseline. Do not combine an evidence-model migration with a
benchmark precision change.

## Test expectations

Proof changes need positive, negative and Unknown-propagation tests. Architecture work
also needs dependency, evidence-flow, proof-closure, stable-ID and schema tests.

PARSEC results validate generic behavior but are not a substitute for synthetic
invariant tests. canneal may expose a missing capability; its name, functions and
observed values must never select analysis semantics.

## Experiment artifacts

Do not commit ordinary local experiment products:

```text
.experiments/
.tmp*
.bmo-check/
large traces
PARSEC temporary results
DuckDB databases
native build output
```

A small fixture may be versioned only when it has an explicit schema version, a
reproduction path and a reviewed reason that a synthetic fixture is insufficient.

## Current commands

```text
bmo-check capture|analyze|run|campaign|explain|locate|diagnose
bmo-check-static fingerprint|recover|slice|analyze|explain|evaluate
```

The H4 Python workflow API is `bmo_check_workflow.analyze_workload`; the one-workload
CLI and serialized hybrid report are scheduled for H5–H6.

`diagnose` consumes only typed static/dynamic snapshots and writes a versioned
diagnostic report. It may correlate observations and create hints, but must not attach
directly to verifier internals, discharge an Unknown, or change a static verdict.
Root-cause classification uses the typed `DiagnosticRootCause` registry. It remains
diagnostic-only: a classification or confidence value cannot discharge an Unknown,
enter static proof closure, or change a verdict.
