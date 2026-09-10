# BMoCheck Architecture

This file is the architecture entry point. The canonical documents are:

- `docs/architecture/repository-audit.md` — current subsystem and dependency audit;
- `docs/architecture/target-architecture.md` — accepted target ownership and package map;
- `docs/architecture/migration-plan.md` — incremental implementation and deletion gates;
- `docs/spec/soundness.md` — repository-level evidence and verdict contract.

## Current state

The repository currently has two independent implementations:

```text
src/bmo_check_dynamic/       trace-scoped TRACE_SAFE verification
src/bmo_check_static/        binary-only static SAFE research
```

They do not import each other. This remains required during the migration.

The current split is not yet a complete evidence boundary. The shared package now
contains stable identities, a typed evidence ledger, a one-way static adapter and a
canonical certificate closure verifier. Dependency-closure recovery now has an
opt-in canonical Unknown sidecar, but static provenance and dynamic certificates
still use their legacy representations. Dynamic-assisted static diagnosis must not
be added directly to those legacy paths; later C6 producers and certificate
consumers must be migrated with differential checks first.

## Accepted direction

The migration introduces narrow shared domains and keeps route implementations
separate:

```text
bmo_check_core
  identity / evidence / memory / contracts / portability / certificate

bmo_check_static       -> core
bmo_check_dynamic      -> core
bmo_check_diagnostics  -> core
bmo_check_evaluation   -> static / dynamic / diagnostics / core
bmo_check_cli          -> application services
```

`bmo_check_core` is not a generic utility package. It owns only canonical facts,
identities, memory-model contracts and certificate verification.

## Non-negotiable boundary

```text
dynamic observation + static Unknown
    -> DiagnosticHint
    -> developer or coding-agent change
    -> fresh pure-static analysis
    -> ProofFact
    -> possible SAFE
```

The following path is forbidden:

```text
dynamic observation -> static proof lattice -> SAFE
```

`TRACE_SAFE` remains bound to a concrete trace. No number of trace runs upgrades it to
static `SAFE`.

## Migration state

The target architecture is accepted, but implementation is intentionally staged.
Legacy models remain authoritative until a characterization test and one-way adapter
exist. Every adapter must list its callers, limitations and deletion condition.

Do not start dynamic/static correlation before the evidence and stable-identity
foundation in Phase C is complete.
