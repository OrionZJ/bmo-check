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

The Phase C evidence boundary is closed. The shared package contains stable
identities, a typed evidence ledger, static recovery/memory/sharing/slicing and
portability sidecars, and a canonical certificate closure verifier. The static
application service translates its complete legacy report, replays the canonical
certificate and compares verdicts before returning the legacy JSON compatibility
payload. The core also owns the typed DBT memory-order contract used by the dynamic
input adapter. Dynamic-assisted diagnosis remains a separate diagnostic service;
observations and hints can never enter static proof closure.

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

Phase C (typed evidence, stable identities, static certificate replay and application
service wiring) is complete on branch `dev`. Legacy models remain as explicitly
documented adapters until native producers and all serializers migrate; they are no
longer an unchecked verdict authority. Every adapter lists its callers, limitations
and deletion condition.

Future native-producer and relation-vocabulary work must preserve the same replay
boundary. Dynamic/static correlation may consume immutable snapshots, but it must not
change either verdict domain.
