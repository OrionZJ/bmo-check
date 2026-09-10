# D1 — Read-only diagnostic snapshots

Status: implemented on branch `dev`

## Scope

`bmo_check_core.diagnostics` defines immutable snapshots that can cross into a
future diagnostics service without exposing analyzer internals:

- `StaticDiagnosticSnapshot` accepts only static `ProofFact` and `UnknownFact`;
- `DynamicDiagnosticSnapshot` accepts only trace-bound `ObservedFact` and dynamic
  `UnknownFact`;
- `EvidenceSnapshot.ledger()` returns a fresh validated ledger on each call.

The new `bmo_check_diagnostics` package only re-exports these core types and imports
neither static nor dynamic route code.

## Safety boundary

- Static snapshots reject observations and hints before correlation starts.
- Dynamic snapshots reject static proof facts and observations from another trace.
- Snapshot construction validates evidence edges and retains Unknown nodes; a copied
  ledger cannot mutate the snapshot.
- No snapshot constructor changes a verdict or creates a proof discharge.

## Next gate

Build read-only adapters from the existing static sidecars and dynamic trace
normalizer into these snapshots. Only after those adapters have characterization
tests should the correlator emit `DiagnosticHint` values.
