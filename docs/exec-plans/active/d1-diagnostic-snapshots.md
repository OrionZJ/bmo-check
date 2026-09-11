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

The static route now has a one-way adapter,
`bmo_check_static.adapters.static_snapshot_from_certificate`. It accepts only the
replayed `StaticCertificateEvidence`, copies all static nodes and discharges into a
fresh immutable snapshot, and derives subject identities from typed fields. It
replays at the boundary so a ledger mutation after certificate construction cannot
silently become a diagnostic input. The adapter rejects `ObservedFact` and
`DiagnosticHint` even when they are unrelated to the certificate roots.

## Safety boundary

- Static snapshots reject observations and hints before correlation starts.
- Dynamic snapshots reject static proof facts and observations from another trace.
- Snapshot construction validates evidence edges and retains Unknown nodes; a copied
  ledger cannot mutate the snapshot.
- No snapshot constructor changes a verdict or creates a proof discharge.

## Next gate

The static adapter is covered by certificate-bridge tests. The dynamic trace
normalizer still needs a corresponding adapter; until both adapters have
characterization tests, the correlator must remain a read-only correlation result
and cannot emit proof or discharge records.
