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

The dynamic route now has the matching one-way adapter,
`bmo_check_dynamic.adapters.dynamic_snapshot_from_trace`. It validates the trace
before reading it, resolves loaded PCs through the module map and bound ELF hashes,
and streams event files into bounded per-thread/site aggregates. Memory, atomic,
explicit-fence, indirect-target and operand-index observations become trace-bound
`ObservedFact` nodes; old traces without an operand index remain instruction-site
observations.
The adapter records both mapping-relative and ELF-relative instruction positions so
static locations can be compared without retaining the raw trace. Any dropped
record, malformed module, unbound mapping, decode failure or site-budget overflow
remains a trace-scoped `UnknownFact` and sets `complete=False`.

## Safety boundary

- Static snapshots reject observations and hints before correlation starts.
- Dynamic snapshots reject static proof facts and observations from another trace.
- Snapshot construction validates evidence edges and retains Unknown nodes; a copied
  ledger cannot mutate the snapshot.
- No snapshot constructor changes a verdict or creates a proof discharge.

## CLI boundary

`bmo-check diagnose STATIC_SNAPSHOT --trace TRACE_DIR --output REPORT.json` uses the
dynamic adapter directly. The command records the trace digest as the dynamic
artifact identity; it does not write a snapshot back into the trace directory or
change the static certificate. A serialized dynamic snapshot remains available for
repeated diagnostics through the existing `--dynamic-snapshot` form.

## Acceptance

Both route adapters have characterization tests for immutable evidence, stable
identity, operand-identity loss and incomplete traces. The adapters expose no
verdict or proof API; correlation and root-cause hints remain read-only.
