# C7 — Canonical static certificate bridge

Status: implemented on branch `dev`

## Scope

`build_static_certificate_with_evidence(...)` remains the typed sidecar entry point.
`build_static_certificate_from_report(...)` now adapts the complete legacy static
report, carries all report Unknowns into the same ledger, records proof-backed
discharges, and feeds the result to `verify_static_certificate(...)`. The static
application service invokes this bridge on the real `analyze` path. The legacy
`PortabilityCertificate` remains unchanged only as the compatibility/JSON output.

## Safety boundary

- Every sidecar node must use the exact certificate scope. The bridge does not
  rewrite scopes because doing so could hide an unresolved obligation.
- `ObservedFact` and `DiagnosticHint` are rejected before certificate creation.
- A legacy `SAFE` becomes canonical `SAFE` only after proof-closure replay; an
  empty Unknown list by itself is not enough.
- Unresolved canonical Unknowns are copied into `relevant_unknowns`, so a
  missing producer cannot silently disappear; filtered report Unknowns require an
  explicit same-scope proof-backed discharge.
- A bounded legacy checker remains bounded in the canonical certificate and is
  rejected as `SAFE` by the core verifier.

## Migration gate

The bridge is now called from the static application service. It compares legacy and
canonical verdicts before the CLI receives the compatibility payload, and raises a
fail-closed application error on replay or identity divergence. The bridge can be
deleted only after all static producers and certificate consumers use canonical
identities directly and differential serialization tests have retired the legacy
model.
