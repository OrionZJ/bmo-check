# C7 — Canonical static certificate bridge

Status: implemented on branch `dev`

## Scope

`build_static_certificate_with_evidence(...)` is the first consumer of the C6
sidecars. It merges the typed slice proofs, removal decisions and portability
Unknowns, constructs a `StaticCertificate`, and immediately runs
`verify_static_certificate(...)`. The legacy `PortabilityCertificate` remains
unchanged and is still the compatibility/JSON output during migration.

## Safety boundary

- Every sidecar node must use the exact certificate scope. The bridge does not
  rewrite scopes because doing so could hide an unresolved obligation.
- `ObservedFact` and `DiagnosticHint` are rejected before certificate creation.
- A legacy `SAFE` becomes canonical `SAFE` only after proof-closure replay; an
  empty Unknown list by itself is not enough.
- Unresolved canonical Unknowns are copied into `relevant_unknowns`, so a
  missing producer cannot silently disappear.
- A bounded legacy checker remains bounded in the canonical certificate and is
  rejected as `SAFE` by the core verifier.

## Migration gate

The bridge is intentionally an explicit service rather than a change to the
legacy CLI. The next step is to call it from one static orchestration path,
compare legacy and canonical verdicts/coverage, and only then move certificate
serialization to the canonical model. The bridge can be deleted only after all
static certificate consumers use the canonical replay result.
