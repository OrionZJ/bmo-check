# D3 — Static Unknown / dynamic observation correlation

Status: implemented on branch `dev`

## Scope

`bmo_check_diagnostics.correlate_unknowns(...)` consumes only the read-only
diagnostic snapshots. It first matches a static Unknown to every dynamic
observation with the same stable subject, then falls back to the static provenance
location (`legacy.module`, `legacy.pc`, `legacy.kind`) and dynamic ELF-relative
attributes. It emits `EXACT` only when the binary closure is known and the location
has one operand interpretation. Missing closure, missing location and closure
mismatch remain explicit `AMBIGUOUS`/`UNMATCHED` outcomes; the correlator never
picks an arbitrary candidate.

## Safety boundary

- The report copies the original static `CertificateVerdict`; correlation cannot
  upgrade `UNKNOWN` or construct a `SAFE` certificate.
- `ObservedFact` IDs remain trace-bound and are never added to a static ledger.
- A successful match is a diagnostic location, not an affine, alias, disjointness
  or lifecycle proof.
- Old traces without operand identity can only be correlated when their stable
  instruction site is unique; when several static candidates share that site, every
  record stays `AMBIGUOUS` and references the same observed site.

## Next gate

D4 consumes this correlation result to build a versioned report and D5 registry-backed
`DiagnosticHint` records. Hints remain outside static proof closure and retain the
original static verdict.
