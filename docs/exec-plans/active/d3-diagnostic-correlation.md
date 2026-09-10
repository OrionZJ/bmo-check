# D3 — Static Unknown / dynamic observation correlation

Status: implemented on branch `dev`

## Scope

`bmo_check_diagnostics.correlate_unknowns(...)` consumes only the read-only
diagnostic snapshots. It matches a static Unknown to every dynamic observation with
the same stable subject, but emits `EXACT` only when both snapshots carry the same
binary closure. Missing closure, missing subject and closure mismatch remain
explicit `AMBIGUOUS`/`UNMATCHED` outcomes; the correlator never picks an arbitrary
candidate.

## Safety boundary

- The report copies the original static `CertificateVerdict`; correlation cannot
  upgrade `UNKNOWN` or construct a `SAFE` certificate.
- `ObservedFact` IDs remain trace-bound and are never added to a static ledger.
- A successful match is a diagnostic location, not an affine, alias, disjointness
  or lifecycle proof.
- Old traces without operand identity can only be correlated when their stable
  subject is already unique; otherwise the result stays conservative.

## Next gate

Add function/block/operand fallback keys only as typed facts, then build
`DiagnosticHint` and root-cause classification. Hints must remain outside static
proof closure and must show the original static verdict.
