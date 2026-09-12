# C6 — Portability Unknown sidecar

Status: implemented on branch `dev`

## Scope

`verify_portability(...)` remains the legacy static verdict producer. The new
`verify_portability_with_evidence(...)` wrapper invokes the same checker and returns
the unchanged `PortabilityCertificate` beside a canonical ledger for the certificate's
`relevant_unknowns`; the application bridge replays those Unknowns before exposing
the compatibility payload.

This closes the producer side of the Unknown migration without pretending that the
legacy certificate's string `ProofObject` payload is already a canonical proof
closure. The report bridge supplies the slice proof/removal sidecar and canonical
replay now gates revision-bound static results.

## Boundary rules

- The wrapper mirrors the final relevance result, while the report bridge separately
  retains upstream Unknowns and requires a proof-backed discharge for any filtered
  event obligation.
- No `ObservedFact` or `DiagnosticHint` can enter the portability ledger.
- Calling the wrapper cannot change verdict, checker limits, counterexample payload,
  or certificate JSON; it is a characterization seam for the later proof migration.
- An empty ledger beside a legacy `SAFE` certificate is not a canonical SAFE proof.
  The absence of relevant Unknowns is accepted only after typed proof roots,
  removal decisions and replay verification close the same report.

## Tests and migration gate

`tests/static/unit/test_portability_verifier.py` compares the legacy certificate and
sidecar certificate byte-for-byte as model values, then checks the canonical Unknown
kind. Existing portability, counterexample and bounded-check tests remain unchanged.

The C7 bridge now consumes the typed slice `RemovalDecision` and portability ledger.
The legacy JSON adapter remains until native producer migration and differential
certificate tests retire the old model.
