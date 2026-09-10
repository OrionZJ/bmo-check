# C6 — Portability Unknown sidecar

Status: implemented on branch `dev`

## Scope

`verify_portability(...)` remains the legacy static verdict entry point. The new
`verify_portability_with_evidence(...)` wrapper invokes the same checker and returns
the unchanged `PortabilityCertificate` beside a canonical ledger for the certificate's
`relevant_unknowns`.

This closes the producer side of the Unknown migration without pretending that the
legacy certificate's string `ProofObject` payload is already a canonical proof
closure. The slice sidecar must be supplied to a future certificate migration before
the new ledger can issue `SAFE` certificates.

## Boundary rules

- The wrapper copies only Unknowns that survived the existing relevance policy;
  filtered legacy Unknowns are not silently reintroduced into this certificate scope.
- No `ObservedFact` or `DiagnosticHint` can enter the portability ledger.
- Calling the wrapper cannot change verdict, checker limits, counterexample payload,
  or certificate JSON; it is a characterization seam for the later proof migration.
- An empty ledger beside a legacy `SAFE` certificate is not a canonical SAFE proof.
  The absence of relevant Unknowns must still be paired with typed proof roots and
  replay verification before the new certificate path is enabled.

## Tests and migration gate

`tests/static/unit/test_portability_verifier.py` compares the legacy certificate and
sidecar certificate byte-for-byte as model values, then checks the canonical Unknown
kind. Existing portability, counterexample and bounded-check tests remain unchanged.

The next gate is C7: migrate certificate construction/replay to consume the typed
slice `RemovalDecision` and portability ledger, while keeping the legacy JSON adapter
until differential certificate tests pass.
