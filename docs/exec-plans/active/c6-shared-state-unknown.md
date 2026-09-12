# C6 — Shared-state and escape Unknown producers

Status: implemented on branch `dev`

## Scope

This slice adds an opt-in canonical ledger path to
`analyze_shared_state(...)`. The legacy `SharedStateReport`, proof objects and
removed-event lists remain unchanged for compatibility callers. The static
certificate bridge translates the resulting proof/removal information before replay.
`analyze_shared_state_with_evidence(...)` runs the same classification and returns
the report beside a ledger containing the Unknowns created by that pass.

The migrated branches cover escaped TLS, materialized/escaped stack addresses and
unclosed affine partition bounds. These are the real proof gaps that make a canneal
style report remain `UNKNOWN`; the sidecar records them without turning a dynamic
observation or an old explanation string into a proof.

## Boundary rules

- The sidecar writes only static `UnknownFact` nodes. It does not create
  `ProofFact`, `ObservedFact` or `DiagnosticHint` and does not alter the old verdict.
- Legacy `ProofObject` and event-removal fields remain on the compatibility report;
  the certificate bridge converts each removal to a canonical `RemovalDecision` and
  refuses an unmapped or unproved event.
- UnknownAffineBounds keeps the full event/address context as explanation data. A
  runtime affine pattern may later produce a diagnostic hint, but cannot discharge
  this Unknown.
- The producer continues to retain all unknown-address and opaque effects in the
  shared slice. A missing proof is never treated as an empty object group.

## Tests and migration gate

`tests/static/unit/test_shared_state_evidence.py` builds a two-role affine group with
missing bounds and checks that the legacy report still contains
`UnknownAffineBounds`, while the sidecar records the canonical kind and no other
evidence category. Existing shared-state/slicing integration tests continue to use
the old entry point.

The slicing/removal sidecar now adds typed event-to-proof links and canonical
`RemovalDecision` records without changing which events the legacy report keeps or
removes. Native shared-state producer migration remains a future cleanup.
