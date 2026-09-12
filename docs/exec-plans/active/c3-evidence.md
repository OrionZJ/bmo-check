# C3 — Typed evidence domain and ledger

Status: complete on branch `dev`

This step establishes the canonical in-memory evidence boundary. Legacy route models
remain as compatibility representations, but the static certificate path now consumes
the canonical ledger through the C4/C7 adapter and replay bridge.

## Canonical variants

- `ProofFact` carries a static rule, scope, typed subject, proof-only premises and an
  optional typed set of covered memory events.
- `ObservedFact` carries a trace, thread instance and typed observation attributes.
- `DiagnosticHint` references Unknown and Observed IDs for diagnosis only.
- `UnknownFact` records a registered kind, reason, scope and static provenance.
- `UnknownDischarge` closes an Unknown only with a same-scope ProofFact and keeps the
  original Unknown in the ledger for audit.

Every variant computes its `EvidenceId` from the complete semantic payload. Changing a
rule, reason, scope, observation or supporting reference therefore cannot silently
reuse an old fact identity.

## Ledger invariants

`EvidenceLedger` rejects:

- missing parents;
- EvidenceId/content mismatches;
- duplicate IDs with different payloads;
- ProofFact premises that are not ProofFacts;
- Unknown provenance that depends on dynamic observations or diagnostic hints;
- diagnostic references with the wrong evidence category;
- discharges whose Unknown, proof or scope does not match.

The ledger is append-only for evidence nodes. A discharge changes whether an Unknown
blocks a declared scope, but never removes the Unknown node.

## Test entry point

`tests/unit/test_evidence.py` covers the positive graph and negative category,
provenance, parent, identity and discharge cases. These tests are intentionally
independent of static/dynamic route internals and do not allow observations to enter a
static proof closure.

## Closure

`verify_static_certificate` and `verify_trace_certificate` consume the typed ledger;
the static application service uses the report adapter before returning its legacy
certificate. Native producer migration remains a separate cleanup: it may replace the
adapter only after differential output tests pass, but it cannot introduce a second
evidence model or bypass replay.
