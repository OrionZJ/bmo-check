# C5 — Certificate proof-closure replay

Status: implemented on branch `dev`

## Purpose

The legacy static certificate model still serializes Pydantic `ProofObject` and
`UnknownFact` values.  C5 adds an executable canonical replay boundary before any
route producer is migrated.  A static certificate now names proof roots,
per-event `RemovalDecision`s and relevant Unknown IDs; a trace certificate names
only trace-bound `ObservedFact` roots.

The new API is deliberately not wired into the old CLI/verifier yet.  Existing
`PortabilityCertificate` JSON and verdict behavior therefore remain unchanged while
the closure rules receive independent negative tests.

## Canonical checks

`verify_static_certificate` rejects:

- missing or non-`ProofFact` roots, including `ObservedFact` roots;
- removed events whose proof is outside the reachable closure or does not cover the
  event;
- omitted or unresolved Unknowns, and discharges whose proof is outside the closure;
- bounded results labeled `SAFE`;
- mismatched binary-closure, DBT-contract, revision or scope bindings;
- relevant Unknowns attached to a `COUNTEREXAMPLE`.

`verify_trace_certificate` separately requires every root to be an `ObservedFact`
from the certificate's `TraceId`, and refuses `TRACE_SAFE` for an incomplete trace.
Neither verifier converts observations into proof facts.

## Model additions

- `CertificateBinding` binds a `BinaryClosureId`, DBT contract/revision and scope.
- `RemovalDecision` carries exactly one `MemoryEventId`, `ProofFact` ID and scope.
- `StaticCertificate` and `TraceCertificate` use disjoint verdict enums.
- `ProofFact.covered_events` retains the event set needed to replay legacy bulk
  removal proofs.

## Deletion/migration gate

The old certificate builder can be migrated only after its report is translated to
these canonical types, replay checks are run on the same inputs, and serialized
output remains unchanged.  Until then, the new verifier is an additive contract and
does not authorize any dynamic observation to affect static `SAFE`.
