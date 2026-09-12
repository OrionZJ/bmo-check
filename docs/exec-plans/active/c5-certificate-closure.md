# C5 — Certificate proof-closure replay

Status: implemented on branch `dev`

## Purpose

The legacy static certificate model still serializes Pydantic `ProofObject` and
`UnknownFact` values.  C5 adds an executable canonical replay boundary before any
route producer is migrated.  A static certificate now names proof roots,
per-event `RemovalDecision`s and relevant Unknown IDs; a trace certificate names
only trace-bound `ObservedFact` roots.

The static application service now invokes the canonical replay for every analysis
whose manifest has a DBT revision. Existing `PortabilityCertificate` JSON and verdict
behavior remain unchanged as a compatibility surface; the service compares the
canonical verdict and fails closed on replay failure or divergence. An unbound
analysis without DBT revision remains an explicit `UNKNOWN` and does not receive a
fabricated certificate binding.

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

## Closure and deletion/migration gate

The report adapter now translates the same input used by the old certificate builder;
replay checks run before the compatibility payload is returned, and differential tests
cover SAFE, UNKNOWN, removal and identity paths. The old builder and serializer can
only be deleted after native static producers emit canonical identities directly and
all external consumers have migrated. Until then, the canonical verifier remains the
only proof-closure authority and never accepts a dynamic observation as static `SAFE`.
