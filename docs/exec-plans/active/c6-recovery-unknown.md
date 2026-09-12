# C6 — Dependency-closure Unknown producer

Status: implemented on branch `dev`

## Scope

This step adds the dependency-closure/recovery producer's canonical ledger seam.
The existing `build_program_manifest(...)` API remains unchanged for compatibility;
the static report adapter later carries its Unknowns into certificate replay.

`build_program_manifest_with_evidence(...)` is an explicit opt-in entry point. It
passes an `EvidenceLedger` through the same dependency walk, so every Unknown made
by this producer is emitted as a canonical `UnknownFact` at the point of creation.
The returned `StaticRecoveryEvidence` keeps the old `ProgramManifest` beside the
ledger for differential checks.

## Boundary rules

- Canonical Unknown kinds come from `bmo_check_core.evidence.UnknownKind`; an old kind
  that is not registered falls back to `UnknownRootCause` rather than being dropped.
- The producer emits no `ObservedFact` or `DiagnosticHint` and has no dynamic-route
  import.
- Legacy `impact` and `details` remain explanation context. They are normalized to
  sorted JSON text for the canonical ID and are not proof premises.
- The optional ledger path is fail-closed for non-canonical details. The legacy path
  keeps its historical behavior when no ledger is supplied.
- A new scope changes canonical Unknown IDs; it cannot reuse a fact from another
  certificate scope.

## Tests and migration gate

`tests/static/unit/test_dependency_evidence.py` checks unchanged legacy manifests,
canonical missing-library/DBT-revision emission, deterministic scope-bound IDs and
the absence of dynamic/diagnostic facts. Existing ELF closure integration tests still
exercise the original API.

The recovery sidecar is now consumed indirectly by the static report-to-certificate
bridge. Native producer migration is still deferred: this sidecar may be removed
only after recovery emits canonical facts directly and differential certificate tests
cover the replacement.
