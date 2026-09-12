# D5 — Generic root-cause registry

Status: implemented on branch `dev`

## Scope

`bmo_check_diagnostics.classification` defines the typed
`DiagnosticRootCause` registry and immutable `ClassificationResult`. It publishes
the planned root-cause codes without adding a second proof lattice. The classifier
uses the static `UnknownKind`, its reason/context and (when present) the typed
correlation status; it never reads benchmark names, raw addresses or dynamic values.

The first rules are deliberately conservative:

- affine-bound context may identify a missing loop bound, induction variable or PHI
  recurrence;
- unresolved indirect targets, opaque memory effects, escape/shared-address gaps,
  thread/lifecycle gaps and unsupported normalization map to their corresponding
  registry code;
- no usable signal returns `UnknownRootCause`;
- an unmatched trace location is reported as `NotExecutedInObservedTrace`, with zero
  confidence, rather than as a static alias/disjointness fact;
- an ambiguous correlation returns `DynamicPatternNotStable` with low confidence.

`DiagnosticReport` now uses these typed results when creating `DiagnosticHint`. The
hint still stores only a registry value and confidence; it cannot discharge an
Unknown, enter a static proof closure or change `SAFE`/`UNKNOWN`.

## Acceptance

- every published root-cause code has a validated descriptor;
- report hints expose the typed code while preserving the static verdict;
- missing or ambiguous observations remain low-confidence diagnostics;
- classification tests cover direct mappings, contextual mappings and mismatched
  correlation IDs;
- no static/dynamic route import boundary changes.

## Deliberate limits

The registry does not infer affine bounds, alias facts, lifecycle proofs or any other
static capability. Implementing such a capability belongs to Phase E and requires a
fresh static `ProofFact` plus pure-static regression tests.

Commit intent: `Classify static precision gaps without changing verdicts`.
