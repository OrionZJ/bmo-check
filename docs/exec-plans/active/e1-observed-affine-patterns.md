# E1 — Observed affine patterns

Status: implemented on branch `dev`

## Scope

`bmo_check_diagnostics.affine` adds the typed `ObservedAffinePattern` model and a
stream-friendly summary pass. It consumes the existing static/dynamic snapshots and
the D3 stable-ID correlation results. It does not import the static lattice and has no
API for creating a `ProofFact` or discharging an `UnknownFact`.

For every `UnknownAffineBounds`, the summary records:

- stable Unknown, observed-fact and trace identities;
- instruction/operand subjects and per-thread execution identities;
- sample count, bounded address samples, observed range and base candidates;
- bounded signed stride candidates and whether either sample set reached its cap;
- observed overlap between complete per-thread samples;
- repetition stability, correlation status and explicit limitations.

The dynamic snapshot adapter keeps at most 32 first-seen addresses and 16 stride
candidates per site. Once a cap is reached it keeps only a lower-bound/incomplete
marker, so a large trace cannot turn the diagnostic pass into an unbounded Python data
structure. These fields describe observations, not affine bounds or disjointness.

## Output contract

`ObservedAffineStatus` distinguishes `NotObserved`, `Insufficient`, `Stable`,
`Variable`, `Incomplete` and `Ambiguous`. `Stable` means that the sampled deltas were
stable in the supplied trace set; it never means that a loop bound or thread partition
has been proved.

`bmo-check diagnose --affine-output PATH` writes the separate versioned affine report
alongside the existing D4 diagnostic report. The JSON file is an explicit output
boundary; the in-memory model remains typed.

## Acceptance

- synthetic tests cover stable, incomplete and proof-boundary behavior;
- dynamic adapter exposes bounded address/stride observations;
- adding or changing observations leaves the static verdict and static evidence
  unchanged;
- no benchmark name, function name, observed address or stride selects semantics.

Commit intent: `Diagnose affine-bound Unknowns from observations`.
