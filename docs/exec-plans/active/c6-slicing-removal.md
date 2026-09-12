# C6 — Slice removal decisions

Status: implemented on branch `dev`

## Scope

`build_shared_memory_slice(...)` keeps its legacy return type and behavior. The new
`build_shared_memory_slice_with_evidence(...)` entry point accepts the memory-event,
shared-state and thread sidecars, runs the same slice builder, then creates a
canonical proof boundary:

- every legacy `ProofObject` becomes a `ProofFact` with typed `covered_events`;
- every removed legacy event becomes one `RemovalDecision`;
- old event and proof IDs remain available through explicit link records;
- input ledgers are copied without changing their evidence categories.

## Refusal rules

- A proof that names an event with no `MemoryEventId` mapping is rejected.
- A removed event with no proof coverage is rejected.
- Duplicate legacy event/proof identities are rejected instead of choosing one by
  traversal order.
- The sidecar does not infer a proof from `PruningCoverage` counters or string
  supporting facts.
- Legacy `SharedMemorySlice` remains the compatibility payload for current callers;
  the static application certificate bridge now consumes this sidecar before replay.

## Tests and migration gate

`tests/static/unit/test_slice_evidence.py` checks a removed event receives a typed
proof and decision, and that an unmapped event fails closed. The full slicing and
shared-state integration suite continues to exercise the original entry point.

The static certificate builder now consumes this ledger and replays its
`RemovalDecision` records on the application path. The sidecar remains until native
slice producers emit canonical identities directly; it is not a second `SAFE` path.
