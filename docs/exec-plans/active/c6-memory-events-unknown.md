# C6 — Memory-event recovery Unknowns and identities

Status: implemented on branch `dev`

## Scope

This slice adds an explicit opt-in ledger path to
`extract_memory_events(...)`. The existing `MemoryEventReport` remains unchanged
for current slicing and proof callers. `extract_memory_events_with_evidence(...)`
returns that report beside a canonical ledger and stable links for every emitted
legacy event.

The producer now emits canonical Unknowns for incomplete thread roles, unknown
addresses, syscalls, opaque calls, argument effects, indirect targets, instruction
facts and extraction failure at the same branches that build the legacy report.
The outer failure path still returns its unknown-event sentinel; the ledger records
the failure instead of allowing an empty event set to look complete.

## Identity and boundary rules

- A `MemoryEventId` is derived from module hash/role, PC, normalized operand/effect,
  legacy thread role and the event discriminator. It never uses Python object IDs,
  traversal order or benchmark names.
- Capstone's `-1` implicit operand index is represented as operand `0` plus an
  `implicit` effect discriminator, so an implicit stack access cannot collide with
  explicit operand `0`.
- The sidecar rejects an event whose module path/hash does not match the extracted
  module. Silently rebinding such an event would make later diagnostics point at the
  wrong binary.
- Canonical output contains only static `UnknownFact` nodes. It does not create
  observations, hints, proofs or removal decisions, and does not alter the legacy
  report. The static certificate bridge consumes the translated event identities and
  proof/removal sidecar at the final boundary.
- Unknowns inherited from reachable Capstone instruction facts are mirrored when
  the memory producer consumes them; unreachable decode gaps remain outside this
  producer's report scope, as before.

## Tests and migration gate

`tests/static/unit/test_memory_event_failures.py` compares legacy and sidecar failure
reports, checks the canonical recovery kind, and verifies a stable event link for the
sentinel. Existing shared-state/slicing integration tests continue to use the legacy
entry point.

The shared-state/slicing sidecars now consume these event links without turning a
legacy string ID into a proof by convention; every removed event is checked against a
canonical `RemovalDecision` before the application exposes a revision-bound result.
Native memory-event producer migration remains a follow-up cleanup.
