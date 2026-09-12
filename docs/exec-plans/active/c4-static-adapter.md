# C4 — Legacy static adapter

Status: implemented on branch `dev`

## Purpose

`bmo_check_static` still produces Pydantic reports because moving every producer and
certificate consumer at once would hide whether a verdict changed.  The adapter in
`src/bmo_check_static/adapters/evidence.py` gives the canonical identity/evidence
domain a real static input while the old report remains the compatibility payload.
The static application service now sends this translated input through canonical
certificate replay before exposing that payload.

The adapter is intentionally one-way:

```text
legacy ProgramSliceReport -> StaticEvidenceSnapshot -> EvidenceLedger
```

It never imports the dynamic route or diagnostics, and it cannot create an
`ObservedFact` or `DiagnosticHint`.

## Mapping

- A legacy `MemoryEvent` receives a `ModuleId`, `InstructionId`, `MemoryOperandId`,
  legacy-thread `ThreadRoleId` and `MemoryEventId`.  The old event ID remains in a
  typed `LegacyEvidenceLink` for report lookup. `None` and negative legacy operand
  indices share the explicit `:implicit` discriminator, so they cannot collide with
  operand zero.
- A legacy `UnknownFact` becomes a canonical `UnknownFact` with a registered
  `UnknownKind`, a scope and a typed event/instruction subject when the old report
  contains enough module/PC or event-ID information.  `impact` and `details` remain
  sorted context strings; they are not proof premises.
- A legacy `ProofObject` becomes a `ProofFact` whose `covered_events` retain the full
  old event set.  Legacy `supporting_facts` remain link context and do not become
  premises.  Premises are empty until a static producer supplies typed parents.
- Repeated references to the same legacy event/proof/Unknown are retained as links;
  the ledger deduplicates only identical canonical content.

## Refusal policy

The adapter fails closed on an empty legacy identifier, malformed module hash or PC,
non-canonical `details`, conflicting payloads for one event/proof ID, or a proof that
references an event not present in the report.  Returning a partial snapshot would
make later proof code less conservative than the old report.

## Tests and deletion gate

`tests/contract/test_static_adapter.py` checks static-only evidence, order-independent
IDs, preserved legacy verdict/JSON, implicit-operand identity, link context and
refusal of dropped event references. `tests/static/unit/test_certificate_bridge.py`
also checks report-to-certificate replay and proof-backed Unknown discharge.

Delete this adapter only after all static producers and certificate consumers use
canonical identities/evidence directly, removal decisions carry canonical proof
references, and differential tests show no legacy output change.
