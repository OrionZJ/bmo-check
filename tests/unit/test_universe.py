from __future__ import annotations

import pytest

from bmo_check_core import (
    CompletenessState,
    CompletenessStatus,
    EventDisposition,
    EventUniverseEntry,
    EventUniverseLedger,
    EvidenceId,
    InstructionId,
    MemoryEventId,
    MemoryOperandId,
    ModuleId,
    ThreadRoleId,
)


HASH = "a" * 64


def _event(event_kind: str) -> MemoryEventId:
    module = ModuleId.from_parts(HASH, "executable")
    instruction = InstructionId.from_parts(module, 0x100)
    operand = MemoryOperandId.from_parts(instruction, 0, event_kind)
    role = ThreadRoleId.from_legacy("worker")
    return MemoryEventId.from_parts(operand, role, event_kind, "universe-test")


def _proof(event: MemoryEventId) -> EvidenceId:
    return EvidenceId.from_parts("ProofFact", "1", "test", event, ())


def _unknown(event: MemoryEventId) -> EvidenceId:
    return EvidenceId.from_parts("UnknownFact", "1", "test", event, ())


def test_complete_universe_accounts_for_each_event_once() -> None:
    retained = _event("Load")
    removed = _event("Store")
    unresolved = _event("Call")
    ledger = EventUniverseLedger(
        stage="static.slice",
        input_event_ids=(unresolved, retained, removed),
        entries=(
            EventUniverseEntry(retained, EventDisposition.RETAINED),
            EventUniverseEntry(
                removed,
                EventDisposition.REMOVED_WITH_PROOF,
                proof_ids=(_proof(removed),),
            ),
            EventUniverseEntry(
                unresolved,
                EventDisposition.UNRESOLVED,
                unknown_ids=(_unknown(unresolved),),
            ),
        ),
        completeness=CompletenessState(
            CompletenessStatus.COMPLETE,
            "static.slice",
        ),
    )

    assert ledger.missing_event_ids == ()
    assert ledger.retained_event_ids == (retained,)
    assert ledger.removed_event_ids == (removed,)
    assert ledger.unresolved_event_ids == (unresolved,)


@pytest.mark.parametrize(
    ("disposition", "proof_ids", "unknown_ids", "message"),
    [
        (EventDisposition.REMOVED_WITH_PROOF, (), (), "ProofFact"),
        (EventDisposition.UNRESOLVED, (), (), "UnknownFact"),
        (EventDisposition.RETAINED, (), (_unknown(_event("Load")),), "retained"),
    ],
)
def test_entry_requires_evidence_matching_its_disposition(
    disposition, proof_ids, unknown_ids, message
) -> None:
    with pytest.raises(ValueError, match=message):
        EventUniverseEntry(
            _event("Entry"),
            disposition,
            proof_ids=proof_ids,
            unknown_ids=unknown_ids,
        )


def test_complete_ledger_rejects_an_unaccounted_input_event() -> None:
    first = _event("Load")
    second = _event("Store")

    with pytest.raises(ValueError, match="every input event"):
        EventUniverseLedger(
            stage="static.recovery",
            input_event_ids=(first, second),
            entries=(EventUniverseEntry(first, EventDisposition.RETAINED),),
            completeness=CompletenessState(
                CompletenessStatus.COMPLETE,
                "static.recovery",
            ),
        )


def test_incomplete_ledger_exposes_missing_events_instead_of_dropping_them() -> None:
    first = _event("Load")
    second = _event("Store")
    ledger = EventUniverseLedger(
        stage="static.recovery",
        input_event_ids=(first, second),
        entries=(EventUniverseEntry(first, EventDisposition.RETAINED),),
        completeness=CompletenessState(
            CompletenessStatus.INCOMPLETE,
            "static.recovery",
            reason="indirect target set is open",
        ),
    )

    assert ledger.missing_event_ids == (second,)
    assert ledger.completeness.status is CompletenessStatus.INCOMPLETE


def test_unsupported_state_requires_reason_and_duplicate_ids_are_rejected() -> None:
    event = _event("Load")
    with pytest.raises(ValueError, match="requires a reason"):
        CompletenessState(CompletenessStatus.UNSUPPORTED, "static.recovery")
    with pytest.raises(ValueError, match="duplicate"):
        EventUniverseLedger(
            stage="static.recovery",
            input_event_ids=(event, event),
            entries=(EventUniverseEntry(event, EventDisposition.RETAINED),),
            completeness=CompletenessState(
                CompletenessStatus.INCOMPLETE,
                "static.recovery",
                reason="duplicate input fixture",
            ),
        )
