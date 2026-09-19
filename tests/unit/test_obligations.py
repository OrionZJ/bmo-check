from __future__ import annotations

import pytest

from bmo_check_core import (
    CompletenessState,
    CompletenessStatus,
    InstructionId,
    MemoryEventId,
    MemoryOperandId,
    ModuleId,
    ObligationId,
    ObligationInventory,
    ObligationKind,
    PropositionId,
    ProofObligation,
    ThreadRoleId,
)


HASH = "a" * 64


def _event(name: str) -> MemoryEventId:
    module = ModuleId.from_parts(HASH, "executable")
    instruction = InstructionId.from_parts(module, 0x100)
    operand = MemoryOperandId.from_parts(instruction, 0, name)
    role = ThreadRoleId.from_legacy("worker")
    return MemoryEventId.from_parts(operand, role, name, "obligation-test")


def _obligation(kind: ObligationKind = ObligationKind.EXECUTION) -> ProofObligation:
    proposition = PropositionId.from_parts("rf", ("store", "load"))
    return ProofObligation.create(
        proposition_id=proposition,
        kind=kind,
        scope="slice-1",
        subjects=(_event("load"), _event("store")),
    )


def test_obligation_binds_proposition_scope_and_stable_subjects() -> None:
    obligation = _obligation()
    same = ProofObligation.create(
        proposition_id=obligation.proposition_id,
        kind=obligation.kind,
        scope=obligation.scope,
        subjects=tuple(reversed(obligation.subjects)),
    )

    assert obligation.id == same.id
    assert obligation.id == obligation.expected_id()
    assert obligation.proposition_id.value.startswith("proposition:")


def test_inventory_completeness_is_not_proof_closure() -> None:
    obligation = _obligation(ObligationKind.PROJECTION)
    inventory = ObligationInventory(
        scope="slice-1",
        obligations=(obligation,),
        completeness=CompletenessState(CompletenessStatus.COMPLETE, "slice-1"),
    )

    assert inventory.is_enumerated
    assert inventory.ids == (obligation.id,)


def test_incomplete_inventory_cannot_be_reported_as_enumerated() -> None:
    inventory = ObligationInventory(
        scope="slice-1",
        obligations=(),
        completeness=CompletenessState(
            CompletenessStatus.INCOMPLETE,
            "slice-1",
            reason="opaque projection stage",
        ),
    )

    assert not inventory.is_enumerated


def test_inventory_rejects_wrong_scope_and_duplicate_obligations() -> None:
    obligation = _obligation()
    with pytest.raises(ValueError, match="scope"):
        ObligationInventory(
            scope="slice-2",
            obligations=(obligation,),
            completeness=CompletenessState(CompletenessStatus.COMPLETE, "slice-2"),
        )
    with pytest.raises(ValueError, match="duplicate"):
        ObligationInventory(
            scope="slice-1",
            obligations=(obligation, obligation),
            completeness=CompletenessState(CompletenessStatus.COMPLETE, "slice-1"),
        )


def test_obligation_id_must_match_content() -> None:
    obligation = _obligation()
    with pytest.raises(ValueError, match="does not match"):
        ProofObligation(
            id=ObligationId.from_parts("fake", "slice-1", ("fake",)),
            proposition_id=obligation.proposition_id,
            kind=obligation.kind,
            scope=obligation.scope,
            subjects=obligation.subjects,
        )
