from __future__ import annotations

import pytest

from bmo_check_core import (
    CompletenessState,
    CompletenessStatus,
    EvidenceId,
    InstructionId,
    MemoryEventId,
    MemoryOperandId,
    ModuleId,
    ProjectionLedger,
    ProjectionRelationDisposition,
    ProjectionRelationEntry,
    ProjectionRelationKind,
    RegisteredProofRule,
    RelationId,
    ThreadRoleId,
)


def _event(label: str) -> MemoryEventId:
    module = ModuleId.from_parts("a" * 64, "executable")
    instruction = InstructionId.from_parts(module, len(label))
    return MemoryEventId.from_parts(
        # The relation ledger only needs stable endpoints; the event identity
        # itself is kept deliberately independent of traversal order.
        operand=MemoryOperandId.from_parts(instruction, 0, "Load"),
        thread_role=ThreadRoleId.from_legacy(label),
        event_kind="Load",
        summary_discriminator=label,
    )


def _relation(
    kind: ProjectionRelationKind,
    first: MemoryEventId,
    second: MemoryEventId,
    *,
    symmetric: bool = False,
) -> RelationId:
    return RelationId.from_parts(
        kind.value,
        (first, second),
        symmetric=symmetric,
    )


def _proof(relation: RelationId) -> EvidenceId:
    return EvidenceId.from_parts(
        "ProjectionProof",
        "test-1",
        "tests.unit.projection",
        relation,
        (),
    )


def _unknown(relation: RelationId) -> EvidenceId:
    return EvidenceId.from_parts(
        "ProjectionUnknown",
        "test-1",
        "tests.unit.projection",
        relation,
        (),
    )


def test_relation_identity_preserves_direction_and_explicit_symmetry() -> None:
    first = _event("first")
    second = _event("second")

    assert _relation(ProjectionRelationKind.PROGRAM_ORDER, first, second) != _relation(
        ProjectionRelationKind.PROGRAM_ORDER, second, first
    )
    assert _relation(
        ProjectionRelationKind.CONFLICT,
        first,
        second,
        symmetric=True,
    ) == _relation(
        ProjectionRelationKind.CONFLICT,
        second,
        first,
        symmetric=True,
    )


def test_projection_ledger_requires_a_disposition_for_every_complete_relation() -> None:
    first = _event("first")
    second = _event("second")
    relation = _relation(ProjectionRelationKind.PROGRAM_ORDER, first, second)

    with pytest.raises(ValueError, match="every input relation"):
        ProjectionLedger(
            stage="static.application",
            input_relation_ids=(relation,),
            entries=(),
            preservation_rule=None,
            completeness=CompletenessState(
                CompletenessStatus.COMPLETE,
                "static.application",
            ),
        )


def test_projection_ledger_keeps_removed_and_unresolved_relations_distinct() -> None:
    first = _event("first")
    second = _event("second")
    retained = _relation(ProjectionRelationKind.PROGRAM_ORDER, first, second)
    removed = _relation(ProjectionRelationKind.SYNCHRONIZATION, first, second)
    unresolved = _relation(ProjectionRelationKind.CONFLICT, first, second, symmetric=True)
    ledger = ProjectionLedger(
        stage="static.application",
        input_relation_ids=(retained, removed, unresolved),
        entries=(
            ProjectionRelationEntry(
                retained,
                ProjectionRelationDisposition.RETAINED,
            ),
            ProjectionRelationEntry(
                removed,
                ProjectionRelationDisposition.REMOVED_WITH_PROOF,
                proof_ids=(_proof(removed),),
            ),
            ProjectionRelationEntry(
                unresolved,
                ProjectionRelationDisposition.UNRESOLVED,
                unknown_ids=(_unknown(unresolved),),
            ),
        ),
        preservation_rule=RegisteredProofRule("application-projection", "1"),
        completeness=CompletenessState(
            CompletenessStatus.COMPLETE,
            "static.application",
        ),
    )

    assert ledger.missing_relation_ids == ()
    assert ledger.retained_relation_ids == (retained,)
    assert ledger.removed_relation_ids == (removed,)
    assert ledger.unresolved_relation_ids == (unresolved,)


@pytest.mark.parametrize(
    ("disposition", "proof_ids", "unknown_ids"),
    [
        (ProjectionRelationDisposition.REMOVED_WITH_PROOF, (), ()),
        (ProjectionRelationDisposition.UNRESOLVED, (), ()),
        (
            ProjectionRelationDisposition.RETAINED,
            (),
            (EvidenceId.from_parts("Unknown", "1", "test", "retained", ()),),
        ),
    ],
)
def test_relation_entry_requires_evidence_matching_disposition(
    disposition,
    proof_ids,
    unknown_ids,
) -> None:
    relation = _relation(ProjectionRelationKind.PROGRAM_ORDER, _event("a"), _event("b"))
    with pytest.raises(ValueError):
        ProjectionRelationEntry(
            relation,
            disposition,
            proof_ids=proof_ids,
            unknown_ids=unknown_ids,
        )
