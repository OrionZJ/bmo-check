from __future__ import annotations

import pytest

from bmo_check_core import (
    AccessRange,
    ExecutionRelations,
    MemoryAccessKind,
    MemoryOperation,
    MemoryRelation,
    RangeRelation,
    RelationKind,
    SemanticPrimitive,
    SemanticPrimitiveRef,
    relate_ranges,
    source_ppo_preserved,
)


def _operation(
    event_id: str,
    kind: MemoryAccessKind,
    *,
    offset: int,
    size: int = 4,
    thread_id: str = "t0",
    sequence: int,
    object_id: str = "alloc-1",
) -> MemoryOperation:
    return MemoryOperation(
        event_id=event_id,
        thread_id=thread_id,
        sequence=sequence,
        access=AccessRange(object_id=object_id, offset=offset, size=size),
        kind=kind,
    )


def test_source_ppo_preserves_same_address_store_to_load() -> None:
    store = _operation("s", MemoryAccessKind.STORE, offset=0, sequence=1)
    load = _operation("l", MemoryAccessKind.LOAD, offset=0, sequence=2)

    assert source_ppo_preserved(store, load)


def test_source_ppo_allows_different_address_store_to_load() -> None:
    store = _operation("s", MemoryAccessKind.STORE, offset=0, sequence=1)
    load = _operation("l", MemoryAccessKind.LOAD, offset=8, sequence=2)

    assert not source_ppo_preserved(store, load)


def test_source_ppo_preserves_partial_overlap_store_to_load() -> None:
    store = _operation("s", MemoryAccessKind.STORE, offset=0, size=8, sequence=1)
    load = _operation("l", MemoryAccessKind.LOAD, offset=4, size=8, sequence=2)

    assert source_ppo_preserved(store, load)


def test_source_ppo_never_creates_cross_thread_program_order() -> None:
    store = _operation("s", MemoryAccessKind.STORE, offset=0, sequence=1)
    load = _operation(
        "l", MemoryAccessKind.LOAD, offset=0, thread_id="t1", sequence=1
    )

    assert not source_ppo_preserved(store, load)


def test_same_object_non_overlapping_ranges_are_disjoint() -> None:
    left = AccessRange(object_id="alloc-1", offset=0, size=4)
    right = AccessRange(object_id="alloc-1", offset=8, size=4)

    assert relate_ranges(left, right) is RangeRelation.DISJOINT


def test_partial_overlap_is_not_clipped_to_an_exact_object() -> None:
    left = AccessRange(object_id="alloc-1", offset=0, size=8)
    right = AccessRange(object_id="alloc-1", offset=4, size=8)

    assert relate_ranges(left, right) is RangeRelation.PARTIAL_OVERLAP


def test_equal_numeric_offsets_on_different_objects_are_disjoint() -> None:
    left = AccessRange(object_id="alloc-1", offset=0, size=4)
    right = AccessRange(object_id="alloc-2", offset=0, size=4)

    assert relate_ranges(left, right) is RangeRelation.DISJOINT


def test_range_identity_is_a_same_address_primitive_input() -> None:
    reference = SemanticPrimitiveRef(
        primitive=SemanticPrimitive.SAME_ADDRESS,
        source_model="x86-tso",
        target_model="rvwmo",
        contract_version="dbt6-mo-off-v2",
    )
    assert reference.primitive is SemanticPrimitive.SAME_ADDRESS


def test_primitive_reference_keeps_model_and_contract_identity() -> None:
    reference = SemanticPrimitiveRef(
        primitive=SemanticPrimitive.PPO,
        source_model="x86-tso",
        target_model="rvwmo",
        contract_version="dbt6-mo-off-v2",
    )

    assert reference.primitive is SemanticPrimitive.PPO
    assert reference.source_model == "x86-tso"
    assert reference.target_model == "rvwmo"
    assert reference.contract_version == "dbt6-mo-off-v2"
    assert reference != SemanticPrimitiveRef(
        primitive=SemanticPrimitive.PPO,
        source_model="x86-tso",
        target_model="rvwmo",
        contract_version="dbt6-mo-off-v3",
    )


@pytest.mark.parametrize("field", ["source_model", "target_model", "contract_version"])
def test_primitive_reference_rejects_missing_identity(field: str) -> None:
    values = {
        "primitive": SemanticPrimitive.READ_FROM,
        "source_model": "x86-tso",
        "target_model": "rvwmo",
        "contract_version": "dbt6-mo-off-v2",
    }
    values[field] = ""

    with pytest.raises(ValueError, match=field):
        SemanticPrimitiveRef(**values)


def test_execution_relations_accept_exact_width_rf_co_fr() -> None:
    write0 = _operation("w0", MemoryAccessKind.STORE, offset=0, sequence=1)
    write1 = _operation("w1", MemoryAccessKind.STORE, offset=0, sequence=2)
    read = _operation("r0", MemoryAccessKind.LOAD, offset=0, sequence=3)

    relations = ExecutionRelations(
        read_from=(MemoryRelation(RelationKind.READ_FROM, write0, read),),
        coherence=(MemoryRelation(RelationKind.COHERENCE, write0, write1),),
        from_read=(MemoryRelation(RelationKind.FROM_READ, read, write1),),
    )

    assert relations.all_exact_width
    assert relations.exact_width_issues() == ()
    assert relations.read_from[0].proposition_key[0] == "read_from"
    assert relations.read_from[0].proposition_id in relations.proposition_ids


def test_relation_proposition_ids_do_not_depend_on_relation_tuple_order() -> None:
    write0 = _operation("w0", MemoryAccessKind.STORE, offset=0, sequence=1)
    write1 = _operation("w1", MemoryAccessKind.STORE, offset=0, sequence=2)
    read = _operation("r0", MemoryAccessKind.LOAD, offset=0, sequence=3)
    first = ExecutionRelations(
        read_from=(MemoryRelation(RelationKind.READ_FROM, write0, read),),
        coherence=(MemoryRelation(RelationKind.COHERENCE, write0, write1),),
    )
    second = ExecutionRelations(
        coherence=(MemoryRelation(RelationKind.COHERENCE, write0, write1),),
        read_from=(MemoryRelation(RelationKind.READ_FROM, write0, read),),
    )

    assert first.proposition_ids == second.proposition_ids


def test_initial_read_from_has_an_explicit_exact_width_proposition() -> None:
    read = _operation("r0", MemoryAccessKind.LOAD, offset=0, sequence=1)

    relation = MemoryRelation(RelationKind.READ_FROM, None, read)

    assert relation.range_relation is RangeRelation.EXACT
    assert relation.exact_width_supported
    assert relation.proposition_key[1] is None


def test_partial_width_relation_stays_visible_but_is_not_exact_width_supported() -> None:
    write = _operation("w", MemoryAccessKind.STORE, offset=0, size=8, sequence=1)
    read = _operation("r", MemoryAccessKind.LOAD, offset=4, size=8, sequence=2)

    relation = MemoryRelation(RelationKind.READ_FROM, write, read)
    relations = ExecutionRelations(read_from=(relation,))

    assert relation.range_relation is RangeRelation.PARTIAL_OVERLAP
    assert not relation.exact_width_supported
    assert relations.exact_width_issues() == ("read_from:w->r:partial_overlap",)
    assert not relations.all_exact_width


def test_relation_direction_and_duplicate_rf_targets_are_checked() -> None:
    write = _operation("w", MemoryAccessKind.STORE, offset=0, sequence=1)
    read = _operation("r", MemoryAccessKind.LOAD, offset=0, sequence=2)

    with pytest.raises(ValueError, match="coherence target"):
        MemoryRelation(RelationKind.COHERENCE, write, read)
    with pytest.raises(ValueError, match="one source per target"):
        ExecutionRelations(
            read_from=(
                MemoryRelation(RelationKind.READ_FROM, write, read),
                MemoryRelation(RelationKind.READ_FROM, None, read),
            )
        )
