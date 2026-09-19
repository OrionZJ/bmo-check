from __future__ import annotations

import pytest

from bmo_check_core import (
    AccessRange,
    MemoryAccessKind,
    MemoryOperation,
    RangeRelation,
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
) -> MemoryOperation:
    return MemoryOperation(
        event_id=event_id,
        thread_id=thread_id,
        sequence=sequence,
        access=AccessRange(object_id="alloc-1", offset=offset, size=size),
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
