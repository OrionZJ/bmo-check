import pytest
from pydantic import ValidationError

from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    CommunicationEdge,
    build_obligation_inventory,
    plan_obligation_preserving_split,
)
from bmo_check_dynamic.model import (
    CandidateSlice,
    EventKind,
    SliceCandidateStatus,
    SliceObligationKind,
    TraceEvent,
)


def _window() -> AnalysisWindow:
    return AnalysisWindow(
        "window-000001",
        (
            TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
            TraceEvent(1, 2, 0, 0x11, EventKind.MFENCE),
            TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
        ),
        (CommunicationEdge("t1:e1", "t2:e1", 0x1000, 4),),
    )


def test_obligation_inventory_has_stable_typed_domains() -> None:
    first = build_obligation_inventory(_window())
    second = build_obligation_inventory(_window())

    assert [item.obligation_id for item in first] == [
        item.obligation_id for item in second
    ]
    kinds = {item.kind for item in first}
    assert SliceObligationKind.EVENT_PRESENCE in kinds
    assert SliceObligationKind.COMMUNICATION_EDGE in kinds
    assert SliceObligationKind.READ_FROM_DOMAIN in kinds
    assert SliceObligationKind.COHERENCE_DOMAIN in kinds
    assert SliceObligationKind.BOUNDARY in kinds


def test_candidate_slice_requires_a_proof_for_complete_removal() -> None:
    event_ids = ("t1:e1", "t1:e2", "t2:e1")
    with pytest.raises(ValidationError):
        CandidateSlice(
            window_id="window-000001",
            source_event_count=3,
            source_event_ids=event_ids,
            retained_event_ids=("t1:e1", "t2:e1"),
            removed_event_ids=("t1:e2",),
            proposed_event_ids=("t1:e2",),
            complete=True,
            status=SliceCandidateStatus.PROVEN,
        )


def test_candidate_only_slice_keeps_all_source_events() -> None:
    event_ids = ("t1:e1", "t1:e2", "t2:e1")
    candidate = CandidateSlice(
        window_id="window-000001",
        source_event_count=3,
        source_event_ids=event_ids,
        retained_event_ids=event_ids,
        proposed_event_ids=("t1:e1",),
        complete=False,
    )
    assert candidate.status is SliceCandidateStatus.CANDIDATE_ONLY
    assert candidate.removed_event_ids == ()


def test_split_plan_refuses_a_communication_connected_window() -> None:
    plan = plan_obligation_preserving_split(_window())

    assert plan.status.value == "no-safe-split"
    assert plan.partition_count == 1
    assert plan.complete is False


def test_split_plan_can_describe_independent_event_components() -> None:
    window = AnalysisWindow(
        "independent",
        (
            TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
            TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
        ),
        (),
    )

    plan = plan_obligation_preserving_split(window)

    assert plan.status.value == "split-proven"
    assert plan.partition_count == 2
    assert plan.complete is False
    assert all(partition.obligation_ids for partition in plan.partitions)
