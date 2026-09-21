from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    CommunicationEdge,
    build_candidate_slice,
    plan_obligation_preserving_split,
)
from bmo_check_dynamic.model import EventKind, TraceEvent


def test_candidate_report_does_not_drop_hub_events() -> None:
    window = AnalysisWindow(
        "hub",
        tuple(
            TraceEvent(1, index, 0, 0x10 + index, EventKind.LOAD, 0x1000, 4)
            for index in range(1, 4)
        )
        + (TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 4),),
        (
            CommunicationEdge("t1:e1", "t2:e1", 0x1000, 4),
            CommunicationEdge("t1:e2", "t2:e1", 0x1000, 4),
            CommunicationEdge("t1:e3", "t2:e1", 0x1000, 4),
        ),
    )

    candidate = build_candidate_slice(window)

    assert candidate.complete is False
    assert candidate.removed_event_ids == ()
    assert set(candidate.retained_event_ids) == {
        event.event_id for event in window.events
    }
    assert candidate.groups[0].communication_endpoint_count == 3
    assert candidate.proposed_event_ids == ()


def test_mixed_width_loads_are_not_grouped_as_duplicates() -> None:
    window = AnalysisWindow(
        "mixed-width",
        (
            TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
            TraceEvent(1, 2, 0, 0x11, EventKind.LOAD, 0x1000, 8),
        ),
        (),
    )

    candidate = build_candidate_slice(window)

    assert candidate.groups == ()
    assert candidate.retained_event_ids == ("t1:e1", "t1:e2")


def test_read_from_domain_blocks_split_even_without_explicit_edge() -> None:
    window = AnalysisWindow(
        "read-domain",
        (
            TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
            TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
        ),
        (),
    )

    plan = plan_obligation_preserving_split(window)

    assert plan.partition_count == 1
    assert plan.status.value == "no-safe-split"
