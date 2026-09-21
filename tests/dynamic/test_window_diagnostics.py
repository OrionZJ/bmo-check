from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    CommunicationEdge,
    characterize_window,
)
from bmo_check_dynamic.model import EventKind, TraceEvent


def test_window_diagnostics_counts_memory_and_relation_candidates() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 8),
        TraceEvent(2, 2, 0, 0x21, EventKind.MFENCE),
    )
    diagnostics = characterize_window(
        AnalysisWindow(
            "window-000001",
            events,
            (CommunicationEdge("t1:e2", "t2:e1", 0x1000, 4),),
        )
    )

    assert diagnostics.event_count == 4
    assert diagnostics.memory_event_count == 3
    assert diagnostics.load_count == 1
    assert diagnostics.store_count == 2
    assert diagnostics.fence_count == 1
    assert diagnostics.thread_count == 2
    assert diagnostics.communication_edge_count == 1
    assert diagnostics.overlap_pair_count == 3
    assert diagnostics.overlap_write_pair_count == 1
    assert diagnostics.overlap_read_write_pair_count == 2
    assert diagnostics.rf_candidate_count == 1
    assert diagnostics.max_rf_candidates == 1
    assert diagnostics.coherence_candidate_pair_count == 1


def test_window_diagnostics_does_not_treat_unwritten_reads_as_rf_candidates() -> None:
    events = (TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x2000, 4),)
    diagnostics = characterize_window(AnalysisWindow("empty", events, ()))

    assert diagnostics.rf_candidate_count == 0
    assert diagnostics.max_rf_candidates == 0
    assert diagnostics.p95_rf_candidates == 0
