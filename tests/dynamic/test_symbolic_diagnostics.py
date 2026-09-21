from bmo_check_dynamic.analysis import AnalysisWindow, CommunicationEdge
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.proof import characterize_symbolic_encoding


def test_symbolic_characterization_counts_candidates_without_solving() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x1000, 4),
    )
    stats = characterize_symbolic_encoding(
        AnalysisWindow(
            "symbolic-diagnostics",
            events,
            (
                CommunicationEdge("t1:e1", "t2:e2", 0x1000, 4),
                CommunicationEdge("t1:e2", "t2:e1", 0x2000, 4),
            ),
        )
    )

    assert stats.event_count == 4
    assert stats.read_count == 2
    assert stats.write_count == 2
    assert stats.rf_part_count == 2
    assert stats.rf_candidate_count == 2
    assert stats.cross_thread_rf_edge_count == 2
    assert stats.from_read_candidate_count == 2
    assert stats.conditional_edge_count == 2
    assert stats.estimated_formula_terms > stats.initial_formula_terms
