from bmo_check_dynamic.analysis import AnalysisWindow, CommunicationEdge
from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent
from bmo_check_dynamic.proof import check_window


KNOWN = EventFlags.VALUE_KNOWN


def test_load_buffering_target_only_execution_is_reported() -> None:
    # T0: r=x; y=1 / T1: r=y; x=1。两次 read 都从对方后续 store 取值时，
    # RVWMO 可形成 x86-TSO 的 Load→Store 环。
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4, 1, KNOWN),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2000, 4, 1, KNOWN),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4, 1, KNOWN),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x1000, 4, 1, KNOWN),
    )
    window = AnalysisWindow(
        "lb",
        events,
        (
            CommunicationEdge("t1:e1", "t2:e2", 0x1000, 4),
            CommunicationEdge("t1:e2", "t2:e1", 0x2000, 4),
        ),
    )
    result = check_window(window, max_executions=100, control_flow_closed=True)
    assert result.status == "counterexample"
    assert result.witness is not None and result.witness.validated


def test_unvalidated_candidate_becomes_unknown() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x1000, 4),
    )
    result = check_window(
        AnalysisWindow(
            "lb",
            events,
            (
                CommunicationEdge("t1:e1", "t2:e2", 0x1000, 4),
                CommunicationEdge("t1:e2", "t2:e1", 0x2000, 4),
            ),
        ),
        max_executions=100,
        control_flow_closed=False,
    )
    assert result.status == "unknown"
    assert result.witness is not None and not result.witness.validated


def test_mfence_blocks_load_buffering_candidate() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.MFENCE),
        TraceEvent(1, 3, 0, 0x12, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.MFENCE),
        TraceEvent(2, 3, 0, 0x22, EventKind.STORE, 0x1000, 4),
    )
    result = check_window(
        AnalysisWindow(
            "fenced-lb",
            events,
            (
                CommunicationEdge("t1:e1", "t2:e3", 0x1000, 4),
                CommunicationEdge("t1:e3", "t2:e1", 0x2000, 4),
            ),
        ),
        max_executions=100,
        control_flow_closed=False,
    )
    assert result.status == "safe"


def test_wider_store_can_supply_contained_read() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 8),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1004, 4),
    )
    result = check_window(
        AnalysisWindow(
            "mixed",
            events,
            (CommunicationEdge("t1:e1", "t2:e1", 0x1004, 4),),
        ),
        max_executions=100,
        control_flow_closed=False,
    )
    assert result.status == "safe"


def test_read_spanning_only_part_of_write_stays_unknown() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 8),
    )
    result = check_window(
        AnalysisWindow(
            "partial-read",
            events,
            (CommunicationEdge("t1:e1", "t2:e1", 0x1000, 4),),
        ),
        max_executions=100,
        control_flow_closed=False,
    )
    assert result.status == "unknown"
    assert "partial writes" in result.reason


def test_symbolic_fallback_finds_load_buffering_candidate() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4, 1, KNOWN),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2000, 4, 1, KNOWN),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4, 1, KNOWN),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x1000, 4, 1, KNOWN),
    )
    result = check_window(
        AnalysisWindow(
            "symbolic-lb",
            events,
            (
                CommunicationEdge("t1:e1", "t2:e2", 0x1000, 4),
                CommunicationEdge("t1:e2", "t2:e1", 0x2000, 4),
            ),
        ),
        max_executions=1,
        control_flow_closed=True,
    )
    assert result.status == "counterexample"
    assert result.witness is not None and result.witness.validated


def test_symbolic_fallback_proves_fenced_load_buffering_safe() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.MFENCE),
        TraceEvent(1, 3, 0, 0x12, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.MFENCE),
        TraceEvent(2, 3, 0, 0x22, EventKind.STORE, 0x1000, 4),
    )
    result = check_window(
        AnalysisWindow(
            "symbolic-fenced-lb",
            events,
            (
                CommunicationEdge("t1:e1", "t2:e3", 0x1000, 4),
                CommunicationEdge("t1:e3", "t2:e1", 0x2000, 4),
            ),
        ),
        max_executions=1,
        control_flow_closed=False,
    )
    assert result.status == "safe"
