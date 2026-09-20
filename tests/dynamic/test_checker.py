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


def test_overlapping_mixed_width_writes_use_symbolic_coherence() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 8),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1004, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1004, 4),
    )
    result = check_window(
        AnalysisWindow(
            "mixed-writes",
            events,
            (
                CommunicationEdge("t1:e1", "t2:e1", 0x1004, 4),
                CommunicationEdge("t1:e2", "t2:e1", 0x1004, 4),
            ),
        ),
        max_executions=100,
        control_flow_closed=False,
    )
    assert result.status == "safe"


def test_mixed_width_atomic_write_uses_symbolic_coherence() -> None:
    """完整覆盖的混合宽度 RMW 应进入 overlap 模型，而不是提前 UNKNOWN。"""
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 8),
        TraceEvent(1, 2, 0, 0x11, EventKind.ATOMIC_RMW, 0x1004, 4),
    )
    result = check_window(
        AnalysisWindow("mixed-atomic-writes", events, ()),
        max_executions=100,
        control_flow_closed=False,
    )
    assert result.status == "safe"
    assert result.reason != "mixed-width atomic coherence is not supported"


def test_partial_mixed_width_atomic_read_remains_unknown() -> None:
    """RMW 不能把一次读拆成不同写源；无法证明时必须保留 UNKNOWN。"""
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1004, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.ATOMIC_RMW, 0x1000, 8),
    )
    result = check_window(
        AnalysisWindow("partial-mixed-atomic-read", events, ()),
        max_executions=100,
        control_flow_closed=False,
    )
    assert result.status == "unknown"
    assert result.reason == "mixed-width atomic read-from is not supported"


def test_read_with_unwritten_part_uses_initial_value_for_that_part() -> None:
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
    assert result.status == "safe"


def test_two_narrow_stores_expose_store_order_candidate_to_wide_read() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1004, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 8),
    )
    result = check_window(
        AnalysisWindow(
            "composite-read",
            events,
            (
                CommunicationEdge("t1:e1", "t2:e1", 0x1000, 4),
                CommunicationEdge("t1:e2", "t2:e1", 0x1004, 4),
            ),
        ),
        max_executions=100,
        control_flow_closed=False,
    )
    assert result.status == "unknown"
    assert result.witness is not None
    assert not result.witness.validated
    assert {
        (item.address, item.size) for item in result.witness.read_from
    } == {(0x1000, 4), (0x1004, 4)}


def test_symbolic_formula_limit_returns_unknown_before_solver() -> None:
    events = tuple(
        TraceEvent(1, sequence, 0, 0x10, EventKind.LOAD, 0x1000, 4)
        for sequence in range(1, 14)
    )
    result = check_window(
        AnalysisWindow("formula-limit", events, ()),
        max_executions=100,
        control_flow_closed=False,
        max_symbolic_terms=10,
    )
    assert result.status == "unknown"
    assert result.reason == "symbolic formula exceeds 10 terms"


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
