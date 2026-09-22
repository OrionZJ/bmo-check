from __future__ import annotations

from bmo_check_dynamic.analysis import AnalysisWindow, characterize_graph_first_window
from bmo_check_dynamic.model import EventKind, GraphFirstQueryStatus, TraceEvent


def _lb_window() -> AnalysisWindow:
    # 两个线程各自先读后写；cross-thread RF 与 source PPO 可以组成候选环。
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x2000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x2000, 4),
    )
    return AnalysisWindow("graph-first-fixture", events, ())


def test_graph_first_is_bounded_and_diagnostic_only() -> None:
    report = characterize_graph_first_window(
        _lb_window(),
        max_cycle_length=6,
        max_cycles=4,
        max_search_states=100,
        execute_local_solver=False,
    )

    assert report.diagnostic_only is True
    assert report.reduction_replay_accepted is True
    assert report.cycles_returned >= 1
    assert report.candidates[0].diagnostic_only is True
    assert report.candidates[0].includes_non_ppo is True
    assert report.candidates[0].local_query is not None
    assert report.candidates[0].local_query.status is GraphFirstQueryStatus.NOT_RUN


def test_graph_first_local_query_never_becomes_a_verdict() -> None:
    report = characterize_graph_first_window(
        _lb_window(),
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )

    query = report.candidates[0].local_query
    assert query is not None
    assert query.diagnostic_only is True
    assert query.status in {
        GraphFirstQueryStatus.SAT_CANDIDATE,
        GraphFirstQueryStatus.UNSAT_LOCAL,
        GraphFirstQueryStatus.UNKNOWN_LOCAL,
    }
    assert not hasattr(report, "verdict")
