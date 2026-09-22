from __future__ import annotations

from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
    characterize_graph_first_window,
    replay_candidate_cycle,
)
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
        max_cycles=1,
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
    assert report.may_graph is not None
    assert report.may_graph.contract.over_approximate is True
    assert report.may_graph.graph_complete_for_observed_candidates is True
    assert report.search_ledger is not None
    assert report.search_ledger.search_truncated is True
    assert report.search_ledger.not_run_count == 1
    assert report.candidates[0].candidate_violation_cycle is not None
    assert any(
        edge.relation_type == "ppo_reachability"
        for edge in report.candidates[0].candidate_violation_cycle.ordered_edges
    )
    assert report.candidates[0].local_obligations is not None
    assert report.candidates[0].local_obligations.rf_exclusivity_preserved is True


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
    assert report.candidates[0].replay is not None
    assert report.candidates[0].replay.status.value == "accepted"
    assert not hasattr(report, "verdict")


def test_candidate_replay_rejects_tampered_ppo_witness() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, certificate_replay = build_ppo_reduction_certificate(graph)
    assert certificate_replay.accepted is True
    source_reduced = frozenset(graph.source_edges)
    target_reduced = frozenset(graph.target_edges)
    bad_cycle = item.candidate_violation_cycle.model_copy(
        update={
            "ordered_edges": tuple(
                edge.model_copy(
                    update={
                        "ppo_reachability_path": (
                            edge.ppo_reachability_path[0],
                            "missing-event",
                        )
                    }
                )
                if edge.relation_type == "ppo_reachability"
                else edge
                for edge in item.candidate_violation_cycle.ordered_edges
            )
        }
    )
    replay = replay_candidate_cycle(
        graph,
        certificate,
        bad_cycle,
        item.local_obligations,
        item.local_witness,
        source_reduced=source_reduced,
        target_reduced=target_reduced,
        events=window.events,
    )
    assert replay.status.value == "rejected"
    assert replay.ppo_reachability_valid is False


def test_candidate_replay_rejects_incomplete_rf_domain() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, certificate_replay = build_ppo_reduction_certificate(graph)
    assert certificate_replay.accepted is True
    incomplete = item.local_obligations.model_copy(
        update={"rf_candidate_domain_ids": ()}
    )
    replay = replay_candidate_cycle(
        graph,
        certificate,
        item.candidate_violation_cycle,
        incomplete,
        item.local_witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=window.events,
    )
    assert replay.status.value == "rejected"
    assert replay.rf_exclusivity_valid is False
