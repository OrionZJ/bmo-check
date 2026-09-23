from __future__ import annotations

from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
    canonicalize_cycle_skeleton,
    characterize_graph_first_window,
    run_fixed_candidate_cycle_shadow,
)
from bmo_check_dynamic.analysis.cycle_relevance import _candidate_relations
from bmo_check_dynamic.analysis.graph_first import _reduced_edges
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.proof import run_symbolic_shadow


def _split_read_window() -> AnalysisWindow:
    return AnalysisWindow(
        "p18-split-read",
        (
            TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 2),
            TraceEvent(3, 1, 0, 0x30, EventKind.STORE, 0x1000, 1),
            TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 2),
        ),
        (),
    )


def test_fixed_cycle_keeps_rf_choices_symbolic_and_relation_group_disjunctive() -> None:
    window = _split_read_window()
    writer, _, read = window.events
    rf_ids = tuple(
        sorted(
            relation.relation_id
            for relation in _candidate_relations(window.events)
            if relation.kind == "rf"
            and relation.event_ids == (writer.event_id, read.event_id)
        )
    )
    assert len(rf_ids) == 2  # 同一 writer/read 在两个字节片段各有一个 relation ID。
    ring = frozenset(
        {
            (writer.event_id, read.event_id),
            (read.event_id, writer.event_id),
        }
    )
    relation_group = (
        (writer.event_id, read.event_id, "rf", rf_ids),
    )
    source_ppo = {(read.event_id, writer.event_id)}
    for target_ppo, expected in ((set(), "sat"), ({(read.event_id, writer.event_id)}, "unsat")):
        common = dict(
            source_ppo=source_ppo,
            target_ppo=target_ppo,
            control_flow_closed=False,
            timeout_ms=2_000,
            max_symbolic_terms=100_000,
            required_source_cycle_edges=ring,
            required_source_cycle_relations=relation_group,
            capture_model=True,
        )
        full_result, full_observation = run_symbolic_shadow(window, **common)
        fixed_result, fixed_observation = run_symbolic_shadow(
            window,
            **common,
            fixed_source_cycle_edges=ring,
        )

        assert full_observation.result == fixed_observation.result == expected
        assert fixed_observation.variable_counts["rf_choice"] == 2
        assert fixed_observation.variable_counts["rf_choice"] == full_observation.variable_counts["rf_choice"]
        assert fixed_observation.constraint_breakdown["cycle_fixed_activation"] >= 1
        assert fixed_observation.constraint_breakdown.get("rf", 0) == full_observation.constraint_breakdown.get("rf", 0)
        if expected == "sat":
            assert full_result.witness is not None
            assert fixed_result.witness is not None
            assert fixed_result.witness.model_snapshot is not None
            assert fixed_result.witness.model_snapshot.complete


def test_fixed_cycle_rejects_a_branching_edge_set_before_solving() -> None:
    window = _split_read_window()
    events = tuple(event.event_id for event in window.events)
    invalid_edges = frozenset(
        {
            (events[0], events[1]),
            (events[1], events[0]),
            (events[1], events[2]),
        }
    )

    result, observation = run_symbolic_shadow(
        window,
        source_ppo={(events[1], events[0])},
        target_ppo=set(),
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=100_000,
        required_source_cycle_edges=invalid_edges,
        fixed_source_cycle_edges=invalid_edges,
    )

    assert observation.result == "unknown"
    assert "one simple closed cycle" in result.reason


def test_fixed_cycle_candidate_replays_complete_window_model() -> None:
    window = AnalysisWindow(
        "p18-lb-candidate",
        (
            TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x2000, 4),
            TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1000, 4),
            TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
            TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x2000, 4),
        ),
        (),
    )
    graph = build_ppo_graph_input(window)
    certificate, reduction_replay = build_ppo_reduction_certificate(graph)
    assert reduction_replay.accepted
    discovery = characterize_graph_first_window(
        window,
        reduction_certificate=certificate,
        control_flow_closed=False,
        max_cycle_length=6,
        max_cycles=4,
        max_search_states=500,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )
    candidate = next(
        item
        for item in discovery.candidates
        if item.candidate_violation_cycle is not None
    )
    skeleton_id = canonicalize_cycle_skeleton(
        candidate.candidate_violation_cycle
    ).canonical_id

    query = run_fixed_candidate_cycle_shadow(
        window,
        graph=graph,
        certificate=certificate,
        candidate=candidate,
        candidate_skeleton_id=skeleton_id,
        p17_independent_result="unknown",
        p17_shared_result="unknown",
        control_flow_closed=False,
        timeout_ms=2_000,
        max_symbolic_terms=10_000,
    )

    assert query.full_window_event_count == len(window.events)
    assert query.full_window_constraints
    assert query.rf_choices_remain_symbolic
    assert query.target_acyclicity_retained and query.rmw_constraints_retained
    assert query.official_verdict_changed is False
    assert query.rf_choice_count > 0
    assert query.solver_result == "sat"
    assert query.witness is not None
    assert query.replay_status.value == "full_window_model_validated"
    assert query.independent_replay is not None
    assert query.independent_replay.model_snapshot_valid is True
    assert query.independent_replay.full_window_closed is True
    assert query.independent_replay.trace_completeness_validated is False
    assert query.independent_replay.control_flow_closure_validated is False
    assert query.independent_replay.read_values_validated is False
    assert query.independent_replay.execution_counterexample_validated is False
