from __future__ import annotations

import z3
import pytest

from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
    canonicalize_cycle_skeleton,
    characterize_graph_first_window,
    find_frozen_p15_mode,
    run_global_constraint_validation,
)
from bmo_check_dynamic.analysis.cycle_relevance import _candidate_relations
from bmo_check_dynamic.model import (
    CandidateViolationCycle,
    CandidateViolationEdge,
    CegarExperimentMode,
    CegarExperimentReport,
    CegarModeComparisonReport,
    CegarModeMetrics,
    EventKind,
    GraphFirstQueryStatus,
    LocalCycleStatus,
    TraceEvent,
)
from bmo_check_dynamic.proof import (
    build_incremental_shadow_session,
    run_symbolic_shadow,
)
from bmo_check_dynamic.proof.relations import (
    source_preserved_order,
    target_preserved_order,
)


def _lb_window() -> AnalysisWindow:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x2000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x2000, 4),
    )
    return AnalysisWindow("p17-lb-fixture", events, ())


def test_frozen_p15_mode_keeps_window_and_certificate_metadata() -> None:
    mode = CegarModeMetrics(
        mode=CegarExperimentMode.STRUCTURED_P15,
        unique_candidates=10,
    )
    comparison = CegarModeComparisonReport(
        fixture="frozen-sb",
        window_id="window-3720",
        event_count=3720,
        max_cycle_length=8,
        max_search_states=10_000,
        max_local_queries=10,
        local_timeout_ms=1_000,
        certificate_digest="certificate-bound-to-window",
        modes=(mode,),
    )
    report = CegarExperimentReport(
        generated_at="2026-09-23T00:00:00Z", reports=(comparison,)
    )

    selected_comparison, selected_mode = find_frozen_p15_mode(report)

    assert selected_comparison.window_id == "window-3720"
    assert selected_comparison.event_count == 3720
    assert selected_comparison.certificate_digest == "certificate-bound-to-window"
    assert selected_mode.unique_candidates == 10
    assert not hasattr(selected_mode, "certificate_digest")


def test_frozen_p15_mode_rejects_ambiguous_or_missing_mode() -> None:
    comparison = CegarModeComparisonReport(
        fixture="frozen-sb",
        window_id="window-3720",
        event_count=3720,
        max_cycle_length=8,
        max_search_states=10_000,
        max_local_queries=10,
        local_timeout_ms=1_000,
    )
    report = CegarExperimentReport(
        generated_at="2026-09-23T00:00:00Z", reports=(comparison,)
    )

    with pytest.raises(ValueError, match="exactly one P15 mode"):
        find_frozen_p15_mode(report)


def _run_unconstrained_cycle_query(window: AnalysisWindow) -> str:
    _, observation = run_symbolic_shadow(
        window,
        source_ppo=source_preserved_order(window.events),
        target_ppo=target_preserved_order(window.events),
        control_flow_closed=False,
        timeout_ms=2_000,
        max_symbolic_terms=20_000,
        execute_solver=True,
    )
    return observation.result


def test_partial_sat_can_become_full_unsat_after_fence_dependency_is_added() -> None:
    # R reads byte 0. E writes bytes 0..1 and W writes byte 1, so E may source R
    # while W and E still have a coherence relation. R and W themselves do not overlap.
    read = TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 1)
    fence = TraceEvent(1, 2, 0, 0x11, EventKind.MFENCE, 0, 0)
    later_write = TraceEvent(1, 3, 0, 0x12, EventKind.STORE, 0x1001, 1)
    source_write = TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 2)

    partial = AnalysisWindow("partial-fence", (read, later_write, source_write), ())
    complete = AnalysisWindow(
        "full-fence", (read, fence, later_write, source_write), ()
    )

    assert _run_unconstrained_cycle_query(partial) == "sat"
    assert _run_unconstrained_cycle_query(complete) == "unsat"


def test_partial_unsat_can_become_full_sat_when_external_rf_source_is_added() -> None:
    # The small query has no external write that can close E -> R -> W -> E.
    # The complete window adds a two-byte write E: it sources R's first byte and
    # overlaps W's second byte, enabling RF, source PPO and CO to form a cycle.
    read = TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x2000, 1)
    later_write = TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2001, 1)
    external_write = TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x2000, 2)

    partial = AnalysisWindow("partial-no-source", (read, later_write), ())
    complete = AnalysisWindow(
        "full-with-source", (read, later_write, external_write), ()
    )

    assert _run_unconstrained_cycle_query(partial) == "unsat"
    assert _run_unconstrained_cycle_query(complete) == "sat"


def test_incremental_push_pop_does_not_leak_one_candidate_into_the_next() -> None:
    first = z3.Bool("first_rf_source")
    second = z3.Bool("second_rf_source")
    solver = z3.Solver()
    solver.add(z3.Xor(first, second))
    edge = ("write", "read")
    # This small solver has the same exact-one RF-source shape as a read part.
    from bmo_check_dynamic.proof.incremental_shadow import IncrementalShadowSession

    session = IncrementalShadowSession(
        solver=solver,
        relation_conditions={
            "rf-first": ((edge, "rf", first),),
            "rf-second": ((edge, "rf", second),),
        },
        selected_edges={},
        window_event_ids=("read", "write"),
        base_formula_terms=1,
        base_assertions=1,
        base_ast_nodes=3,
        base_build_ms=0,
        source_ppo_edge_count=0,
        target_ppo_edge_count=0,
    )

    first_result = session.check_candidate(
        required_source_cycle_edges=frozenset(),
        required_source_cycle_relations=(("write", "read", "rf", ("rf-first",)),),
        timeout_ms=100,
    )
    second_result = session.check_candidate(
        required_source_cycle_edges=frozenset(),
        required_source_cycle_relations=(("write", "read", "rf", ("rf-second",)),),
        timeout_ms=100,
    )

    assert first_result.result == "sat"
    assert second_result.result == "sat"


def test_p16_relation_identity_guard_does_not_change_default_shadow_formula() -> None:
    window = _lb_window()
    source = source_preserved_order(window.events)
    target = target_preserved_order(window.events)
    baseline, baseline_stats = run_symbolic_shadow(
        window,
        source_ppo=source,
        target_ppo=target,
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=10_000,
    )
    explicit_empty, explicit_stats = run_symbolic_shadow(
        window,
        source_ppo=source,
        target_ppo=target,
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=10_000,
        required_source_cycle_relations=(),
    )

    assert explicit_empty.status == baseline.status
    assert explicit_stats.result == baseline_stats.result
    assert explicit_stats.formula_terms == baseline_stats.formula_terms
    assert explicit_stats.assertion_count == baseline_stats.assertion_count


def test_shared_full_formula_matches_independent_candidate_queries() -> None:
    window = _lb_window()
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted

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
    candidate_graph = candidate.candidate_violation_cycle
    assert candidate_graph is not None
    from bmo_check_dynamic.analysis.global_constraint_validation import (
        _candidate_edges,
    )
    from bmo_check_dynamic.analysis.graph_first import _required_local_source_edges

    required = _required_local_source_edges(_candidate_edges(candidate))
    source_reduced = set(graph.source_edges) - {
        (item.source_event, item.target_event)
        for item in certificate.source.removed_edges
    }
    target_reduced = set(graph.target_edges) - {
        (item.source_event, item.target_event)
        for item in certificate.target.removed_edges
    }
    _, independent = run_symbolic_shadow(
        window,
        source_ppo=source_reduced,
        target_ppo=target_reduced,
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=10_000,
        execute_solver=True,
        required_source_cycle_edges=required.endpoints,
        required_source_cycle_relations=required.relation_groups,
        capture_model=True,
    )
    session, base = build_incremental_shadow_session(
        window,
        source_ppo=source_reduced,
        target_ppo=target_reduced,
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=10_000,
    )
    assert session is not None, base.reason
    shared = session.check_candidate(
        required_source_cycle_edges=required.endpoints,
        required_source_cycle_relations=required.relation_groups,
        timeout_ms=1_000,
    )

    assert shared.result == independent.result
    assert shared.added_assertions == len(required.endpoints) + len(
        required.relation_groups
    )


def test_global_validation_keeps_partial_results_diagnostic_only() -> None:
    window = _lb_window()
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted
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
    candidates = tuple(
        item
        for item in discovery.candidates
        if item.candidate_violation_cycle is not None
    )[:2]
    skeletons = {
        item.cycle_id: canonicalize_cycle_skeleton(
            item.candidate_violation_cycle
        ).canonical_id
        for item in candidates
        if item.candidate_violation_cycle is not None
    }

    report = run_global_constraint_validation(
        window,
        certificate,
        candidates,
        candidate_skeleton_ids=skeletons,
        trace_id="synthetic-p17",
        trace_sha256="trace-digest",
        contract_sha256="contract-digest",
        control_flow_closed=False,
        partial_timeout_ms=500,
        full_timeout_ms=1_000,
        max_symbolic_terms=10_000,
        max_queries_per_solver_session=1,
        process_wall_limit_seconds=30,
        process_memory_limit_mb=512,
    )

    assert report.diagnostic_only is True
    assert len(report.progressive_runs) == len(candidates)
    assert len(report.shared_incremental_queries) == len(candidates)
    assert len(report.incremental_session_builds) == len(candidates)
    assert len(report.fixed_candidate_baseline) == len(candidates)
    assert all(
        item.result_matches_independent_full
        == (item.solver_result == item.independent_full_query_result)
        for item in report.shared_incremental_queries
    )
    assert all(run.diagnostic_only for run in report.progressive_runs)
    for run in report.progressive_runs:
        assert run.has_full_window_model_validated == (
            run.final_full_query_result == "sat"
            and run.final_full_query_replay_status == "full_window_model_validated"
        )
        assert all(item.diagnostic_only for item in run.rounds)
        assert all(
            item.status.value == "covered"
            for item in run.dependency_coverage
            if item.family.value in {"candidate_core", "full_window_target_acyclicity"}
        )


def test_candidate_baseline_preserves_every_byte_part_rf_source() -> None:
    window = AnalysisWindow(
        "mixed-width-domain",
        (
            TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x3000, 2),
            TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x3000, 1),
            TraceEvent(3, 1, 0, 0x30, EventKind.STORE, 0x3001, 1),
        ),
        (),
    )
    candidate = CandidateViolationCycle(
        cycle_id="candidate-rf-low-byte",
        cycle_nodes=("t2:e1", "t1:e1"),
        ordered_edges=(
            CandidateViolationEdge(
                source_event="t2:e1",
                target_event="t1:e1",
                relation_type="rf",
                side="source",
                conditional=True,
                relation_ids=("rf:t1:e1:0:0:t2:e1:12288:1",),
            ),
        ),
    )
    from bmo_check_dynamic.analysis.global_constraint_validation import (
        _read_source_domains,
    )
    from bmo_check_dynamic.model import GraphFirstCandidateCycle, GraphFirstLocalQuery

    graph_candidate = GraphFirstCandidateCycle(
        cycle_id="candidate-rf-low-byte",
        event_ids=("t2:e1", "t1:e1", "t2:e1"),
        edges=(),
        includes_non_ppo=True,
        candidate_violation_cycle=candidate,
        local_query=GraphFirstLocalQuery(
            status=GraphFirstQueryStatus.SAT_CANDIDATE,
            solver_result="sat",
            reason="fixture",
            event_count=2,
            source_ppo_edge_count=0,
            target_ppo_edge_count=0,
            feasibility_status=LocalCycleStatus.FEASIBLE,
        ),
    )

    domains = _read_source_domains(window, graph_candidate)

    assert len(domains) == 1
    parts = domains[0].parts
    assert [(part.address, part.size) for part in parts] == [(0x3000, 1), (0x3001, 1)]
    assert parts[0].initial_write_allowed and parts[1].initial_write_allowed
    assert parts[0].candidate_write_event_ids == ("t2:e1",)
    assert parts[1].candidate_write_event_ids == ("t3:e1",)
    assert len(parts[0].relation_ids) == len(parts[1].relation_ids) == 1


def test_local_unsat_candidate_is_still_sent_to_full_window_query() -> None:
    window = _lb_window()
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted
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
    original = next(
        item for item in discovery.candidates
        if item.candidate_violation_cycle is not None and item.local_query is not None
    )
    assert original.local_query.feasibility_status is LocalCycleStatus.FEASIBLE
    # 仅改变记录中的局部分类，用来确认 P17 不以它筛掉候选；真正的全窗
    # 查询仍会重建公式。这个记录不被解释为新的求解结果。
    local_unsat = original.local_query.model_copy(
        update={
            "status": GraphFirstQueryStatus.UNSAT_LOCAL,
            "solver_result": "unsat",
            "feasibility_status": LocalCycleStatus.INFEASIBLE,
        }
    )
    candidate = original.model_copy(update={"local_query": local_unsat})
    skeleton_id = canonicalize_cycle_skeleton(
        candidate.candidate_violation_cycle
    ).canonical_id

    report = run_global_constraint_validation(
        window,
        certificate,
        (candidate,),
        candidate_skeleton_ids={candidate.cycle_id: skeleton_id},
        trace_id="synthetic-p17-unsat-local",
        trace_sha256="trace-digest",
        contract_sha256="contract-digest",
        fixed_candidate_report_sha256="candidate-report-digest",
        control_flow_closed=False,
        partial_timeout_ms=500,
        full_timeout_ms=1_000,
        max_symbolic_terms=10_000,
        max_queries_per_solver_session=1,
        process_wall_limit_seconds=30,
        process_memory_limit_mb=512,
    )

    assert report.fixed_candidate_baseline[0].local_query.feasibility_status is LocalCycleStatus.INFEASIBLE
    assert len(report.independent_full_queries) == 1
    assert report.progressive_runs[0].rounds[-1].full_window is True
