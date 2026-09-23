from __future__ import annotations

from time import monotonic

from bmo_check_dynamic.model import (
    CandidateCycleReplayStatus,
    FixedCycleRelationRequirement,
    FixedCycleShadowQuery,
    GraphFirstCandidateCycle,
    LocalCycleWitness,
    TracePpoReductionCertificate,
)
from bmo_check_dynamic.proof import run_symbolic_shadow

from .graph_first import (
    _LabeledEdge,
    _build_local_obligations,
    _build_local_witness,
    _reduced_edges,
    _required_local_source_edges,
    replay_candidate_cycle,
)
from .windows import AnalysisWindow
from .ppo_reduction import PpoGraphInput


def run_fixed_candidate_cycle_shadow(
    window: AnalysisWindow,
    *,
    graph: PpoGraphInput,
    certificate: TracePpoReductionCertificate,
    candidate: GraphFirstCandidateCycle,
    candidate_skeleton_id: str,
    p17_independent_result: str,
    p17_shared_result: str,
    control_flow_closed: bool,
    timeout_ms: int,
    max_symbolic_terms: int,
) -> FixedCycleShadowQuery:
    """在完整窗口内固定一个已发现的 source cycle，其余内存选择保持符号化。"""

    semantic = candidate.candidate_violation_cycle
    if semantic is None:
        raise ValueError("fixed-cycle query requires a semantic candidate cycle")
    started = monotonic()
    cycle_edges = tuple(
        _LabeledEdge(
            source=edge.source_event,
            target=edge.target_event,
            kind=edge.relation_type,
            relation_id=edge.relation_ids[0] if edge.relation_ids else "",
            relation_ids=edge.relation_ids,
            witness_path=edge.ppo_reachability_path,
        )
        for edge in semantic.ordered_edges
    )
    required = _required_local_source_edges(cycle_edges)
    source_reduced = _reduced_edges(
        graph.source_edges, certificate.source.removed_edges
    )
    target_reduced = _reduced_edges(
        graph.target_edges, certificate.target.removed_edges
    )
    preparation_ms = max(0, int((monotonic() - started) * 1000))

    _, p17_profile = run_symbolic_shadow(
        window,
        source_ppo=set(source_reduced),
        target_ppo=set(target_reduced),
        control_flow_closed=control_flow_closed,
        timeout_ms=timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        execute_solver=False,
        required_source_cycle_edges=required.endpoints,
        required_source_cycle_relations=required.relation_groups,
    )
    result, observation = run_symbolic_shadow(
        window,
        source_ppo=set(source_reduced),
        target_ppo=set(target_reduced),
        control_flow_closed=control_flow_closed,
        timeout_ms=timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        required_source_cycle_edges=required.endpoints,
        required_source_cycle_relations=required.relation_groups,
        fixed_source_cycle_edges=required.endpoints,
        capture_model=True,
    )

    local_witness: LocalCycleWitness | None = None
    replay_status = CandidateCycleReplayStatus.NOT_RUN
    replay_reasons: tuple[str, ...] = ()
    if observation.result == "sat":
        local_witness = _build_local_witness(
            semantic,
            cycle_edges=cycle_edges,
            local_result=result,
        )
        if local_witness is None:
            replay_status = CandidateCycleReplayStatus.REJECTED
            replay_reasons = ("SAT query returned no model witness",)
        else:
            event_ids = tuple(event.event_id for event in window.events)
            obligations = _build_local_obligations(
                semantic,
                cycle_edges=cycle_edges,
                events=window.events,
                witness=local_witness,
                query_event_ids=event_ids,
                window_event_ids=event_ids,
            )
            replay = replay_candidate_cycle(
                graph,
                certificate,
                semantic,
                obligations,
                local_witness,
                source_reduced=source_reduced,
                target_reduced=target_reduced,
                events=window.events,
            )
            replay_status = replay.status
            replay_reasons = replay.reasons

    return FixedCycleShadowQuery(
        candidate_id=candidate.cycle_id,
        candidate_skeleton_id=candidate_skeleton_id,
        fixed_cycle_edges=tuple(sorted(required.endpoints)),
        relation_requirements=tuple(
            FixedCycleRelationRequirement(
                source_event=source,
                target_event=target,
                relation_type=relation_type,
                relation_ids=relation_ids,
            )
            for source, target, relation_type, relation_ids in required.relation_groups
        ),
        full_window_event_count=len(window.events),
        candidate_preparation_time_ms=preparation_ms,
        rf_choice_count=observation.variable_counts.get("rf_choice", 0),
        p17_independent_result=p17_independent_result,
        p17_shared_result=p17_shared_result,
        p17_formula_profile_result=p17_profile.result,
        p17_formula_profile_reason=p17_profile.reason,
        p17_formula_profile_terms=p17_profile.formula_terms,
        p17_formula_profile_assertions=p17_profile.assertion_count,
        p17_formula_profile_ast_nodes=p17_profile.z3_ast_count,
        p17_formula_profile_build_ms=p17_profile.build_time_ms,
        p17_formula_breakdown=p17_profile.formula_breakdown,
        p17_constraint_breakdown=p17_profile.constraint_breakdown,
        p17_variable_counts=p17_profile.variable_counts,
        definitive_result_matches_p17=(
            observation.result == p17_independent_result
            if observation.result in {"sat", "unsat"}
            and p17_independent_result in {"sat", "unsat"}
            else None
        ),
        solver_result=observation.result,
        reason=observation.reason,
        formula_terms=observation.formula_terms,
        assertion_count=observation.assertion_count,
        ast_node_count=observation.z3_ast_count,
        build_time_ms=observation.build_time_ms,
        solver_time_ms=observation.solver_time_ms,
        peak_rss_mb=observation.peak_rss_mb,
        formula_breakdown=observation.formula_breakdown,
        constraint_breakdown=observation.constraint_breakdown,
        variable_counts=observation.variable_counts,
        replay_status=replay_status,
        replay_reasons=replay_reasons,
        witness=local_witness,
    )
