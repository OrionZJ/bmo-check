"""P12 graph-first CEGAR shadow prototype.

This module deliberately sits beside the P11 graph-first route.  It can
canonicalize candidates and use replayable UNSAT information to avoid
repeating local queries, but it never calls the formal window checker and
never turns an exhausted search into SAFE.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Iterable

from bmo_check_dynamic.model import (
    CandidateBlockingConstraint,
    CandidateSpaceProfile,
    CandidateViolationCycle,
    CegarCandidateRecord,
    CegarSearchLedger,
    CegarSearchStatus,
    CegarWindowReport,
    CanonicalCycleSkeleton,
    GraphFirstLocalQuery,
    LocalCycleObligationSet,
    LocalCycleStatus,
    MayViolationGraphSummary,
    TraceCegarReport,
    TraceEvent,
    BlockingReplayReport,
)
from bmo_check_dynamic.proof import run_symbolic_shadow

from .graph_first import (
    _build_candidate_graph,
    _build_candidate_violation_cycle,
    _build_local_obligations,
    _build_local_witness,
    _component_nodes,
    _cycle_local_ids,
    _enumerate_skeleton_cycles,
    _feasibility_status,
    _local_status,
    _reduced_edges,
    _required_local_source_edges,
    _strongly_connected_components,
    replay_candidate_cycle,
)
from .ppo_reduction import (
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
    ppo_certificate_digest,
    replay_ppo_reduction,
)
from .windows import AnalysisWindow


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rotations(values: tuple[tuple[str, ...], ...]) -> Iterable[tuple[tuple[str, ...], ...]]:
    for index in range(len(values)):
        yield values[index:] + values[:index]


def canonicalize_cycle_skeleton(
    candidate: CandidateViolationCycle,
) -> CanonicalCycleSkeleton:
    """构造不依赖 PPO 内部 witness 的稳定候选身份。

    有向环只允许旋转，不允许反向；RF/FR/CO 的 relation id 保留在签名
    中。这样不同的 PPO witness 不会制造新候选，而不同的 RF/CO 假设
    不会被错误合并。
    """

    signatures: list[tuple[str, ...]] = []
    ppo_pairs: set[tuple[str, str]] = set()
    for edge in candidate.ordered_edges:
        if edge.relation_type == "ppo_reachability":
            labels: tuple[str, ...] = ()
            ppo_pairs.add((edge.source_event, edge.target_event))
        elif edge.relation_type == "rf":
            labels = tuple(sorted(edge.rf_candidate_ids or edge.relation_ids))
        elif edge.relation_type == "fr":
            labels = tuple(sorted(edge.fr_consequence_ids or edge.relation_ids))
        elif edge.relation_type == "coherence":
            labels = tuple(sorted(edge.co_dependency_ids or edge.relation_ids))
        else:
            labels = tuple(sorted(edge.relation_ids))
        signatures.append(
            (
                edge.source_event,
                edge.target_event,
                edge.relation_type,
                edge.side,
                "1" if edge.conditional else "0",
                *labels,
            )
        )
    ordered = tuple(signatures)
    canonical_edges = min(_rotations(ordered), default=())
    critical = tuple(
        sorted(
            {
                endpoint
                for edge in candidate.ordered_edges
                for endpoint in (edge.source_event, edge.target_event)
            }
        )
    )
    payload = {
        "edges": canonical_edges,
        "rf": tuple(sorted(candidate.rf_dependencies)),
        "fr": tuple(sorted(candidate.fr_dependencies)),
        "co": tuple(sorted(candidate.co_dependencies)),
        "source_side": candidate.source_side,
        "target": candidate.target_side_condition,
    }
    return CanonicalCycleSkeleton(
        canonical_id=_digest(payload),
        edge_signatures=canonical_edges,
        critical_endpoints=critical,
        rf_candidate_ids=tuple(sorted(candidate.rf_dependencies)),
        fr_dependency_ids=tuple(sorted(candidate.fr_dependencies)),
        co_dependency_ids=tuple(sorted(candidate.co_dependencies)),
        ppo_reachability_pairs=tuple(sorted(ppo_pairs)),
        source_side=candidate.source_side,
        target_side_condition=candidate.target_side_condition,
    )


def _structure_without_conditional_labels(
    skeleton: CanonicalCycleSkeleton,
) -> tuple[tuple[str, ...], ...]:
    """返回用于 profile 的结构 key；不参与 blocking 或 verdict。"""

    result: list[tuple[str, ...]] = []
    for signature in skeleton.edge_signatures:
        # source,target,kind,side,conditional 后去掉 RF/FR/CO labels。
        result.append(signature[:5])
    return tuple(result)


def _obligation_assumptions(
    obligations: LocalCycleObligationSet,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    rf = tuple(sorted(f"rf={value}" for value in obligations.selected_rf_relation_ids))
    fr = tuple(sorted(f"fr={value}" for value in obligations.required_fr_relation_ids))
    co = tuple(sorted(f"co={value}" for value in obligations.required_co_relation_ids))
    return rf, fr, co, tuple(sorted(rf + fr + co))


def _candidate_digest(candidate: CandidateViolationCycle) -> str:
    return _digest(candidate.model_dump(mode="json"))


def _obligation_digest(obligations: LocalCycleObligationSet) -> str:
    return _digest(obligations.model_dump(mode="json"))


def _semantic_context_digest(
    skeleton: CanonicalCycleSkeleton,
    obligations: LocalCycleObligationSet,
) -> str:
    """把 block 绑定到候选结构和局部 obligation，而不是只绑定 event 数。"""

    return _digest(
        {
            "canonical_id": skeleton.canonical_id,
            "edges": skeleton.edge_signatures,
            "source_side": skeleton.source_side,
            "target": skeleton.target_side_condition,
            "rf_domain": obligations.rf_candidate_domain_ids,
            "rf_exclusivity": obligations.rf_exclusivity_preserved,
            "fr": obligations.required_fr_relation_ids,
            "co": obligations.required_co_relation_ids,
            "boundary": obligations.boundary_event_ids,
        }
    )


def _replay_blocking_assumptions(
    candidate: CandidateViolationCycle,
    obligations: LocalCycleObligationSet,
) -> bool:
    """独立检查 block 的 identity/domain；不相信 solver 的内部状态。"""

    if candidate.unresolved_dependencies or not obligations.rf_exclusivity_preserved:
        return False
    selected = set(obligations.selected_rf_relation_ids)
    if not selected <= set(candidate.rf_dependencies):
        return False
    if not set(obligations.required_fr_relation_ids) <= set(candidate.fr_dependencies):
        return False
    if not set(obligations.required_co_relation_ids) <= set(candidate.co_dependencies):
        return False
    # RF domain 至少要包含每一个被选 read 的全部候选；这与候选 replay
    # 使用的 exactly-one obligation 相同，避免把“未记录”当成“不存在”。
    return bool(set(obligations.selected_rf_relation_ids) <= set(obligations.rf_candidate_domain_ids))


def build_blocking_constraint(
    candidate: CandidateViolationCycle,
    skeleton: CanonicalCycleSkeleton,
    obligations: LocalCycleObligationSet,
    *,
    solver_result: str,
    query_digest: str,
) -> CandidateBlockingConstraint | None:
    """只为明确 UNSAT 且可重放的局部查询生成 semantic block。"""

    if solver_result != "unsat" or not _replay_blocking_assumptions(candidate, obligations):
        return None
    rf, fr, co, assumptions = _obligation_assumptions(obligations)
    if rf and co:
        kind = "rf_co"
    elif rf:
        kind = "rf_combination"
    elif fr or co:
        kind = "edge_activation"
    else:
        kind = "exact"
    structure_id = skeleton.canonical_id if kind == "exact" else None
    payload = {
        "kind": kind,
        "assumptions": assumptions,
        "structure": structure_id,
        "query": query_digest,
    }
    return CandidateBlockingConstraint(
        block_id=_digest(payload),
        kind=kind,
        assumptions=assumptions,
        rf_relation_ids=tuple(sorted(obligations.selected_rf_relation_ids)),
        co_relation_ids=tuple(sorted(obligations.required_co_relation_ids)),
        fr_relation_ids=tuple(sorted(obligations.required_fr_relation_ids)),
        canonical_structure_id=structure_id,
        source_candidate_id=candidate.cycle_id,
        source_query_digest=query_digest,
        candidate_digest=_candidate_digest(candidate),
        obligation_digest=_obligation_digest(obligations),
        semantic_context_digest=_semantic_context_digest(skeleton, obligations),
        proof_scope="local-cycle-obligations-v1",
        solver_result=solver_result,
        verified_unsat=True,
        replayable=True,
    )


def blocking_constraint_applies(
    block: CandidateBlockingConstraint,
    skeleton: CanonicalCycleSkeleton,
    obligations: LocalCycleObligationSet,
) -> bool:
    """判断一个已 replay 的 block 是否覆盖当前候选。"""

    if not block.verified_unsat or not block.replayable:
        return False
    expected_assumptions = tuple(
        sorted(
            [*(f"rf={value}" for value in block.rf_relation_ids),
             *(f"fr={value}" for value in block.fr_relation_ids),
             *(f"co={value}" for value in block.co_relation_ids)]
        )
    )
    # 先重放 block 自身的字段关系，再检查它是否覆盖当前候选；这样
    # producer 不能篡改 assumptions 后仍让 verifier 依据一个更弱的字段
    # 集合进行剪枝。
    if block.assumptions != expected_assumptions:
        return False
    if block.solver_result != "unsat":
        return False
    if block.kind == "exact":
        return block.canonical_structure_id == skeleton.canonical_id
    if not set(block.rf_relation_ids) <= set(obligations.selected_rf_relation_ids):
        return False
    if not set(block.fr_relation_ids) <= set(obligations.required_fr_relation_ids):
        return False
    return set(block.co_relation_ids) <= set(obligations.required_co_relation_ids)


def replay_blocking_constraint(
    block: CandidateBlockingConstraint,
    candidate: CandidateViolationCycle,
    skeleton: CanonicalCycleSkeleton,
    obligations: LocalCycleObligationSet,
) -> bool:
    """独立重放 producer 产生的 UNSAT block。

    这里不调用 producer 的 solver 状态，只用候选、obligation 和记录的
    query digest 重新构造期望 block；字段或 provenance 被篡改时拒绝。
    """

    return replay_blocking_constraint_detail(
        block, candidate, skeleton, obligations
    ).accepted


def replay_blocking_constraint_detail(
    block: CandidateBlockingConstraint,
    candidate: CandidateViolationCycle,
    skeleton: CanonicalCycleSkeleton,
    obligations: LocalCycleObligationSet,
) -> BlockingReplayReport:
    """独立返回 block 的绑定/范围检查，供 P13 统计无效剪枝。"""

    reasons: list[str] = []
    query_binding_valid = bool(block.source_query_digest)
    assumption_scope_valid = _replay_blocking_assumptions(candidate, obligations)
    semantic_context_valid = True
    solver_status_valid = block.solver_result == "unsat" and block.verified_unsat
    if not query_binding_valid:
        reasons.append("missing source query digest")
    if not assumption_scope_valid:
        reasons.append("blocking assumptions are outside the local RF/FR/CO domain")
    if not solver_status_valid:
        reasons.append("block is not backed by an UNSAT solver result")
    expected = build_blocking_constraint(
        candidate,
        skeleton,
        obligations,
        solver_result=block.solver_result,
        query_digest=block.source_query_digest,
    )
    if expected is None:
        reasons.append("producer block cannot be reconstructed from the bound query")
    else:
        fields = (
            "block_id",
            "kind",
            "assumptions",
            "rf_relation_ids",
            "co_relation_ids",
            "fr_relation_ids",
            "canonical_structure_id",
            "source_candidate_id",
            "source_query_digest",
            "candidate_digest",
            "obligation_digest",
            "semantic_context_digest",
            "proof_scope",
            "solver_result",
            "verified_unsat",
            "replayable",
        )
        if any(getattr(expected, field) != getattr(block, field) for field in fields):
            semantic_context_valid = False
            reasons.append("block fields do not match the reconstructed query context")
    accepted = not reasons and semantic_context_valid
    return BlockingReplayReport(
        block_id=block.block_id,
        accepted=accepted,
        query_binding_valid=query_binding_valid,
        assumption_scope_valid=assumption_scope_valid,
        semantic_context_valid=semantic_context_valid,
        solver_status_valid=solver_status_valid,
        reasons=tuple(reasons),
    )


def _local_query_for_candidate(
    window: AnalysisWindow,
    graph,
    certificate,
    source_reduced,
    target_reduced,
    cycle: tuple[tuple[str, ...], tuple[object, ...]],
    *,
    candidate_id: str,
    control_flow_closed: bool,
    local_timeout_ms: int,
    local_max_symbolic_terms: int,
    execute_local_solver: bool,
    enable_blocking: bool = True,
) -> tuple[CegarCandidateRecord, str]:
    event_by_id = {event.event_id: event for event in window.events}
    cycle_event_ids = tuple(cycle[0])
    cycle_edges = tuple(cycle[1])
    candidate = _build_candidate_violation_cycle(
        cycle_id=candidate_id,
        cycle_edges=cycle_edges,
        event_by_id=event_by_id,
    )
    skeleton = canonicalize_cycle_skeleton(candidate)
    local_ids = _cycle_local_ids(cycle_edges)
    local_events = tuple(
        sorted(
            (event_by_id[event_id] for event_id in local_ids),
            key=lambda event: (event.thread_id, event.sequence, event.event_id),
        )
    )
    local_window = AnalysisWindow(
        window_id=f"{window.window_id}:cegar:{candidate_id.rsplit(':', 1)[-1]}",
        events=local_events,
        communication_edges=tuple(
            edge
            for edge in window.communication_edges
            if edge.first_event in local_ids and edge.second_event in local_ids
        ),
        event_inclusions=tuple(
            inclusion
            for inclusion in window.event_inclusions
            if inclusion.event_id in local_ids
        ),
    )
    local_source = {
        edge for edge in source_reduced if edge[0] in local_ids and edge[1] in local_ids
    }
    local_target = {
        edge for edge in target_reduced if edge[0] in local_ids and edge[1] in local_ids
    }
    required = frozenset(_required_local_source_edges(cycle_edges))
    local_result, observation = run_symbolic_shadow(
        local_window,
        source_ppo=local_source,
        target_ppo=local_target,
        control_flow_closed=control_flow_closed,
        timeout_ms=local_timeout_ms,
        max_symbolic_terms=local_max_symbolic_terms,
        execute_solver=execute_local_solver,
        required_source_cycle_edges=required,
    )
    query = GraphFirstLocalQuery(
        status=_local_status(observation.result, execute_local_solver),
        feasibility_status=_feasibility_status(observation.result),
        solver_result=observation.result,
        reason=observation.reason,
        event_count=len(local_events),
        source_ppo_edge_count=len(local_source),
        target_ppo_edge_count=len(local_target),
        formula_terms=observation.formula_terms,
        assertion_count=observation.assertion_count,
        z3_ast_count=observation.z3_ast_count,
        build_time_ms=observation.build_time_ms,
        solver_time_ms=observation.solver_time_ms,
    )
    witness = _build_local_witness(candidate, cycle_edges=cycle_edges, local_result=local_result)
    obligations = _build_local_obligations(
        candidate,
        cycle_edges=cycle_edges,
        events=window.events,
        witness=witness,
    )
    replay = replay_candidate_cycle(
        graph,
        certificate,
        candidate,
        obligations,
        witness,
        source_reduced=source_reduced,
        target_reduced=target_reduced,
        events=window.events,
    )
    query_digest = _digest(
        {
            "candidate": candidate.model_dump(mode="json"),
            "obligations": obligations.model_dump(mode="json"),
            "solver_result": observation.result,
        }
    )
    block = None
    if enable_blocking:
        block = build_blocking_constraint(
            candidate,
            skeleton,
            obligations,
            solver_result=observation.result,
            query_digest=query_digest,
        )
        if block is not None and not replay_blocking_constraint(
            block, candidate, skeleton, obligations
        ):
            block = None
    return (
        CegarCandidateRecord(
            candidate_id=candidate_id,
            canonical_skeleton=skeleton,
            candidate_violation_cycle=candidate,
            local_query=query,
            local_obligations=obligations,
            local_witness=witness,
            replay=replay,
            blocking_constraint=block,
        ),
        query_digest,
    )


def _graph_summary(
    events: tuple[TraceEvent, ...], labeled, relation_counts, components, cyclic_components
) -> MayViolationGraphSummary:
    grouped = _component_nodes(components)
    component_edge_counts = {
        component: sum(
            components.get(edge.source) == component
            and components.get(edge.target) == component
            for edge in labeled
        )
        for component in grouped
    }
    return MayViolationGraphSummary(
        node_count=len(events),
        edge_count=len(labeled),
        relation_counts=dict(relation_counts),
        conditional_edge_count=sum(edge.kind != "source_ppo" for edge in labeled),
        scc_count=len(grouped),
        cyclic_scc_count=len(cyclic_components),
        largest_scc_node_count=max((len(nodes) for nodes in grouped.values()), default=0),
        largest_scc_edge_count=max(component_edge_counts.values(), default=0),
        graph_complete_for_observed_candidates=True,
        reasons=(
            "may graph is an over-approximation; missing candidate information remains unknown",
        ),
    )


def characterize_cegar_window(
    window: AnalysisWindow,
    *,
    reduction_certificate=None,
    control_flow_closed: bool = False,
    max_cycle_length: int = 12,
    max_search_states: int = 10_000,
    max_local_queries: int = 1_000,
    max_generated_candidates: int = 100_000,
    local_timeout_ms: int = 1_000,
    local_max_symbolic_terms: int = 100_000,
    execute_local_solver: bool = True,
    canonicalize: bool = True,
    enable_blocking: bool = True,
    mode: str = "P12_CANONICAL_BLOCKING",
) -> CegarWindowReport:
    """执行 bounded CEGAR candidate search；结果始终为 diagnostic-only。

    ``canonicalize`` 和 ``enable_blocking`` 只控制 P13 shadow 对比路径，
    不改变正式 checker 的输入或 verdict。
    """

    limits = (
        max_cycle_length,
        max_search_states,
        max_local_queries,
        max_generated_candidates,
        local_timeout_ms,
        local_max_symbolic_terms,
    )
    if any(value < 1 for value in limits):
        raise ValueError("CEGAR limits must be positive")
    graph = build_ppo_graph_input(window)
    certificate = reduction_certificate
    if certificate is None:
        certificate, reduction_replay = build_ppo_reduction_certificate(graph)
    else:
        reduction_replay = replay_ppo_reduction(graph, certificate)
    source_original = graph.source_edges
    target_original = graph.target_edges
    source_reduced = _reduced_edges(source_original, certificate.source.removed_edges)
    target_reduced = _reduced_edges(target_original, certificate.target.removed_edges)
    reasons = list(reduction_replay.reasons)
    if not reduction_replay.accepted or not certificate.reduction_eligible:
        reasons.append("certified reduced PPO is unavailable; CEGAR did not run")
        return CegarWindowReport(
            window_id=window.window_id,
            event_count=len(window.events),
            mode=mode,
            reduction_certificate_digest=ppo_certificate_digest(certificate),
            source_original_ppo_edges=len(source_original),
            source_reduced_ppo_edges=len(source_reduced),
            target_original_ppo_edges=len(target_original),
            target_reduced_ppo_edges=len(target_reduced),
            reasons=tuple(dict.fromkeys(reasons)),
        )

    labeled, relation_counts, _collapsed_parallel = _build_candidate_graph(
        window.events, source_reduced
    )
    event_ids = tuple(event.event_id for event in window.events)
    components = _strongly_connected_components(event_ids, labeled)
    grouped = _component_nodes(components)
    cyclic_components = {
        component
        for component, nodes in grouped.items()
        if len(nodes) > 1
        or any(
            edge.source == edge.target and components.get(edge.source) == component
            for edge in labeled
        )
    }
    raw_candidates, explored, search_truncated, _skeleton_edges = _enumerate_skeleton_cycles(
        window.events,
        labeled,
        source_reduced,
        components,
        cyclic_components,
        max_cycle_length=max_cycle_length,
        max_cycles=max_generated_candidates,
        max_search_states=max_search_states,
    )
    event_by_id = {event.event_id: event for event in window.events}
    records: list[CegarCandidateRecord] = []
    canonical_ids: set[str] = set()
    structure_seen: dict[tuple[tuple[str, ...], ...], tuple[str, ...]] = {}
    blocks: list[CandidateBlockingConstraint] = []
    block_ids: set[str] = set()
    repeated_cores = 0
    duplicate_count = 0
    rf_variants = 0
    ppo_variants = 0
    blocked_count = 0
    local_query_count = 0
    feasible_count = 0
    infeasible_count = 0
    unknown_count = 0
    not_run_count = 0
    query_truncated = False
    depth_histogram: Counter[str] = Counter(str(len(item[0])) for item in raw_candidates)

    for index, cycle in enumerate(raw_candidates):
        candidate_id = f"{window.window_id}:cegar-{index:06d}"
        # Build a candidate once to canonicalize before spending a solver query.
        candidate = _build_candidate_violation_cycle(
            cycle_id=candidate_id,
            cycle_edges=tuple(cycle[1]),
            event_by_id=event_by_id,
        )
        skeleton = canonicalize_cycle_skeleton(candidate)
        structure_key = _structure_without_conditional_labels(skeleton)
        old_rf = structure_seen.get(structure_key)
        if old_rf is not None and old_rf != skeleton.rf_candidate_ids:
            rf_variants += 1
        elif old_rf is not None:
            ppo_variants += 1
        structure_seen.setdefault(structure_key, skeleton.rf_candidate_ids)
        if canonicalize and skeleton.canonical_id in canonical_ids:
            duplicate_count += 1
            # Keep a compact audit record: duplicate candidates are not silently
            # re-submitted, but their identity remains visible in the report.
            records.append(
                CegarCandidateRecord(
                    candidate_id=candidate_id,
                    canonical_skeleton=skeleton,
                    candidate_violation_cycle=candidate,
                    pruned=True,
                    prune_reason="duplicate canonical cycle skeleton",
                )
            )
            continue
        canonical_ids.add(skeleton.canonical_id)
        obligations = _build_local_obligations(
            candidate,
            cycle_edges=tuple(cycle[1]),
            events=window.events,
            witness=None,
        )
        applicable = None
        if enable_blocking:
            applicable = next(
                (
                    block
                    for block in blocks
                    if blocking_constraint_applies(block, skeleton, obligations)
                ),
                None,
            )
        if applicable is not None:
            blocked_count += 1
            updated = applicable.model_copy(
                update={"pruned_candidate_count": applicable.pruned_candidate_count + 1}
            )
            blocks[blocks.index(applicable)] = updated
            records.append(
                CegarCandidateRecord(
                    candidate_id=candidate_id,
                    canonical_skeleton=skeleton,
                    candidate_violation_cycle=candidate,
                    local_obligations=obligations,
                    pruned=True,
                    prune_reason=f"semantic block {applicable.block_id}",
                )
            )
            continue
        if local_query_count >= max_local_queries:
            query_truncated = True
            break
        record, _query_digest = _local_query_for_candidate(
            window,
            graph,
            certificate,
            source_reduced,
            target_reduced,
            cycle,
            candidate_id=candidate_id,
            control_flow_closed=control_flow_closed,
            local_timeout_ms=local_timeout_ms,
            local_max_symbolic_terms=local_max_symbolic_terms,
            execute_local_solver=execute_local_solver,
            enable_blocking=enable_blocking,
        )
        local_query_count += 1
        if record.local_query is not None:
            status = record.local_query.feasibility_status
            if record.local_query.status.value == "not_run":
                not_run_count += 1
            elif status is LocalCycleStatus.FEASIBLE:
                feasible_count += 1
            elif status is LocalCycleStatus.INFEASIBLE:
                infeasible_count += 1
            else:
                unknown_count += 1
        if record.blocking_constraint is not None:
            block = record.blocking_constraint
            if block.block_id in block_ids:
                repeated_cores += 1
            else:
                block_ids.add(block.block_id)
                blocks.append(block)
        records.append(record)

    if query_truncated:
        reasons.append("local query budget reached before candidate space was explored")
    if search_truncated:
        reasons.append("bounded candidate search reached max_search_states or candidate limit")
    if unknown_count:
        status = CegarSearchStatus.UNKNOWN_REMAINS
    elif not_run_count:
        status = CegarSearchStatus.INCOMPLETE
    elif query_truncated or search_truncated:
        status = CegarSearchStatus.TRUNCATED
    else:
        status = CegarSearchStatus.COMPLETE
    not_explored = (
        None
        if query_truncated or search_truncated
        else max(0, len(raw_candidates) - len(records))
    )
    profile = CandidateSpaceProfile(
        raw_search_states=explored,
        generated_skeletons=len(raw_candidates),
        unique_skeletons=len(canonical_ids) if canonicalize else len(raw_candidates),
        duplicate_skeletons=duplicate_count if canonicalize else 0,
        same_rf_assignment_variants=rf_variants,
        same_structural_cycle_different_ppo_witness=ppo_variants,
        local_smt_submitted=local_query_count,
        exact_blocked_candidates=sum(block.kind == "exact" for block in blocks)
        if enable_blocking
        else 0,
        repeated_infeasible_cores=repeated_cores,
        branching_factor=(explored / max(1, len(raw_candidates))),
        depth_histogram=dict(sorted(depth_histogram.items())),
        search_truncated=search_truncated,
        query_truncated=query_truncated,
    )
    ledger = CegarSearchLedger(
        candidate_space=(
            "bounded may-graph cycle skeletons with certified PPO reachability; "
            "diagnostic-only and not a SAFE completeness proof"
        ),
        may_graph_complete=True,
        status=status,
        raw_search_states=explored,
        generated_count=len(raw_candidates),
        canonical_count=len(canonical_ids),
        duplicate_count=duplicate_count,
        feasible_count=feasible_count,
        infeasible_count=infeasible_count,
        unknown_count=unknown_count,
        not_run_count=not_run_count,
        blocked_count=len(blocks),
        pruned_by_block_count=blocked_count,
        local_query_count=local_query_count,
        not_explored_count=not_explored,
        search_truncated=search_truncated,
        query_truncated=query_truncated,
        frontier_count=not_explored,
        blocking_constraints=tuple(blocks),
    )
    return CegarWindowReport(
        window_id=window.window_id,
        event_count=len(window.events),
        mode=mode,
        reduction_replay_accepted=True,
        reduction_certificate_digest=ppo_certificate_digest(certificate),
        source_original_ppo_edges=len(source_original),
        source_reduced_ppo_edges=len(source_reduced),
        target_original_ppo_edges=len(target_original),
        target_reduced_ppo_edges=len(target_reduced),
        candidate_edge_count=len(labeled),
        relation_counts=dict(relation_counts),
        scc_count=len(grouped),
        cyclic_scc_count=len(cyclic_components),
        largest_scc_node_count=max((len(nodes) for nodes in grouped.values()), default=0),
        largest_scc_edge_count=max(
            (
                sum(
                    components.get(edge.source) == component
                    and components.get(edge.target) == component
                    for edge in labeled
                )
                for component in grouped
            ),
            default=0,
        ),
        candidates=tuple(records),
        profile=profile,
        ledger=ledger,
        reasons=tuple(dict.fromkeys(reasons)),
    )


__all__ = [
    "canonicalize_cycle_skeleton",
    "build_blocking_constraint",
    "blocking_constraint_applies",
    "replay_blocking_constraint",
    "replay_blocking_constraint_detail",
    "characterize_cegar_window",
]
