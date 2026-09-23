from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from bmo_check_dynamic.model import (
    CandidateCycleReplayStatus,
    CandidateReadPartDomain,
    CandidateReadSourceDomain,
    CegarExperimentMode,
    CegarExperimentReport,
    CegarModeComparisonReport,
    CegarModeMetrics,
    DependencyCoverage,
    DependencyCoverageStatus,
    DependencyFamily,
    EventKind,
    FixedCandidateBaseline,
    GraphFirstQueryStatus,
    GraphFirstCandidateCycle,
    IndependentFullWindowQuery,
    IncrementalCandidateCheck,
    IncrementalSessionBuild,
    GlobalConstraintValidationReport,
    ProgressiveCandidateValidation,
    ProgressiveValidationRound,
    LocalCycleStatus,
    TracePpoReductionCertificate,
    TraceEvent,
)
from bmo_check_dynamic.proof import (
    build_incremental_shadow_session,
    run_symbolic_shadow,
)
from bmo_check_dynamic.proof.checker import _overlap_components

from .cycle_relevance import _candidate_relations
from .obligation_bottleneck import _read_parts
from .graph_first import (
    _LabeledEdge,
    _build_local_obligations,
    _build_local_witness,
    _reduced_edges,
    _required_local_source_edges,
    replay_candidate_cycle,
)
from .ppo_reduction import build_ppo_graph_input
from .ppo_reduction import ppo_certificate_digest, replay_ppo_reduction
from .windows import AnalysisWindow


def find_frozen_p15_mode(
    report: CegarExperimentReport,
) -> tuple[CegarModeComparisonReport, CegarModeMetrics]:
    """返回冻结窗口摘要和 P15 指标，避免混用两个报告层级的字段。"""

    matches = [
        (comparison, mode)
        for comparison in report.reports
        for mode in comparison.modes
        if mode.mode is CegarExperimentMode.STRUCTURED_P15
    ]
    if len(matches) != 1:
        raise ValueError("frozen candidate report must contain exactly one P15 mode report")
    return matches[0]


def _candidate_edges(candidate: GraphFirstCandidateCycle) -> tuple[_LabeledEdge, ...]:
    semantic = candidate.candidate_violation_cycle
    if semantic is None:
        return ()
    return tuple(
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


def _relation_inventory_ids(
    relations: tuple[object, ...], source_ppo: frozenset[tuple[str, str]]
) -> set[str]:
    """把内存关系和 PPO 直边放进各自同一轮可用的 relation inventory。"""

    return {item.relation_id for item in relations} | {
        f"ppo:source:{source}:{target}" for source, target in source_ppo
    }


def _read_source_domains(
    window: AnalysisWindow, candidate: GraphFirstCandidateCycle
) -> tuple[CandidateReadSourceDomain, ...]:
    """保存候选 read 每个字节片段的完整 RF 来源域，不把初始写当作事件。"""

    semantic = candidate.candidate_violation_cycle
    if semantic is None:
        return ()
    read_ids = {
        edge.target_event
        for edge in semantic.ordered_edges
        if edge.relation_type == "rf"
    } | {
        edge.source_event
        for edge in semantic.ordered_edges
        if edge.relation_type == "fr"
    }
    event_by_id = {event.event_id: event for event in window.events}
    writes = tuple(event for event in window.events if event.kind.is_write)
    rf_by_read_part: dict[tuple[str, int, int], list[object]] = defaultdict(list)
    for relation in _candidate_relations(window.events):
        if relation.kind == "rf":
            rf_by_read_part[
                (relation.event_ids[1], relation.address, relation.size)
            ].append(relation)

    result: list[CandidateReadSourceDomain] = []
    for read_id in sorted(read_ids):
        read = event_by_id.get(read_id)
        if read is None or not read.kind.is_read:
            continue
        parts: list[CandidateReadPartDomain] = []
        for address, size in _read_parts(read, writes):
            relations = tuple(rf_by_read_part.get((read_id, address, size), ()))
            parts.append(
                CandidateReadPartDomain(
                    address=address,
                    size=size,
                    initial_write_allowed=True,
                    candidate_write_event_ids=tuple(
                        sorted(relation.event_ids[0] for relation in relations)
                    ),
                    relation_ids=tuple(
                        sorted(relation.relation_id for relation in relations)
                    ),
                )
            )
        result.append(
            CandidateReadSourceDomain(read_event_id=read_id, parts=tuple(parts))
        )
    return tuple(result)


def _fixed_candidate_baseline(
    window: AnalysisWindow,
    candidate: GraphFirstCandidateCycle,
    skeleton_id: str,
) -> FixedCandidateBaseline:
    semantic = candidate.candidate_violation_cycle
    if semantic is None or candidate.local_query is None:
        raise ValueError("fixed candidate lacks semantic cycle or fresh local query")
    return FixedCandidateBaseline(
        candidate_id=candidate.cycle_id,
        candidate_skeleton_id=skeleton_id,
        candidate=semantic,
        local_query=candidate.local_query,
        local_replay=candidate.replay,
        read_source_domains=_read_source_domains(window, candidate),
    )


def _seed_event_ids(candidate: GraphFirstCandidateCycle) -> set[str]:
    semantic = candidate.candidate_violation_cycle
    if semantic is None:
        return set()
    selected = set(semantic.cycle_nodes)
    for edge in semantic.ordered_edges:
        selected.update(edge.ppo_reachability_path)
        selected.update(edge.boundary_dependency_ids)
    selected.update(semantic.fence_rmw_futex_dependencies)
    for edge in semantic.ordered_edges:
        selected.update((edge.source_event, edge.target_event))
    return selected


def _add_rf_source_dependencies(
    selected: set[str],
    *,
    event_by_id: dict[str, TraceEvent],
    rf_sources_by_read: dict[str, set[str]],
) -> set[str]:
    before = set(selected)
    for event_id in tuple(selected):
        if event_by_id[event_id].kind.is_read:
            selected.update(rf_sources_by_read.get(event_id, ()))
    return selected - before


def _close_fr_and_co_dependencies(
    selected: set[str],
    *,
    event_by_id: dict[str, TraceEvent],
    fr_targets_by_read: dict[str, set[str]],
    overlap_component_by_write: dict[str, set[str]],
) -> set[str]:
    """加入相关 read 的完整 FR 目标和 write 所在的完整 coherence component。"""

    before = set(selected)
    for event_id in tuple(selected):
        event = event_by_id[event_id]
        if event.kind.is_read:
            selected.update(fr_targets_by_read.get(event_id, ()))
        if event.kind.is_write:
            selected.update(overlap_component_by_write.get(event_id, ()))
    return selected - before


def _close_rf_fr_and_co_dependencies(
    selected: set[str],
    *,
    event_by_id: dict[str, TraceEvent],
    rf_sources_by_read: dict[str, set[str]],
    fr_targets_by_read: dict[str, set[str]],
    overlap_component_by_write: dict[str, set[str]],
) -> set[str]:
    """把 RF 来源、FR 目标和 CO component 一直补到稳定。"""

    before = set(selected)
    while True:
        added_rf_sources = _add_rf_source_dependencies(
            selected,
            event_by_id=event_by_id,
            rf_sources_by_read=rf_sources_by_read,
        )
        added_fr_co = _close_fr_and_co_dependencies(
            selected,
            event_by_id=event_by_id,
            fr_targets_by_read=fr_targets_by_read,
            overlap_component_by_write=overlap_component_by_write,
        )
        if not added_rf_sources and not added_fr_co:
            return selected - before


def _coverage_for_scope(
    *,
    candidate: GraphFirstCandidateCycle,
    selected: set[str],
    full_event_ids: set[str],
    rf_relations_by_read: dict[str, tuple[object, ...]],
    fr_relations_by_read: dict[str, tuple[object, ...]],
    overlap_component_by_write: dict[str, set[str]],
    all_target_event_ids: set[str],
    read_event_ids: set[str],
    available_relation_ids: set[str],
) -> tuple[DependencyCoverage, ...]:
    semantic = candidate.candidate_violation_cycle
    if semantic is None:
        return ()
    coverage: list[DependencyCoverage] = []

    def add(
        dependency_id: str,
        family: DependencyFamily,
        event_ids: tuple[str, ...],
        relation_ids: tuple[str, ...],
        explanation: str,
    ) -> None:
        present = (
            set(event_ids) <= selected
            and set(relation_ids) <= available_relation_ids
        )
        coverage.append(
            DependencyCoverage(
                dependency_id=dependency_id,
                family=family,
                event_ids=event_ids,
                relation_ids=relation_ids,
                status=(
                    DependencyCoverageStatus.COVERED
                    if present
                    else DependencyCoverageStatus.NOT_COVERED
                ),
                explanation=explanation,
            )
        )

    add(
        f"candidate-core:{candidate.cycle_id}",
        DependencyFamily.CANDIDATE_CORE,
        tuple(sorted(_seed_event_ids(candidate))),
        tuple(
            sorted(
                relation_id
                for edge in semantic.ordered_edges
                for relation_id in edge.relation_ids
            )
        ),
        "候选环端点、PPO witness path 和显式 boundary event 必须都在本轮查询中。",
    )
    # 每个进入本轮编码器的 read 都会得到 RF/FR 变量。报告其本轮 relation
    # inventory，避免 thread-span 新加入的 read 被误报为 relation-closed。
    candidate_reads = selected & read_event_ids
    candidate_reads.update(
        edge.target_event
        for edge in semantic.ordered_edges
        if edge.relation_type == "rf"
    )
    candidate_reads.update(
        edge.source_event
        for edge in semantic.ordered_edges
        if edge.relation_type == "fr"
    )
    for read_id in sorted(candidate_reads):
        rf_values = rf_relations_by_read.get(read_id, ())
        rf_event_ids = tuple(
            sorted({read_id, *(item.event_ids[0] for item in rf_values)})
        )
        add(
            f"rf-domain:{read_id}",
            DependencyFamily.RF_SOURCE_DOMAIN,
            rf_event_ids,
            tuple(sorted(item.relation_id for item in rf_values)),
            "列出该 read 在完整窗口中的全部 byte-part RF 来源；初始写是模型中的 -1 选项，不伪造为 trace event。",
        )
        fr_values = fr_relations_by_read.get(read_id, ())
        fr_event_ids = tuple(
            sorted({read_id, *(item.event_ids[1] for item in fr_values)})
        )
        add(
            f"fr-domain:{read_id}",
            DependencyFamily.FR_LATER_WRITE,
            fr_event_ids,
            tuple(sorted(item.relation_id for item in fr_values)),
            "列出该 read 后所有可能产生 from-read 边的重叠写；不只检查候选环当前选中的 FR。",
        )

    for write_id in sorted(
        event_id
        for event_id in selected
        if event_id in overlap_component_by_write
    ):
        component = tuple(sorted(overlap_component_by_write[write_id]))
        add(
            f"co-component:{write_id}",
            DependencyFamily.COHERENCE_COMPONENT,
            component,
            (),
            "共享任意字节的写必须使用同一完整 coherence component；component 外事件仍可能约束全窗。",
        )

    for index, path in enumerate(semantic.ppo_reachability_dependencies):
        add(
            f"source-ppo-path:{index}",
            DependencyFamily.SOURCE_PPO_PATH,
            tuple(path),
            (),
            "候选 source PPO 摘要边依赖其完整 reduced-graph witness path。",
        )
    boundary_ids = tuple(sorted(set(semantic.fence_rmw_futex_dependencies)))
    if boundary_ids:
        add(
            "candidate-boundaries",
            DependencyFamily.BOUNDARY,
            boundary_ids,
            (),
            "候选引用的 Fence/RMW/FUTEX boundary 必须保留；其他线程和远距离边界尚未覆盖。",
        )

    full_scope = selected == full_event_ids
    coverage.append(
        DependencyCoverage(
            dependency_id="global-target-acyclicity-and-window-closure",
            family=DependencyFamily.FULL_WINDOW,
            event_ids=tuple(sorted(all_target_event_ids - selected)),
            relation_ids=(),
            status=(
                DependencyCoverageStatus.COVERED
                if full_scope
                else DependencyCoverageStatus.UNKNOWN
            ),
            explanation=(
                "全窗口事件及 target-order/acyclicity 约束均已加入。"
                if full_scope
                else "未纳入事件仍可能带来 target PPO、RF 来源、CO/FR 或另一个 target cycle；不能据局部结果判断与候选无关。"
            ),
        )
    )
    return tuple(coverage)


def run_progressive_candidate_validation(
    window: AnalysisWindow,
    certificate,
    candidate: GraphFirstCandidateCycle,
    *,
    candidate_skeleton_id: str,
    control_flow_closed: bool,
    partial_timeout_ms: int,
    full_timeout_ms: int,
    max_symbolic_terms: int,
) -> ProgressiveCandidateValidation:
    """按依赖类别逐轮扩窗；部分 SAT/UNSAT 始终只作为诊断结果。"""

    semantic = candidate.candidate_violation_cycle
    if semantic is None:
        return ProgressiveCandidateValidation(
            candidate_id=candidate.cycle_id,
            candidate_skeleton_id=candidate_skeleton_id,
            window_id=window.window_id,
            full_window_event_count=len(window.events),
            final_full_query_result="unknown",
        )

    graph = build_ppo_graph_input(window)
    source_reduced = _reduced_edges(
        graph.source_edges, certificate.source.removed_edges
    )
    target_reduced = _reduced_edges(
        graph.target_edges, certificate.target.removed_edges
    )
    event_by_id = {event.event_id: event for event in window.events}
    full_event_ids = set(event_by_id)
    candidate_edges = _candidate_edges(candidate)
    required = _required_local_source_edges(candidate_edges)
    relations = _candidate_relations(window.events)
    rf_relations_by_read_values: dict[str, list[object]] = defaultdict(list)
    fr_relations_by_read_values: dict[str, list[object]] = defaultdict(list)
    rf_sources_by_read: dict[str, set[str]] = defaultdict(set)
    fr_targets_by_read: dict[str, set[str]] = defaultdict(set)
    for relation in relations:
        if relation.kind == "rf":
            rf_relations_by_read_values[relation.owner_event_id].append(relation)
            rf_sources_by_read[relation.owner_event_id].add(relation.event_ids[0])
        elif relation.kind == "fr":
            fr_relations_by_read_values[relation.owner_event_id].append(relation)
            fr_targets_by_read[relation.owner_event_id].add(relation.event_ids[1])
    rf_relations_by_read = {
        key: tuple(values) for key, values in rf_relations_by_read_values.items()
    }
    fr_relations_by_read = {
        key: tuple(values) for key, values in fr_relations_by_read_values.items()
    }
    writes = tuple(event for event in window.events if event.kind.is_write)
    overlap_component_by_write: dict[str, set[str]] = {}
    for component in _overlap_components(writes):
        component_ids = {event.event_id for event in component}
        for event_id in component_ids:
            overlap_component_by_write[event_id] = component_ids

    selected = _seed_event_ids(candidate) & full_event_ids
    rounds: list[ProgressiveValidationRound] = []
    latest_replay_status = "not_run"
    latest_replay_reasons: tuple[str, ...] = ()
    final_result = "not_reached"

    def execute_round(index: int, stage: str, added: set[str]) -> None:
        nonlocal latest_replay_status, latest_replay_reasons, final_result
        before_count = len(selected) - len(added)
        round_events = tuple(
            event for event in window.events if event.event_id in selected
        )
        full_window = selected == full_event_ids
        source_edges = {
            edge
            for edge in source_reduced
            if edge[0] in selected and edge[1] in selected
        }
        target_edges = {
            edge
            for edge in target_reduced
            if edge[0] in selected and edge[1] in selected
        }
        query_window = AnalysisWindow(window.window_id, round_events, ())
        timeout_ms = full_timeout_ms if full_window else partial_timeout_ms
        result, observation = run_symbolic_shadow(
            query_window,
            source_ppo=source_edges,
            target_ppo=target_edges,
            control_flow_closed=control_flow_closed,
            timeout_ms=timeout_ms,
            max_symbolic_terms=max_symbolic_terms,
            execute_solver=True,
            required_source_cycle_edges=required.endpoints,
            required_source_cycle_relations=required.relation_groups,
            capture_model=full_window,
        )
        if full_window:
            final_result = observation.result
        scoped_relations = _candidate_relations(round_events)
        relation_counts = {
            kind: sum(item.kind == kind for item in scoped_relations)
            for kind in ("rf", "fr", "coherence")
        }
        coverage = _coverage_for_scope(
            candidate=candidate,
            selected=selected,
            full_event_ids=full_event_ids,
            rf_relations_by_read=rf_relations_by_read,
            fr_relations_by_read=fr_relations_by_read,
            overlap_component_by_write=overlap_component_by_write,
            all_target_event_ids=full_event_ids,
            read_event_ids={
                event.event_id for event in window.events if event.kind.is_read
            },
            available_relation_ids=_relation_inventory_ids(
                scoped_relations, frozenset(source_edges)
            ),
        )
        unresolved = sum(
            item.status
            in {
                DependencyCoverageStatus.NOT_COVERED,
                DependencyCoverageStatus.UNKNOWN,
            }
            for item in coverage
        )
        unresolved_events = len(full_event_ids - selected)
        termination = (
            "full-window query returned " + observation.result
            if full_window
            else "partial result is diagnostic only; remaining dependencies keep full status open"
        )
        if observation.result == "unknown":
            termination = observation.reason or "solver returned unknown"
        elif observation.result == "resource_limited":
            termination = observation.reason or "formula resource limit"

        if full_window and result.witness is not None:
            cycle_edges = candidate_edges
            witness = _build_local_witness(
                semantic,
                cycle_edges=cycle_edges,
                local_result=result,
            )
            if witness is not None:
                obligations = _build_local_obligations(
                    semantic,
                    cycle_edges=cycle_edges,
                    events=window.events,
                    witness=witness,
                    query_event_ids=tuple(event.event_id for event in window.events),
                    window_event_ids=tuple(event.event_id for event in window.events),
                )
                replay = replay_candidate_cycle(
                    graph,
                    certificate,
                    semantic,
                    obligations,
                    witness,
                    source_reduced=source_reduced,
                    target_reduced=target_reduced,
                    events=window.events,
                )
                latest_replay_status = replay.status.value
                latest_replay_reasons = replay.reasons
                if replay.status is CandidateCycleReplayStatus.FULL_WINDOW_MODEL_VALIDATED:
                    termination = "full-window symbolic model independently replayed"
        rounds.append(
            ProgressiveValidationRound(
                round_index=index,
                stage=stage,
                scope="full_window" if full_window else "partial_diagnostic",
                full_window=full_window,
                event_count_before=before_count,
                event_count_after=len(selected),
                added_event_ids=tuple(sorted(added)),
                source_ppo_edge_count=len(source_edges),
                target_ppo_edge_count=len(target_edges),
                relation_counts=relation_counts,
                formula_terms=observation.formula_terms,
                assertion_count=observation.assertion_count,
                ast_node_count=observation.z3_ast_count,
                encode_ms=observation.build_time_ms,
                solver_ms=observation.solver_time_ms,
                solver_result=observation.result,
                unresolved_dependency_count=unresolved,
                unresolved_event_count=unresolved_events,
                termination_reason=termination,
            )
        )

    # 第一轮仅包含候选环端点；其关系域尚未闭合，所以不建立 SMT 查询。
    rounds.append(
        ProgressiveValidationRound(
            round_index=0,
            stage="candidate_core_inventory",
            scope="partial_diagnostic",
            full_window=False,
            event_count_before=0,
            event_count_after=len(selected),
            added_event_ids=tuple(sorted(selected)),
            solver_result="not_run",
            unresolved_dependency_count=1,
            unresolved_event_count=len(full_event_ids - selected),
            termination_reason="候选 read 的完整 RF 来源域和 global order 尚未纳入，不创建可能被误解的 SMT 子问题。",
        )
    )

    added = _add_rf_source_dependencies(
        selected,
        event_by_id=event_by_id,
        rf_sources_by_read=rf_sources_by_read,
    )
    execute_round(1, "complete_rf_fr_and_overlap_domains", added)

    # 把 candidate-read 的全部 FR 目标和相关写入 coherence component 显式成批加入。
    before = set(selected)
    for read_id in {
        event_id
        for event_id in selected
        if event_by_id[event_id].kind.is_read
    }:
        selected.update(fr_targets_by_read.get(read_id, ()))
    _close_rf_fr_and_co_dependencies(
        selected,
        event_by_id=event_by_id,
        rf_sources_by_read=rf_sources_by_read,
        fr_targets_by_read=fr_targets_by_read,
        overlap_component_by_write=overlap_component_by_write,
    )
    execute_round(2, "fr_later_writes_and_coherence_components", selected - before)

    # 线程内隔着未纳入 event 的 PPO 或 boundary 仍可能形成约束，先补入相关线程跨度。
    before = set(selected)
    by_thread: dict[int, list[TraceEvent]] = defaultdict(list)
    for event in window.events:
        by_thread[event.thread_id].append(event)
    for thread_events in by_thread.values():
        thread_events.sort(key=lambda event: event.sequence)
        positions = [
            index
            for index, event in enumerate(thread_events)
            if event.event_id in selected
        ]
        if positions:
            selected.update(
                event.event_id
                for event in thread_events[min(positions) : max(positions) + 1]
            )
    _close_rf_fr_and_co_dependencies(
        selected,
        event_by_id=event_by_id,
        rf_sources_by_read=rf_sources_by_read,
        fr_targets_by_read=fr_targets_by_read,
        overlap_component_by_write=overlap_component_by_write,
    )
    execute_round(3, "thread_order_and_boundary_spans", selected - before)

    before = set(selected)
    selected.update(full_event_ids)
    execute_round(4, "restore_global_window_constraints", selected - before)

    final_coverage = _coverage_for_scope(
        candidate=candidate,
        selected=selected,
        full_event_ids=full_event_ids,
        rf_relations_by_read=rf_relations_by_read,
        fr_relations_by_read=fr_relations_by_read,
        overlap_component_by_write=overlap_component_by_write,
        all_target_event_ids=full_event_ids,
        read_event_ids={
            event.event_id for event in window.events if event.kind.is_read
        },
        available_relation_ids=_relation_inventory_ids(
            relations, source_reduced
        ),
    )
    full_model_validated = (
        final_result == "sat"
        and latest_replay_status
        == CandidateCycleReplayStatus.FULL_WINDOW_MODEL_VALIDATED.value
    )
    return ProgressiveCandidateValidation(
        candidate_id=candidate.cycle_id,
        candidate_skeleton_id=candidate_skeleton_id,
        window_id=window.window_id,
        full_window_event_count=len(window.events),
        rounds=tuple(rounds),
        dependency_coverage=final_coverage,
        final_full_query_result=final_result,
        final_full_query_replay_status=latest_replay_status,
        final_full_query_replay_reasons=latest_replay_reasons,
        has_full_window_model_validated=full_model_validated,
    )


def _candidate_replay_for_full_query(
    window: AnalysisWindow,
    graph,
    certificate,
    candidate: GraphFirstCandidateCycle,
    source_reduced,
    target_reduced,
    *,
    control_flow_closed: bool,
    timeout_ms: int,
    max_symbolic_terms: int,
):
    """对独立 full-window SAT 查询取得模型，并由既有 replay 从头验证。"""

    semantic = candidate.candidate_violation_cycle
    if semantic is None:
        return None, None, "not_run", ("candidate has no semantic cycle",)
    edges = _candidate_edges(candidate)
    required = _required_local_source_edges(edges)
    result, observation = run_symbolic_shadow(
        window,
        source_ppo=set(source_reduced),
        target_ppo=set(target_reduced),
        control_flow_closed=control_flow_closed,
        timeout_ms=timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        execute_solver=True,
        required_source_cycle_edges=required.endpoints,
        required_source_cycle_relations=required.relation_groups,
        capture_model=True,
    )
    replay_status = "not_run"
    replay_reasons: tuple[str, ...] = ()
    if result.witness is not None:
        witness = _build_local_witness(
            semantic,
            cycle_edges=edges,
            local_result=result,
        )
        obligations = _build_local_obligations(
            semantic,
            cycle_edges=edges,
            events=window.events,
            witness=witness,
            query_event_ids=tuple(event.event_id for event in window.events),
            window_event_ids=tuple(event.event_id for event in window.events),
        )
        replay = replay_candidate_cycle(
            graph,
            certificate,
            semantic,
            obligations,
            witness,
            source_reduced=source_reduced,
            target_reduced=target_reduced,
            events=window.events,
        )
        replay_status = replay.status.value
        replay_reasons = replay.reasons
    return result, observation, replay_status, replay_reasons


def run_global_constraint_validation(
    window: AnalysisWindow,
    certificate,
    candidates: tuple[GraphFirstCandidateCycle, ...],
    *,
    candidate_skeleton_ids: dict[str, str],
    trace_id: str,
    trace_sha256: str,
    contract_sha256: str,
    fixed_candidate_report_sha256: str = "",
    control_flow_closed: bool,
    partial_timeout_ms: int,
    full_timeout_ms: int,
    max_symbolic_terms: int,
    max_queries_per_solver_session: int,
    process_wall_limit_seconds: int,
    process_memory_limit_mb: int | None,
    progress_callback: Callable[[GlobalConstraintValidationReport], None] | None = None,
) -> GlobalConstraintValidationReport:
    """运行 shadow-only 的渐进式查询和共享完整公式 A/B。"""

    if max_queries_per_solver_session < 1:
        raise ValueError("max_queries_per_solver_session must be positive")
    if len({candidate.cycle_id for candidate in candidates}) != len(candidates):
        raise ValueError("fixed candidate IDs must be unique")
    if any(candidate.cycle_id not in candidate_skeleton_ids for candidate in candidates):
        raise ValueError("every fixed candidate must have a stable skeleton identity")
    if any(
        candidate.candidate_violation_cycle is None or candidate.local_query is None
        for candidate in candidates
    ):
        raise ValueError("fixed candidates must include semantic cycles and local queries")
    graph = build_ppo_graph_input(window)
    certificate_replay = replay_ppo_reduction(graph, certificate)
    certificate_digest = ppo_certificate_digest(certificate)
    skeleton_ids = tuple(candidate_skeleton_ids[candidate.cycle_id] for candidate in candidates)
    if not certificate_replay.accepted:
        return GlobalConstraintValidationReport(
            trace_id=trace_id,
            trace_sha256=trace_sha256,
            contract_sha256=contract_sha256,
            window_id=window.window_id,
            event_count=len(window.events),
            ppo_certificate_digest=certificate_digest,
            fixed_candidate_report_sha256=fixed_candidate_report_sha256,
            candidate_skeleton_ids=skeleton_ids,
            max_partial_timeout_ms=partial_timeout_ms,
            max_full_timeout_ms=full_timeout_ms,
            max_symbolic_terms=max_symbolic_terms,
            max_queries_per_solver_session=max_queries_per_solver_session,
            process_wall_limit_seconds=process_wall_limit_seconds,
            process_memory_limit_mb=process_memory_limit_mb,
            termination_reason="ppo_certificate_replay_rejected",
            limitations=certificate_replay.reasons,
        )

    source_reduced = _reduced_edges(
        graph.source_edges, certificate.source.removed_edges
    )
    target_reduced = _reduced_edges(
        graph.target_edges, certificate.target.removed_edges
    )
    fixed_baseline = tuple(
        _fixed_candidate_baseline(
            window,
            candidate,
            candidate_skeleton_ids[candidate.cycle_id],
        )
        for candidate in candidates
    )
    progressive: list[ProgressiveCandidateValidation] = []
    independent_queries: list[IndependentFullWindowQuery] = []
    session_builds: list[IncrementalSessionBuild] = []
    shared_queries: list[IncrementalCandidateCheck] = []

    def emit_progress() -> None:
        if progress_callback is None:
            return
        progress_callback(
            GlobalConstraintValidationReport(
                trace_id=trace_id,
                trace_sha256=trace_sha256,
                contract_sha256=contract_sha256,
                window_id=window.window_id,
                event_count=len(window.events),
                ppo_certificate_digest=certificate_digest,
                fixed_candidate_report_sha256=fixed_candidate_report_sha256,
                candidate_skeleton_ids=skeleton_ids,
                fixed_candidate_baseline=fixed_baseline,
                progressive_runs=tuple(progressive),
                independent_full_queries=tuple(independent_queries),
                shared_incremental_queries=tuple(shared_queries),
                incremental_session_builds=tuple(session_builds),
                max_partial_timeout_ms=partial_timeout_ms,
                max_full_timeout_ms=full_timeout_ms,
                max_symbolic_terms=max_symbolic_terms,
                max_queries_per_solver_session=max_queries_per_solver_session,
                process_wall_limit_seconds=process_wall_limit_seconds,
                process_memory_limit_mb=process_memory_limit_mb,
                termination_reason="in_progress",
                limitations=(
                    "Checkpoint contains only completed candidate/solver-session units.",
                    "All current results are shadow diagnostics, not formal verdicts.",
                ),
            )
        )

    for candidate in candidates:
        skeleton_id = candidate_skeleton_ids.get(candidate.cycle_id)
        if skeleton_id is None:
            continue
        item = run_progressive_candidate_validation(
            window,
            certificate,
            candidate,
            candidate_skeleton_id=skeleton_id,
            control_flow_closed=control_flow_closed,
            partial_timeout_ms=partial_timeout_ms,
            full_timeout_ms=full_timeout_ms,
            max_symbolic_terms=max_symbolic_terms,
        )
        progressive.append(item)
        final_round = next(
            (round_item for round_item in reversed(item.rounds) if round_item.full_window),
            None,
        )
        if final_round is not None:
            independent_queries.append(
                IndependentFullWindowQuery(
                    candidate_id=candidate.cycle_id,
                    candidate_skeleton_id=skeleton_id,
                    formula_terms=final_round.formula_terms,
                    assertion_count=final_round.assertion_count,
                    ast_node_count=final_round.ast_node_count,
                    encode_ms=final_round.encode_ms,
                    solver_ms=final_round.solver_ms,
                    solver_result=final_round.solver_result,
                    replay_status=item.final_full_query_replay_status,
                    replay_reasons=item.final_full_query_replay_reasons,
                )
            )
        emit_progress()

    progressive_by_id = {item.candidate_id: item for item in progressive}
    for offset in range(0, len(candidates), max_queries_per_solver_session):
        batch = candidates[offset : offset + max_queries_per_solver_session]
        session_index = len(session_builds)
        session, base = build_incremental_shadow_session(
            window,
            source_ppo=set(source_reduced),
            target_ppo=set(target_reduced),
            control_flow_closed=control_flow_closed,
            timeout_ms=full_timeout_ms,
            max_symbolic_terms=max_symbolic_terms,
        )
        if session is None:
            session_builds.append(
                IncrementalSessionBuild(
                    session_index=session_index,
                    candidate_query_count=0,
                    base_formula_terms=base.formula_terms,
                    base_assertion_count=base.assertion_count,
                    base_ast_node_count=base.z3_ast_count,
                    base_encode_ms=base.build_time_ms,
                    peak_rss_mb=base.peak_rss_mb,
                    status=base.result,
                    reason=base.reason,
                )
            )
            for candidate in batch:
                skeleton_id = candidate_skeleton_ids.get(candidate.cycle_id)
                if skeleton_id is None or candidate.candidate_violation_cycle is None:
                    continue
                shared_queries.append(
                    IncrementalCandidateCheck(
                        candidate_id=candidate.cycle_id,
                        candidate_skeleton_id=skeleton_id,
                        session_index=session_index,
                        query_index_in_session=0,
                        base_formula_terms=base.formula_terms,
                        base_assertion_count=base.assertion_count,
                        base_ast_node_count=base.z3_ast_count,
                        base_encode_ms=base.build_time_ms,
                        candidate_added_assertions=0,
                        candidate_added_ast_nodes=0,
                        candidate_constraint_build_ms=0,
                        candidate_push_pop_ms=0,
                        solver_ms=None,
                        peak_rss_mb=base.peak_rss_mb,
                        solver_result="unknown",
                        reason=base.reason or "shared full-window base formula was not built",
                        independent_full_query_result=(
                            progressive_by_id[candidate.cycle_id].final_full_query_result
                        ),
                        result_matches_independent_full=(
                            progressive_by_id[candidate.cycle_id].final_full_query_result
                            == "unknown"
                        ),
                        independent_full_replay_status=(
                            progressive_by_id[candidate.cycle_id].final_full_query_replay_status
                        ),
                    )
                )
            emit_progress()
            continue

        session_query_count = 0
        batch_checks: list[tuple[GraphFirstCandidateCycle, object]] = []
        for query_index, candidate in enumerate(batch):
            skeleton_id = candidate_skeleton_ids.get(candidate.cycle_id)
            if skeleton_id is None or candidate.candidate_violation_cycle is None:
                continue
            edges = _candidate_edges(candidate)
            required = _required_local_source_edges(edges)
            check = session.check_candidate(
                required_source_cycle_edges=required.endpoints,
                required_source_cycle_relations=required.relation_groups,
                timeout_ms=full_timeout_ms,
            )
            session_query_count += 1
            batch_checks.append((candidate, check))
            shared_queries.append(
                IncrementalCandidateCheck(
                    candidate_id=candidate.cycle_id,
                    candidate_skeleton_id=skeleton_id,
                    session_index=session_index,
                    query_index_in_session=query_index,
                    base_formula_terms=session.base_formula_terms,
                    base_assertion_count=session.base_assertions,
                    base_ast_node_count=session.base_ast_nodes,
                    base_encode_ms=session.base_build_ms,
                    candidate_added_assertions=check.added_assertions,
                    candidate_added_ast_nodes=check.added_ast_nodes,
                    candidate_constraint_build_ms=check.build_ms,
                    candidate_push_pop_ms=check.push_pop_ms,
                    solver_ms=check.solver_ms,
                    peak_rss_mb=check.peak_rss_mb,
                    solver_result=check.result,
                    reason=check.reason,
                    independent_full_query_result=(
                        progressive_by_id[candidate.cycle_id].final_full_query_result
                    ),
                    result_matches_independent_full=(
                        check.result
                        == progressive_by_id[candidate.cycle_id].final_full_query_result
                    ),
                    independent_full_replay_status=(
                        progressive_by_id[candidate.cycle_id].final_full_query_replay_status
                    ),
                )
            )
        session_builds.append(
            IncrementalSessionBuild(
                session_index=session_index,
                candidate_query_count=session_query_count,
                base_formula_terms=session.base_formula_terms,
                base_assertion_count=session.base_assertions,
                base_ast_node_count=session.base_ast_nodes,
                base_encode_ms=session.base_build_ms,
                peak_rss_mb=base.peak_rss_mb,
            )
        )

        # 同一批里若 shared solver 给出 SAT，而独立 full query 没有通过 replay，
        # 再用新建的独立 solver 重跑；shared solver 的 SAT 本身绝不升级为验证通过。
        for candidate, check in batch_checks:
            if check.result != "sat":
                continue
            pgv = progressive_by_id.get(candidate.cycle_id)
            if (
                pgv is not None
                and pgv.final_full_query_replay_status
                == CandidateCycleReplayStatus.FULL_WINDOW_MODEL_VALIDATED.value
            ):
                continue
            _, recheck, replay_status, replay_reasons = _candidate_replay_for_full_query(
                window,
                graph,
                certificate,
                candidate,
                source_reduced,
                target_reduced,
                control_flow_closed=control_flow_closed,
                timeout_ms=full_timeout_ms,
                max_symbolic_terms=max_symbolic_terms,
            )
            query_index = next(
                index
                for index in range(len(shared_queries) - len(batch_checks), len(shared_queries))
                if shared_queries[index].candidate_id == candidate.cycle_id
            )
            shared_queries[query_index] = shared_queries[query_index].model_copy(
                update={
                    "independent_recheck_result": recheck.result,
                    "independent_replay_status": replay_status,
                    "independent_replay_reasons": replay_reasons,
                }
            )
        del session
        emit_progress()

    return GlobalConstraintValidationReport(
        trace_id=trace_id,
        trace_sha256=trace_sha256,
        contract_sha256=contract_sha256,
        window_id=window.window_id,
        event_count=len(window.events),
        ppo_certificate_digest=certificate_digest,
        fixed_candidate_report_sha256=fixed_candidate_report_sha256,
        candidate_skeleton_ids=skeleton_ids,
        fixed_candidate_baseline=fixed_baseline,
        progressive_runs=tuple(progressive),
        independent_full_queries=tuple(independent_queries),
        shared_incremental_queries=tuple(shared_queries),
        incremental_session_builds=tuple(session_builds),
        max_partial_timeout_ms=partial_timeout_ms,
        max_full_timeout_ms=full_timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        max_queries_per_solver_session=max_queries_per_solver_session,
        process_wall_limit_seconds=process_wall_limit_seconds,
        process_memory_limit_mb=process_memory_limit_mb,
        limitations=(
            "Progressive partial SAT/UNSAT is diagnostic only and is not a full-window result.",
            "Shared incremental SAT requires an independent full-window replay before it can be called model-validated.",
            "The process memory limit is enforced by the outer experiment launcher, not by this in-process runner.",
        ),
    )
