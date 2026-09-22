from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from bmo_check_dynamic.model import (
    GraphFirstCandidateCycle,
    GraphFirstEdge,
    GraphFirstLocalQuery,
    GraphFirstQueryStatus,
    GraphFirstWindowReport,
    TraceEvent,
    TraceGraphFirstReport,
)
from bmo_check_dynamic.proof import run_symbolic_shadow
from bmo_check_dynamic.proof.relations import Edge

from .cycle_relevance import _candidate_relations
from .ppo_reduction import (
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
    ppo_certificate_digest,
    replay_ppo_reduction,
)
from .windows import AnalysisWindow


@dataclass(frozen=True, slots=True)
class _LabeledEdge:
    source: str
    target: str
    kind: str
    relation_id: str


def characterize_graph_first_window(
    window: AnalysisWindow,
    *,
    reduction_certificate=None,
    control_flow_closed: bool = False,
    max_cycle_length: int = 12,
    max_cycles: int = 32,
    max_search_states: int = 100_000,
    local_timeout_ms: int = 1_000,
    local_max_symbolic_terms: int = 100_000,
    execute_local_solver: bool = True,
) -> GraphFirstWindowReport:
    """寻找有界候选坏环，并对每个候选做局部 shadow SMT 查询。

    该函数故意不调用 ``check_window``。图搜索和局部查询都可能截断，
    因而结果只描述诊断证据，不能改变正式的 UNKNOWN/SAFE/反例语义。
    """

    _validate_limits(
        max_cycle_length,
        max_cycles,
        max_search_states,
        local_timeout_ms,
        local_max_symbolic_terms,
    )
    graph = build_ppo_graph_input(window)
    certificate = reduction_certificate
    if certificate is None:
        certificate, replay = build_ppo_reduction_certificate(graph)
    else:
        replay = replay_ppo_reduction(graph, certificate)
    source_original = graph.source_edges
    target_original = graph.target_edges
    source_reduced = _reduced_edges(source_original, certificate.source.removed_edges)
    target_reduced = _reduced_edges(target_original, certificate.target.removed_edges)
    reasons = list(replay.reasons)
    if not replay.accepted or not certificate.reduction_eligible:
        reasons.append("certified reduced PPO is unavailable; local graph search not run")
        return GraphFirstWindowReport(
            window_id=window.window_id,
            event_count=len(window.events),
            reduction_replay_accepted=False,
            reduction_certificate_digest=ppo_certificate_digest(certificate),
            source_original_ppo_edges=len(source_original),
            source_reduced_ppo_edges=len(source_reduced),
            target_original_ppo_edges=len(target_original),
            target_reduced_ppo_edges=len(target_reduced),
            max_cycle_length=max_cycle_length,
            max_cycles=max_cycles,
            max_search_states=max_search_states,
            reasons=tuple(dict.fromkeys(reasons)),
        )

    labeled, relation_counts, collapsed_parallel = _build_candidate_graph(
        window.events, source_reduced
    )
    if collapsed_parallel:
        reasons.append(
            f"collapsed {collapsed_parallel} parallel RF/FR/CO labels for bounded search"
        )
    components = _strongly_connected_components(
        tuple(event.event_id for event in window.events), labeled
    )
    cyclic_components = {
        component
        for component, nodes in _component_nodes(components).items()
        if len(nodes) > 1
        or any(edge.source == edge.target and components.get(edge.source) == component for edge in labeled)
    }
    candidates, explored, truncated = _enumerate_cycles(
        labeled,
        components,
        cyclic_components,
        max_cycle_length=max_cycle_length,
        max_cycles=max_cycles,
        max_search_states=max_search_states,
    )
    if truncated:
        reasons.append("bounded graph search reached a configured limit")
    if not candidates:
        reasons.append("no non-PPO candidate cycle was found within the bound")

    event_by_id = {event.event_id: event for event in window.events}
    reports: list[GraphFirstCandidateCycle] = []
    for index, cycle in enumerate(candidates):
        cycle_event_ids = tuple(cycle[0])
        cycle_edges = tuple(cycle[1])
        local_ids = set(cycle_event_ids)
        local_events = tuple(
            sorted(
                (event_by_id[event_id] for event_id in local_ids),
                key=lambda event: (event.thread_id, event.sequence, event.event_id),
            )
        )
        local_window = AnalysisWindow(
            window_id=f"{window.window_id}:cycle-{index:04d}",
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
        local_source = {edge for edge in source_reduced if edge[0] in local_ids and edge[1] in local_ids}
        local_target = {edge for edge in target_reduced if edge[0] in local_ids and edge[1] in local_ids}
        required = frozenset((edge.source, edge.target) for edge in cycle_edges)
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
        reports.append(
            GraphFirstCandidateCycle(
                cycle_id=f"{window.window_id}:cycle-{index:04d}",
                event_ids=cycle_event_ids + (cycle_event_ids[0],),
                edges=tuple(
                    GraphFirstEdge(
                        source_event=edge.source,
                        target_event=edge.target,
                        relation_kind=edge.kind,
                        relation_id=edge.relation_id,
                    )
                    for edge in cycle_edges
                ),
                includes_non_ppo=any(edge.kind != "source_ppo" for edge in cycle_edges),
                local_query=query,
            )
        )
        # Keep the result variable visible in this diagnostic route: the
        # observation is intentionally the only accepted summary of the query.
        del local_result

    return GraphFirstWindowReport(
        window_id=window.window_id,
        event_count=len(window.events),
        reduction_replay_accepted=True,
        reduction_certificate_digest=ppo_certificate_digest(certificate),
        source_original_ppo_edges=len(source_original),
        source_reduced_ppo_edges=len(source_reduced),
        target_original_ppo_edges=len(target_original),
        target_reduced_ppo_edges=len(target_reduced),
        candidate_edge_count=len(labeled),
        relation_counts=dict(relation_counts),
        scc_count=len(_component_nodes(components)),
        cyclic_scc_count=len(cyclic_components),
        explored_states=explored,
        cycles_considered=len(candidates),
        cycles_returned=len(reports),
        truncated=truncated,
        max_cycle_length=max_cycle_length,
        max_cycles=max_cycles,
        max_search_states=max_search_states,
        candidates=tuple(reports),
        reasons=tuple(dict.fromkeys(reasons)),
    )


def graph_first_trace(
    trace_id: str,
    windows: tuple[AnalysisWindow, ...],
    *,
    reduction_certificates: dict[str, object] | None = None,
    control_flow_closed: bool = False,
    max_cycle_length: int = 12,
    max_cycles: int = 32,
    max_search_states: int = 100_000,
    local_timeout_ms: int = 1_000,
    local_max_symbolic_terms: int = 100_000,
    execute_local_solver: bool = True,
    trace_complete: bool = False,
    reasons: tuple[str, ...] = (),
) -> TraceGraphFirstReport:
    """对已恢复窗口运行 graph-first shadow，不进入正式 pipeline verdict。"""

    certificates = reduction_certificates or {}
    reports = tuple(
        characterize_graph_first_window(
            window,
            reduction_certificate=certificates.get(window.window_id),
            control_flow_closed=control_flow_closed,
            max_cycle_length=max_cycle_length,
            max_cycles=max_cycles,
            max_search_states=max_search_states,
            local_timeout_ms=local_timeout_ms,
            local_max_symbolic_terms=local_max_symbolic_terms,
            execute_local_solver=execute_local_solver,
        )
        for window in windows
    )
    return TraceGraphFirstReport(
        trace_id=trace_id,
        trace_complete=trace_complete,
        analysis_reached_windows=True,
        windows=reports,
        reasons=reasons,
    )


def _validate_limits(*values: int) -> None:
    if any(value < 1 for value in values):
        raise ValueError("graph-first limits must be positive")


def _reduced_edges(original: frozenset[Edge], removed: tuple[object, ...]) -> frozenset[Edge]:
    removed_edges = {
        (item.source_event, item.target_event)
        for item in removed
    }
    return frozenset(original - removed_edges)


def _build_candidate_graph(
    events: tuple[TraceEvent, ...],
    source_ppo: frozenset[Edge],
) -> tuple[tuple[_LabeledEdge, ...], Counter[str], int]:
    event_by_id = {event.event_id: event for event in events}
    values: dict[tuple[str, str, str], _LabeledEdge] = {}
    counts: Counter[str] = Counter()
    for left, right in source_ppo:
        values[(left, right, "source_ppo")] = _LabeledEdge(
            left, right, "source_ppo", f"ppo:source:{left}:{right}"
        )
        counts["source_ppo"] += 1
    collapsed = 0
    for candidate in _candidate_relations(events):
        left, right = candidate.event_ids
        if candidate.kind == "rf" and event_by_id[left].thread_id == event_by_id[right].thread_id:
            continue
        key = (left, right, candidate.kind)
        counts[candidate.kind] += 1
        if key in values:
            collapsed += 1
            continue
        values[key] = _LabeledEdge(left, right, candidate.kind, candidate.relation_id)
    return tuple(sorted(values.values(), key=lambda edge: (edge.source, edge.target, edge.kind, edge.relation_id))), counts, collapsed


def _component_nodes(components: dict[str, int]) -> dict[int, set[str]]:
    result: dict[int, set[str]] = defaultdict(set)
    for node, component in components.items():
        result[component].add(node)
    return result


def _strongly_connected_components(
    nodes: tuple[str, ...], edges: tuple[_LabeledEdge, ...]
) -> dict[str, int]:
    adjacency: dict[str, list[str]] = defaultdict(list)
    reverse: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        adjacency[node]
        reverse[node]
    for edge in edges:
        adjacency[edge.source].append(edge.target)
        reverse[edge.target].append(edge.source)
    visited: set[str] = set()
    order: list[str] = []
    for start in nodes:
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                order.append(node)
                continue
            stack.append((node, True))
            for target in sorted(adjacency[node], reverse=True):
                if target not in visited:
                    visited.add(target)
                    stack.append((target, False))
    components: dict[str, int] = {}
    component_id = 0
    for start in reversed(order):
        if start in components:
            continue
        components[start] = component_id
        stack = [start]
        while stack:
            node = stack.pop()
            for source in sorted(reverse[node]):
                if source not in components:
                    components[source] = component_id
                    stack.append(source)
        component_id += 1
    return components


def _enumerate_cycles(
    edges: tuple[_LabeledEdge, ...],
    components: dict[str, int],
    cyclic_components: set[int],
    *,
    max_cycle_length: int,
    max_cycles: int,
    max_search_states: int,
) -> tuple[list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]], int, bool]:
    adjacency: dict[str, list[_LabeledEdge]] = defaultdict(list)
    for edge in edges:
        adjacency[edge.source].append(edge)
    for values in adjacency.values():
        values.sort(key=lambda edge: (edge.target, edge.kind, edge.relation_id))
    candidates: list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]] = []
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    explored = 0
    truncated = False
    for start in sorted(components):
        if components[start] not in cyclic_components or len(candidates) >= max_cycles:
            continue
        path_nodes = [start]
        path_edges: list[_LabeledEdge] = []

        def visit(node: str) -> None:
            nonlocal explored, truncated
            if explored >= max_search_states or len(candidates) >= max_cycles:
                truncated = True
                return
            if len(path_nodes) >= max_cycle_length:
                return
            for edge in adjacency[node]:
                if explored >= max_search_states or len(candidates) >= max_cycles:
                    truncated = True
                    return
                explored += 1
                if edge.target == start and len(path_nodes) >= 2:
                    cycle_edges = tuple(path_edges + [edge])
                    if not any(item.kind != "source_ppo" for item in cycle_edges):
                        continue
                    key = (
                        tuple(path_nodes),
                        tuple(item.relation_id for item in cycle_edges),
                    )
                    if key not in seen:
                        seen.add(key)
                        candidates.append((tuple(path_nodes), cycle_edges))
                    continue
                if edge.target in path_nodes or edge.target < start:
                    continue
                if components.get(edge.target) != components.get(start):
                    continue
                path_nodes.append(edge.target)
                path_edges.append(edge)
                visit(edge.target)
                path_edges.pop()
                path_nodes.pop()

        visit(start)
        if truncated:
            break
    return candidates, explored, truncated


def _local_status(result: str, execute_solver: bool) -> GraphFirstQueryStatus:
    if not execute_solver:
        return GraphFirstQueryStatus.NOT_RUN
    if result == "sat":
        return GraphFirstQueryStatus.SAT_CANDIDATE
    if result == "unsat":
        return GraphFirstQueryStatus.UNSAT_LOCAL
    return GraphFirstQueryStatus.UNKNOWN_LOCAL


__all__ = ["characterize_graph_first_window", "graph_first_trace"]
