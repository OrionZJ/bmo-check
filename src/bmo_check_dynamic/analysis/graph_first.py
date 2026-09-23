from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Iterator

try:  # pragma: no cover - Windows development uses None RSS samples.
    import resource as _resource
except ImportError:  # pragma: no cover
    _resource = None

from bmo_check_dynamic.model import (
    CandidateBlockingClause,
    CandidateDiscoveryProfile,
    CandidateDiscoveryResourcePolicy,
    CandidateCycleReplay,
    CandidateCycleReplayStatus,
    CandidateReplayFailure,
    CandidateReplayFailureKind,
    CandidateSearchLedger,
    CandidateViolationCycle,
    CandidateViolationEdge,
    GraphFirstCandidateCycle,
    GraphFirstEdge,
    GraphFirstLocalQuery,
    GraphFirstQueryStatus,
    GraphFirstWindowReport,
    LocalCycleObligationSet,
    LocalCycleStatus,
    LocalCycleWitness,
    MayViolationGraphSummary,
    TraceEvent,
    TraceGraphFirstReport,
)
from bmo_check_dynamic.proof import run_symbolic_shadow
from bmo_check_dynamic.proof.relations import Edge, find_cycle

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
    relation_ids: tuple[str, ...] = ()
    witness_path: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _LazyPathNode:
    """共享父链，避免每个兄弟状态复制整条 path tuple。"""

    event_id: str
    edge: _LabeledEdge | None
    parent: "_LazyPathNode | None"
    depth: int


@dataclass(frozen=True, slots=True)
class _LazyStructuredState:
    seed_index: int
    start: str
    current: str
    path: _LazyPathNode
    used_relations: frozenset[str]
    next_successor_index: int = 0


@dataclass(frozen=True, slots=True)
class _LazyTransition:
    reach_edge: _LabeledEdge
    next_edge: _LabeledEdge | None
    candidate: bool


def _rss_mb() -> float | None:
    if _resource is None:
        return None
    value = float(_resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss)
    return value / 1024.0


def _shallow_size(value: object) -> int:
    """估算画像对象大小；不递归遍历整个图，避免画像本身制造压力。"""

    size = sys.getsizeof(value)
    if isinstance(value, dict):
        size += sum(sys.getsizeof(key) + sys.getsizeof(item) for key, item in islice(value.items(), 64))
    elif isinstance(value, (tuple, list, set, frozenset, deque)):
        size += sum(sys.getsizeof(item) for item in islice(iter(value), 64))
    return size


def _structured_memory_sample(
    frontier: deque[_LazyStructuredState] | deque[tuple[object, ...]],
    oracle: "_ReachabilityOracle",
    *,
    pending_seed_indices: deque[int] | None = None,
    seen: set[object] | None = None,
    candidates: list[object] | None = None,
    skeleton_edges: dict[object, object] | None = None,
) -> dict[str, object]:
    sample = list(islice(frontier, 64))
    state_bytes = sum(_shallow_size(item) for item in sample)
    average_state = state_bytes / len(sample) if sample else 0.0
    estimated_frontier = int(len(frontier) * average_state)
    path_bytes = sum(
        _shallow_size(item.path) if isinstance(item, _LazyStructuredState) else _shallow_size(item)
        for item in sample
    )
    cache_bytes = _shallow_size(oracle.source_cache) + _shallow_size(oracle.path_cache)
    # 只对容器和少量元素做浅层估计。这里的目的是解释 RSS 曲线，
    # 不是递归遍历整个 frontier；后者本身会制造额外内存压力。
    components = {
        "frontier_states": estimated_frontier,
        "frontier_path_sample": path_bytes,
        "reachability_cache": cache_bytes,
        "dedup_seen": _shallow_size(seen) if seen is not None else 0,
        "candidate_store": _shallow_size(candidates) if candidates is not None else 0,
        "skeleton_edge_index": _shallow_size(skeleton_edges)
        if skeleton_edges is not None
        else 0,
        "pending_seed_queue": _shallow_size(pending_seed_indices)
        if pending_seed_indices is not None
        else 0,
    }
    return {
        "expanded_states": None,
        "frontier_states": len(frontier),
        "rss_mb": _rss_mb(),
        "estimated_frontier_bytes": estimated_frontier,
        "estimated_state_bytes": int(average_state),
        "estimated_path_bytes": path_bytes,
        "estimated_reachability_cache_bytes": cache_bytes,
        "memory_components": components,
        "dedup_count": len(seen) if seen is not None else 0,
        "candidate_count": len(candidates) if candidates is not None else 0,
        "pending_seed_count": len(pending_seed_indices)
        if pending_seed_indices is not None
        else 0,
        "sample_state_count": len(sample),
    }


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
    discovery_scheduler: str = "depth_first",
    evaluate_candidates: bool = True,
    capture_model: bool = False,
    discovery_resource_policy: CandidateDiscoveryResourcePolicy | None = None,
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
    may_components = _strongly_connected_components(
        tuple(event.event_id for event in window.events), labeled
    )
    components = may_components
    cyclic_components = {
        component
        for component, nodes in _component_nodes(components).items()
        if len(nodes) > 1
        or any(edge.source == edge.target and components.get(edge.source) == component for edge in labeled)
    }
    discovery_data: dict[str, object] = {}
    candidates, explored, truncated, skeleton_edges = _enumerate_skeleton_cycles(
        window.events,
        labeled,
        source_reduced,
        components,
        cyclic_components,
        max_cycle_length=max_cycle_length,
        max_cycles=max_cycles,
        max_search_states=max_search_states,
        scheduler=discovery_scheduler,
        profile=discovery_data,
        resource_policy=discovery_resource_policy,
        binding_scope=(
            f"{window.window_id}:{ppo_certificate_digest(certificate)}"
            if discovery_resource_policy is not None
            else None
        ),
    )
    if truncated:
        reasons.append("bounded graph search reached a configured limit")
    if not candidates:
        reasons.append("no non-PPO candidate cycle was found within the bound")
    if not evaluate_candidates:
        reasons.append("candidate evaluation skipped; discovery-only profile")

    event_by_id = {event.event_id: event for event in window.events}
    reports: list[GraphFirstCandidateCycle] = []
    for index, cycle in enumerate(candidates):
        cycle_event_ids = tuple(cycle[0])
        cycle_edges = tuple(cycle[1])
        local_ids = _cycle_local_ids(cycle_edges)
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
        candidate = _build_candidate_violation_cycle(
            cycle_id=f"{window.window_id}:cycle-{index:04d}",
            cycle_edges=cycle_edges,
            event_by_id=event_by_id,
        )
        if evaluate_candidates:
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
                capture_model=capture_model,
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
            witness_started = time.perf_counter()
            local_witness = _build_local_witness(
                candidate,
                cycle_edges=cycle_edges,
                local_result=local_result,
            )
            witness_build_ms = max(
                0, int((time.perf_counter() - witness_started) * 1000)
            )
            # RF/CO 的端点也必须成为 local query 的必要条件；否则 solver
            # 可能用另一条 conditional edge 闭合一个不同的环，而 replay
            # 看到的却仍是 producer 声称的 candidate。
            obligations_started = time.perf_counter()
            obligations = _build_local_obligations(
                candidate,
                cycle_edges=cycle_edges,
                events=window.events,
                witness=local_witness,
                query_event_ids=tuple(event.event_id for event in local_events),
            )
            obligations_build_ms = max(
                0, int((time.perf_counter() - obligations_started) * 1000)
            )
            replay_started = time.perf_counter()
            replay = replay_candidate_cycle(
                graph,
                certificate,
                candidate,
                obligations,
                local_witness,
                source_reduced=source_reduced,
                target_reduced=target_reduced,
                events=window.events,
            )
            replay_ms = max(0, int((time.perf_counter() - replay_started) * 1000))
            blocking = (
                _blocking_clause(candidate, obligations, observation.result)
                if query.feasibility_status is LocalCycleStatus.INFEASIBLE
                else None
            )
        else:
            query = None
            local_witness = None
            obligations = None
            replay = None
            witness_build_ms = 0
            obligations_build_ms = 0
            replay_ms = 0
            blocking = None
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
                        relation_ids=edge.relation_ids,
                        side="source",
                        conditional=edge.kind not in {"source_ppo", "ppo_reachability"},
                        witness_path=edge.witness_path,
                    )
                    for edge in cycle_edges
                ),
                includes_non_ppo=any(
                    edge.kind not in {"source_ppo", "ppo_reachability"}
                    for edge in cycle_edges
                ),
                local_query=query,
                candidate_violation_cycle=candidate,
                local_obligations=obligations,
                local_witness=local_witness,
                replay=replay,
                witness_build_ms=witness_build_ms,
                obligations_build_ms=obligations_build_ms,
                replay_ms=replay_ms,
                blocking_clause=blocking,
            )
        )
        # Keep the result variable visible in this diagnostic route: the
        # observation is intentionally the only accepted summary of the query.
        if evaluate_candidates:
            del local_result

    component_nodes = _component_nodes(may_components)
    component_edge_counts = {
        component: sum(
            may_components.get(edge.source) == component
            and may_components.get(edge.target) == component
            for edge in labeled
        )
        for component in component_nodes
    }
    may_graph = MayViolationGraphSummary(
        node_count=len(event_by_id),
        edge_count=len(labeled),
        relation_counts=dict(relation_counts),
        conditional_edge_count=sum(edge.kind != "source_ppo" for edge in labeled),
        scc_count=len(component_nodes),
        cyclic_scc_count=len(cyclic_components),
        largest_scc_node_count=max((len(nodes) for nodes in component_nodes.values()), default=0),
        largest_scc_edge_count=max(component_edge_counts.values(), default=0),
        graph_complete_for_observed_candidates=True,
        reasons=(
            "all observed RF/FR/CO candidate labels are retained; "
            "parallel labels may share one topology edge",
        ),
    )
    blocking_clauses = tuple(
        item.blocking_clause
        for item in reports
        if item.blocking_clause is not None
    )
    feasible_count = sum(
        item.local_query is not None
        and item.local_query.feasibility_status is LocalCycleStatus.FEASIBLE
        for item in reports
    )
    infeasible_count = sum(
        item.local_query is not None
        and item.local_query.feasibility_status is LocalCycleStatus.INFEASIBLE
        for item in reports
    )
    unknown_count = sum(
        item.local_query is None
        or (
            item.local_query.feasibility_status is LocalCycleStatus.UNKNOWN
            and item.local_query.solver_result != "not_run"
        )
        for item in reports
    )
    not_run_count = sum(
        item.local_query is not None
        and item.local_query.solver_result == "not_run"
        for item in reports
    )
    ledger = CandidateSearchLedger(
        candidate_space=(
            "bounded simple cycles in the may graph containing source PPO "
            "reachability and at least one RF/FR/CO edge"
        ),
        may_graph_complete=True,
        generated_count=len(reports),
        feasible_count=feasible_count,
        infeasible_count=infeasible_count,
        unknown_count=unknown_count,
        blocked_count=len(blocking_clauses),
        not_run_count=not_run_count,
        not_explored_count=None if truncated else 0,
        search_truncated=truncated,
        blocking_clauses=blocking_clauses,
    )

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
        may_graph=may_graph,
        search_ledger=ledger,
        discovery_profile=(
            CandidateDiscoveryProfile(**discovery_data)
            if discovery_data
            else None
        ),
        skeleton_edge_count=len(skeleton_edges),
        skeleton_scc_count=len(
            _component_nodes(
                _strongly_connected_components(
                    tuple(event.event_id for event in window.events),
                    tuple(skeleton_edges),
                )
            )
        ),
        skeleton_cyclic_scc_count=_cyclic_component_count(
            tuple(event.event_id for event in window.events),
            tuple(skeleton_edges),
        ),
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
            left,
            right,
            "source_ppo",
            f"ppo:source:{left}:{right}",
            (f"ppo:source:{left}:{right}",),
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
            previous = values[key]
            labels = tuple(sorted(set(previous.relation_ids) | {candidate.relation_id}))
            values[key] = _LabeledEdge(
                previous.source,
                previous.target,
                previous.kind,
                labels[0],
                labels,
            )
            continue
        values[key] = _LabeledEdge(
            left,
            right,
            candidate.kind,
            candidate.relation_id,
            (candidate.relation_id,),
        )
    return (
        tuple(
            sorted(
                values.values(),
                key=lambda edge: (edge.source, edge.target, edge.kind, edge.relation_id),
            )
        ),
        counts,
        collapsed,
    )


@dataclass(slots=True)
class _ReachabilityOracle:
    """按需查询 certified reduced PPO，避免构造全对全 reachability 图。"""

    events: dict[str, TraceEvent]
    adjacency: dict[str, tuple[str, ...]]
    source_cache: dict[str, dict[str, tuple[str, ...]]]
    path_cache: dict[tuple[str, str], tuple[str, ...] | None]
    cache_sources: bool = True
    cache_paths: bool = True
    query_count: int = 0
    cache_hit_count: int = 0

    @classmethod
    def build(
        cls,
        events: tuple[TraceEvent, ...],
        edges: frozenset[Edge],
        *,
        cache_sources: bool = True,
        cache_paths: bool = True,
    ) -> "_ReachabilityOracle":
        adjacency: dict[str, list[str]] = defaultdict(list)
        for left, right in edges:
            adjacency[left].append(right)
        return cls(
            events={event.event_id: event for event in events},
            adjacency={
                event_id: tuple(sorted(values))
                for event_id, values in adjacency.items()
            },
            source_cache={},
            path_cache={},
            cache_sources=cache_sources,
            cache_paths=cache_paths,
        )

    def path(self, source: str, target: str) -> tuple[str, ...] | None:
        key = (source, target)
        if self.cache_paths and key in self.path_cache:
            return self.path_cache[key]
        if source == target:
            if self.cache_paths:
                self.path_cache[key] = ()
            return ()
        first, last = self.events.get(source), self.events.get(target)
        if first is None or last is None or first.thread_id != last.thread_id:
            if self.cache_paths:
                self.path_cache[key] = None
            return None
        parent: dict[str, str | None] = {source: None}
        pending: deque[str] = deque([source])
        while pending:
            current = pending.popleft()
            for neighbor in self.adjacency.get(current, ()):
                if neighbor in parent:
                    continue
                parent[neighbor] = current
                if neighbor == target:
                    path: list[str] = [target]
                    while path[-1] != source:
                        previous = parent[path[-1]]
                        if previous is None:
                            if self.cache_paths:
                                self.path_cache[key] = None
                            return None
                        path.append(previous)
                    path.reverse()
                    value = tuple(path)
                    if self.cache_paths:
                        self.path_cache[key] = value
                    return value
                pending.append(neighbor)
        if self.cache_paths:
            self.path_cache[key] = None
        return None

    def reachable_sources(
        self,
        source: str,
        targets_by_thread: dict[int, set[str]],
    ) -> dict[str, tuple[str, ...]]:
        self.query_count += 1
        cached = self.source_cache.get(source) if self.cache_sources else None
        if cached is not None:
            self.cache_hit_count += 1
            return cached
        event = self.events.get(source)
        if event is None:
            if self.cache_sources:
                self.source_cache[source] = {}
            return {}
        targets = targets_by_thread.get(event.thread_id, set())
        found: dict[str, tuple[str, ...]] = {}
        pending: deque[str] = deque([source])
        parent: dict[str, str | None] = {source: None}
        while pending:
            current = pending.popleft()
            if current in targets:
                if current == source:
                    found[current] = ()
                else:
                    path: list[str] = [current]
                    while path[-1] != source:
                        previous = parent[path[-1]]
                        if previous is None:
                            break
                        path.append(previous)
                    if path[-1] == source:
                        path.reverse()
                        found[current] = tuple(path)
            for neighbor in self.adjacency.get(current, ()):
                if neighbor not in parent:
                    parent[neighbor] = current
                    pending.append(neighbor)
        if self.cache_sources:
            self.source_cache[source] = found
        if self.cache_paths:
            for target, path in found.items():
                self.path_cache[(source, target)] = path
        return found


def _enumerate_skeleton_cycles(
    events: tuple[TraceEvent, ...],
    may_edges: tuple[_LabeledEdge, ...],
    source_ppo: frozenset[Edge],
    components: dict[str, int],
    cyclic_components: set[int],
    *,
    max_cycle_length: int,
    max_cycles: int,
    max_search_states: int,
    scheduler: str = "depth_first",
    profile: dict[str, object] | None = None,
    resource_policy: CandidateDiscoveryResourcePolicy | None = None,
    binding_scope: str | None = None,
) -> tuple[
    list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]],
    int,
    bool,
    tuple[_LabeledEdge, ...],
]:
    """从 conditional edges 出发，懒查询 PPO reachability 并生成 skeleton。"""

    if scheduler == "fair_structured":
        return _enumerate_structured_skeleton_cycles(
            events,
            may_edges,
            source_ppo,
            components,
            cyclic_components,
            max_cycle_length=max_cycle_length,
            max_cycles=max_cycles,
            max_search_states=max_search_states,
            profile=profile,
        )
    if scheduler == "bounded_lazy_p15":
        return _enumerate_bounded_lazy_skeleton_cycles(
            events,
            may_edges,
            source_ppo,
            components,
            cyclic_components,
            max_cycle_length=max_cycle_length,
            max_cycles=max_cycles,
            max_search_states=max_search_states,
            resource_policy=resource_policy,
            profile=profile,
            binding_scope=binding_scope,
        )
    if scheduler != "depth_first":
        raise ValueError(f"unknown candidate discovery scheduler: {scheduler}")

    conditional = tuple(edge for edge in may_edges if edge.kind != "source_ppo")
    if profile is not None:
        profile.update(
            {
                "scheduler": "depth_first",
                "fair_seed_scheduling": False,
                "conditional_seed_count": len(conditional),
                "max_cycle_length": max_cycle_length,
                "max_search_states": max_search_states,
            }
        )
    by_source: dict[str, list[_LabeledEdge]] = defaultdict(list)
    targets_by_thread: dict[int, set[str]] = defaultdict(set)
    event_by_id = {event.event_id: event for event in events}
    for edge in conditional:
        by_source[edge.source].append(edge)
        event = event_by_id.get(edge.source)
        if event is not None:
            targets_by_thread[event.thread_id].add(edge.source)
    oracle = _ReachabilityOracle.build(events, source_ppo)
    for values in by_source.values():
        values.sort(key=lambda edge: (edge.target, edge.kind, edge.relation_id))

    candidates: list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]] = []
    skeleton_edges: dict[tuple[str, str, str], _LabeledEdge] = {}
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    explored = 0
    truncated = False

    for start_edge in conditional:
        if len(candidates) >= max_cycles:
            truncated = True
            break
        if (
            components.get(start_edge.source) not in cyclic_components
            or components.get(start_edge.target) != components.get(start_edge.source)
        ):
            continue
        start = start_edge.source
        path_nodes = [start, start_edge.target]
        path_edges = [start_edge]
        used_relations = {start_edge.relation_id}

        def visit(current: str) -> None:
            nonlocal explored, truncated
            if explored >= max_search_states or len(candidates) >= max_cycles:
                truncated = True
                return
            if len(path_nodes) >= max_cycle_length:
                return
            event = event_by_id.get(current)
            if event is None:
                return
            reachable = oracle.reachable_sources(current, targets_by_thread)
            for next_source, ppo_path in sorted(reachable.items()):
                if components.get(next_source) != components.get(start):
                    continue
                reach_edge: _LabeledEdge | None = None
                if ppo_path:
                    relation_ids = tuple(
                        f"ppo:source:{left}:{right}"
                        for left, right in zip(ppo_path, ppo_path[1:])
                    )
                    reach_edge = _LabeledEdge(
                        current,
                        next_source,
                        "ppo_reachability",
                        f"ppo-reach:source:{current}:{next_source}",
                        relation_ids,
                        ppo_path,
                    )
                    skeleton_edges[(reach_edge.source, reach_edge.target, reach_edge.kind)] = reach_edge
                # PPO reachability 本身也可以闭合候选环。典型 LB 环在
                # 最后一条 RF 之后回到起始 Load；此时起始 Load 没有
                # 必须再次消费的 conditional edge，若只在下面的
                # ``next_edge.target == start`` 分支闭合，会漏掉这个环。
                if reach_edge is not None and next_source == start:
                    completed = tuple(path_edges + [reach_edge])
                    if any(
                        item.kind in {"source_ppo", "ppo_reachability"}
                        for item in completed
                    ) and any(
                        item.kind not in {"source_ppo", "ppo_reachability"}
                        for item in completed
                    ):
                        key = (
                            tuple(path_nodes),
                            tuple(edge.relation_id for edge in completed),
                        )
                        if key not in seen:
                            seen.add(key)
                            candidates.append((tuple(path_nodes), completed))
                            if len(candidates) >= max_cycles:
                                truncated = True
                                return
                if next_source in path_nodes and next_source != start:
                    # skeleton 也保持简单环约束；PPO 中间节点不计入
                    # path_nodes，但 conditional endpoint 不能在环内重复。
                    continue
                for next_edge in by_source.get(next_source, ()):
                    if explored >= max_search_states or len(candidates) >= max_cycles:
                        truncated = True
                        return
                    explored += 1
                    if next_edge.relation_id in used_relations:
                        continue
                    if next_edge.target == start:
                        completed = tuple(path_edges + ([reach_edge] if reach_edge else []) + [next_edge])
                        # 只有包含 source PPO reachability 的环才可能体现
                        # source/target ordering 的差异。仅由 RF/FR/CO
                        # 闭合的环在两侧都会出现，不能冒充 target-only
                        # candidate；跳过它们也避免小预算被这种短环耗尽。
                        if not any(
                            item.kind in {"source_ppo", "ppo_reachability"}
                            for item in completed
                        ):
                            continue
                        key = (
                            tuple(path_nodes),
                            tuple(edge.relation_id for edge in completed),
                        )
                        if key not in seen:
                            seen.add(key)
                            candidates.append((tuple(path_nodes), completed))
                        skeleton_edges[(next_edge.source, next_edge.target, next_edge.kind)] = next_edge
                        continue
                    if next_edge.target in path_nodes:
                        continue
                    if components.get(next_edge.target) != components.get(start):
                        continue
                    addition = [item for item in (reach_edge, next_edge) if item is not None]
                    path_nodes.append(next_edge.target)
                    path_edges.extend(addition)
                    used_relations.add(next_edge.relation_id)
                    skeleton_edges[(next_edge.source, next_edge.target, next_edge.kind)] = next_edge
                    if len(path_nodes) <= max_cycle_length:
                        visit(next_edge.target)
                    used_relations.remove(next_edge.relation_id)
                    del path_edges[-len(addition):]
                    path_nodes.pop()

        visit(start_edge.target)
        if truncated:
            break
    if profile is not None:
        profile.update(
            {
                "seeds_visited": len(conditional),
                "ppo_reachability_queries": len(oracle.source_cache),
                "ppo_reachability_cache_hits": 0,
                "path_expansions": explored,
                "rejected_cycles": 0,
                "rejection_reasons": {},
                "generated_skeletons": len(candidates),
                "unique_skeletons": len(seen),
                "remaining_frontier": None if truncated else 0,
                "search_truncated": truncated,
            }
        )
    return candidates, explored, truncated, tuple(skeleton_edges.values())


def _enumerate_structured_skeleton_cycles(
    events: tuple[TraceEvent, ...],
    may_edges: tuple[_LabeledEdge, ...],
    source_ppo: frozenset[Edge],
    components: dict[str, int],
    cyclic_components: set[int],
    *,
    max_cycle_length: int,
    max_cycles: int,
    max_search_states: int,
    profile: dict[str, object] | None = None,
) -> tuple[
    list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]],
    int,
    bool,
    tuple[_LabeledEdge, ...],
]:
    """用条件边种子和 round-robin 前沿生成结构化候选。

    这条路径只改变诊断候选的遍历顺序和计数，不改变 may graph、PPO
    certificate 或正式 checker。前沿被显式保留，达到边界时只能报告
    截断，不能把未访问的种子当作不存在。
    """

    conditional = tuple(
        sorted(
            (edge for edge in may_edges if edge.kind != "source_ppo"),
            key=lambda edge: (edge.source, edge.target, edge.kind, edge.relation_id),
        )
    )
    event_by_id = {event.event_id: event for event in events}
    by_source: dict[str, list[_LabeledEdge]] = defaultdict(list)
    targets_by_thread: dict[int, set[str]] = defaultdict(set)
    for edge in conditional:
        by_source[edge.source].append(edge)
        source_event = event_by_id.get(edge.source)
        if source_event is not None:
            targets_by_thread[source_event.thread_id].add(edge.source)
    for values in by_source.values():
        values.sort(key=lambda edge: (edge.target, edge.kind, edge.relation_id))
    oracle = _ReachabilityOracle.build(events, source_ppo)
    candidates: list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]] = []
    skeleton_edges: dict[tuple[str, str, str], _LabeledEdge] = {}
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    rejection_reasons: Counter[str] = Counter()
    # state: seed index, start event, current event, conditional endpoints,
    # edges (including reachability summaries), used relation ids.
    frontier: deque[
        tuple[int, str, str, tuple[str, ...], tuple[_LabeledEdge, ...], frozenset[str]]
    ] = deque()
    for index, seed in enumerate(conditional):
        component = components.get(seed.source)
        if component not in cyclic_components or components.get(seed.target) != component:
            rejection_reasons["seed_outside_cyclic_scc"] += 1
            continue
        frontier.append(
            (
                index,
                seed.source,
                seed.target,
                (seed.source, seed.target),
                (seed,),
                frozenset((seed.relation_id,)),
            )
        )
    explored = 0
    truncated = False
    seeds_visited: set[int] = set()
    memory_samples: list[dict[str, object]] = []
    frontier_peak = len(frontier)

    def sample_memory() -> None:
        nonlocal frontier_peak
        frontier_peak = max(frontier_peak, len(frontier))
        item = _structured_memory_sample(
            frontier,
            oracle,
            seen=seen,
            candidates=candidates,
            skeleton_edges=skeleton_edges,
        )
        item["expanded_states"] = explored
        memory_samples.append(item)

    def add_candidate(
        nodes: tuple[str, ...], edges: tuple[_LabeledEdge, ...]
    ) -> None:
        nonlocal truncated
        key = (nodes, tuple(edge.relation_id for edge in edges))
        if key in seen:
            rejection_reasons["duplicate_skeleton"] += 1
            return
        seen.add(key)
        candidates.append((nodes, edges))
        if len(candidates) >= max_cycles:
            truncated = True

    while frontier and not truncated:
        if explored >= max_search_states:
            truncated = True
            rejection_reasons["search_state_limit"] += 1
            break
        seed_index, start, current, path_nodes, path_edges, used_relations = frontier.popleft()
        explored += 1
        seeds_visited.add(seed_index)
        if len(path_nodes) >= max_cycle_length:
            rejection_reasons["max_cycle_length"] += 1
            continue
        cached = current in oracle.source_cache
        reachable = oracle.reachable_sources(current, targets_by_thread)
        if cached:
            # ReachabilitySource already computed this exact source in an
            # earlier fair state; retain the cache-hit measurement separately.
            rejection_reasons["cached_reachability"] += 1
        for next_source, ppo_path in sorted(reachable.items()):
            if components.get(next_source) != components.get(start):
                rejection_reasons["reachability_outside_scc"] += 1
                continue
            reach_edge: _LabeledEdge | None = None
            if ppo_path:
                relation_ids = tuple(
                    f"ppo:source:{left}:{right}"
                    for left, right in zip(ppo_path, ppo_path[1:])
                )
                reach_edge = _LabeledEdge(
                    current,
                    next_source,
                    "ppo_reachability",
                    f"ppo-reach:source:{current}:{next_source}",
                    relation_ids,
                    ppo_path,
                )
                skeleton_edges[(reach_edge.source, reach_edge.target, reach_edge.kind)] = reach_edge
            if reach_edge is None:
                continue
            if next_source == start:
                completed = tuple(path_edges + (reach_edge,))
                if any(edge.kind != "ppo_reachability" for edge in completed[:-1]):
                    add_candidate(path_nodes, completed)
                else:
                    rejection_reasons["ppo_only_cycle"] += 1
                continue
            if next_source in path_nodes:
                rejection_reasons["repeated_endpoint"] += 1
                continue
            for next_edge in by_source.get(next_source, ()):
                if truncated:
                    break
                if explored >= max_search_states:
                    truncated = True
                    rejection_reasons["search_state_limit"] += 1
                    break
                if next_edge.relation_id in used_relations:
                    rejection_reasons["repeated_relation"] += 1
                    continue
                if components.get(next_edge.target) != components.get(start):
                    rejection_reasons["edge_outside_scc"] += 1
                    continue
                if next_edge.target == start:
                    completed = tuple(path_edges + (reach_edge, next_edge))
                    add_candidate(path_nodes, completed)
                    skeleton_edges[(next_edge.source, next_edge.target, next_edge.kind)] = next_edge
                    continue
                if next_edge.target in path_nodes:
                    rejection_reasons["repeated_endpoint"] += 1
                    continue
                skeleton_edges[(next_edge.source, next_edge.target, next_edge.kind)] = next_edge
                frontier.append(
                    (
                        seed_index,
                        start,
                        next_edge.target,
                        path_nodes + (next_edge.target,),
                        path_edges + (reach_edge, next_edge),
                        used_relations | frozenset((next_edge.relation_id,)),
                    )
                )
                # Count each fair frontier expansion, not an unbounded hidden
                # recursive traversal.
                rejection_reasons["frontier_expansion"] += 1
        if explored and explored % 100 == 0:
            sample_memory()

    if profile is not None:
        cached_queries = rejection_reasons.pop("cached_reachability", 0)
        path_expansions = rejection_reasons.pop("frontier_expansion", 0)
        profile.update(
            {
                "scheduler": "fair_structured",
                "fair_seed_scheduling": True,
                "conditional_seed_count": len(conditional),
                "seeds_visited": len(seeds_visited),
                "ppo_reachability_queries": len(oracle.source_cache),
                "ppo_reachability_cache_hits": cached_queries,
                "path_expansions": path_expansions,
                "rejected_cycles": sum(rejection_reasons.values()),
                "rejection_reasons": dict(sorted(rejection_reasons.items())),
                "generated_skeletons": len(candidates),
                "unique_skeletons": len(seen),
                "remaining_frontier": len(frontier) if truncated else 0,
                "search_truncated": truncated,
                "max_cycle_length": max_cycle_length,
                "max_search_states": max_search_states,
                "frontier_peak": frontier_peak,
                "memory_samples": tuple(memory_samples),
                "estimated_frontier_bytes": (
                    memory_samples[-1].get("estimated_frontier_bytes")
                    if memory_samples
                    else None
                ),
                "estimated_state_bytes": (
                    memory_samples[-1].get("estimated_state_bytes")
                    if memory_samples
                    else None
                ),
                "estimated_path_bytes": (
                    memory_samples[-1].get("estimated_path_bytes")
                    if memory_samples
                    else None
                ),
                "estimated_reachability_cache_bytes": (
                    memory_samples[-1].get("estimated_reachability_cache_bytes")
                    if memory_samples
                    else None
                ),
                "memory_components": (
                    memory_samples[-1].get("memory_components", {})
                    if memory_samples
                    else {}
                ),
            }
        )
    return candidates, explored, truncated, tuple(skeleton_edges.values())


def _path_materialize(path: _LazyPathNode) -> tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]:
    nodes: list[str] = []
    edges: list[_LabeledEdge] = []
    current: _LazyPathNode | None = path
    while current is not None:
        nodes.append(current.event_id)
        if current.edge is not None:
            edges.append(current.edge)
        current = current.parent
    nodes.reverse()
    edges.reverse()
    return tuple(nodes), tuple(edges)


def _path_contains(path: _LazyPathNode, event_id: str) -> bool:
    current: _LazyPathNode | None = path
    while current is not None:
        if current.event_id == event_id:
            return True
        current = current.parent
    return False


def _edge_payload(edge: _LabeledEdge) -> dict[str, object]:
    return {
        "source": edge.source,
        "target": edge.target,
        "kind": edge.kind,
        "relation_id": edge.relation_id,
        "relation_ids": list(edge.relation_ids),
        "witness_path": list(edge.witness_path),
    }


def _edge_from_payload(payload: dict[str, object]) -> _LabeledEdge:
    return _LabeledEdge(
        source=str(payload["source"]),
        target=str(payload["target"]),
        kind=str(payload["kind"]),
        relation_id=str(payload["relation_id"]),
        relation_ids=tuple(str(item) for item in payload.get("relation_ids", ())),
        witness_path=tuple(str(item) for item in payload.get("witness_path", ())),
    )


def _discovery_binding_digest(
    events: tuple[TraceEvent, ...],
    may_edges: tuple[_LabeledEdge, ...],
    source_ppo: frozenset[Edge],
    scope: str | None = None,
) -> str:
    payload = {
        "scope": scope,
        "events": [event.event_id for event in events],
        "may_edges": [_edge_payload(edge) for edge in may_edges],
        "source_ppo": sorted([list(edge) for edge in source_ppo]),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _write_discovery_checkpoint(
    path: str,
    *,
    binding_digest: str,
    explored: int,
    candidates: list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]],
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]],
    skeleton_edges: dict[tuple[str, str, str], _LabeledEdge],
    frontier: deque[_LazyStructuredState],
    pending_seed_indices: deque[int],
    rejection_reasons: Counter[str],
    seeds_visited: set[int],
) -> int:
    payload = {
        "schema_version": "candidate-discovery-checkpoint-v1",
        "binding_digest": binding_digest,
        "explored": explored,
        "candidates": [
            {"nodes": list(nodes), "edges": [_edge_payload(edge) for edge in edges]}
            for nodes, edges in candidates
        ],
        "seen": [
            {"nodes": list(nodes), "relations": list(relations)}
            for nodes, relations in sorted(seen)
        ],
        "skeleton_edges": [_edge_payload(edge) for edge in skeleton_edges.values()],
        "frontier": [
            {
                "seed_index": state.seed_index,
                "start": state.start,
                "current": state.current,
                "next_successor_index": state.next_successor_index,
                "path_nodes": list(_path_materialize(state.path)[0]),
                "path_edges": [_edge_payload(edge) for edge in _path_materialize(state.path)[1]],
                "used_relations": sorted(state.used_relations),
            }
            for state in frontier
        ],
        "pending_seed_indices": list(pending_seed_indices),
        "rejection_reasons": dict(rejection_reasons),
        "seeds_visited": sorted(seeds_visited),
    }
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, destination)
    return destination.stat().st_size


def _restore_discovery_checkpoint(
    path: str,
    *,
    binding_digest: str,
) -> dict[str, object]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema_version") != "candidate-discovery-checkpoint-v1":
        raise ValueError("unsupported candidate discovery checkpoint schema")
    if payload.get("binding_digest") != binding_digest:
        raise ValueError("candidate discovery checkpoint binding mismatch")
    restored_frontier: deque[_LazyStructuredState] = deque()
    for item in payload.get("frontier", ()):
        parent: _LazyPathNode | None = None
        path_nodes = tuple(str(value) for value in item.get("path_nodes", ()))
        path_edges = tuple(_edge_from_payload(value) for value in item.get("path_edges", ()))
        if len(path_nodes) != len(path_edges) + 1:
            raise ValueError("invalid checkpoint path shape")
        for index, event_id in enumerate(path_nodes):
            parent = _LazyPathNode(
                event_id,
                path_edges[index - 1] if index else None,
                parent,
                index,
            )
        if parent is None:
            raise ValueError("checkpoint contains an empty path")
        restored_frontier.append(
            _LazyStructuredState(
                seed_index=int(item["seed_index"]),
                start=str(item["start"]),
                current=str(item["current"]),
                path=parent,
                used_relations=frozenset(str(value) for value in item.get("used_relations", ())),
                next_successor_index=int(item.get("next_successor_index", 0)),
            )
        )
    return {
        "explored": int(payload.get("explored", 0)),
        "candidates": [
            (
                tuple(str(value) for value in item.get("nodes", ())),
                tuple(_edge_from_payload(value) for value in item.get("edges", ())),
            )
            for item in payload.get("candidates", ())
        ],
        "seen": {
            (
                tuple(str(value) for value in item.get("nodes", ())),
                tuple(str(value) for value in item.get("relations", ())),
            )
            for item in payload.get("seen", ())
        },
        "skeleton_edges": {
            (edge.source, edge.target, edge.kind): edge
            for edge in (_edge_from_payload(value) for value in payload.get("skeleton_edges", ()))
        },
        "frontier": restored_frontier,
        "pending_seed_indices": deque(int(value) for value in payload.get("pending_seed_indices", ())),
        "rejection_reasons": Counter(payload.get("rejection_reasons", {})),
        "seeds_visited": set(int(value) for value in payload.get("seeds_visited", ())),
    }


def _structured_successor_at(
    state: _LazyStructuredState,
    *,
    oracle: _ReachabilityOracle,
    targets_by_thread: dict[int, set[str]],
    by_source: dict[str, list[_LabeledEdge]],
    components: dict[str, int],
    rejection_reasons: Counter[str],
) -> _LazyTransition | None:
    """生成第 N 个后继；不把同一状态的兄弟后继同时放入 frontier。"""

    path_nodes, path_edges = _path_materialize(state.path)
    reachable = oracle.reachable_sources(state.current, targets_by_thread)
    ordinal = 0
    for next_source, ppo_path in sorted(reachable.items()):
        if components.get(next_source) != components.get(state.start):
            rejection_reasons["reachability_outside_scc"] += 1
            continue
        if not ppo_path:
            continue
        relation_ids = tuple(
            f"ppo:source:{left}:{right}"
            for left, right in zip(ppo_path, ppo_path[1:])
        )
        reach_edge = _LabeledEdge(
            state.current,
            next_source,
            "ppo_reachability",
            f"ppo-reach:source:{state.current}:{next_source}",
            relation_ids,
            ppo_path,
        )
        if next_source == state.start:
            if any(edge.kind not in {"source_ppo", "ppo_reachability"} for edge in path_edges):
                if ordinal == state.next_successor_index:
                    return _LazyTransition(reach_edge, None, True)
                ordinal += 1
            else:
                rejection_reasons["ppo_only_cycle"] += 1
            continue
        if _path_contains(state.path, next_source):
            rejection_reasons["repeated_endpoint"] += 1
            continue
        for next_edge in by_source.get(next_source, ()):
            if next_edge.relation_id in state.used_relations:
                rejection_reasons["repeated_relation"] += 1
                continue
            if components.get(next_edge.target) != components.get(state.start):
                rejection_reasons["edge_outside_scc"] += 1
                continue
            if next_edge.target in path_nodes and next_edge.target != state.start:
                rejection_reasons["repeated_endpoint"] += 1
                continue
            if ordinal == state.next_successor_index:
                return _LazyTransition(reach_edge, next_edge, next_edge.target == state.start)
            ordinal += 1
    return None


def _enumerate_bounded_lazy_skeleton_cycles(
    events: tuple[TraceEvent, ...],
    may_edges: tuple[_LabeledEdge, ...],
    source_ppo: frozenset[Edge],
    components: dict[str, int],
    cyclic_components: set[int],
    *,
    max_cycle_length: int,
    max_cycles: int,
    max_search_states: int,
    resource_policy: CandidateDiscoveryResourcePolicy | None = None,
    binding_scope: str | None = None,
    profile: dict[str, object] | None = None,
) -> tuple[list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]], int, bool, tuple[_LabeledEdge, ...]]:
    """P15 lazy fair search。

    每次只取一个后继，并把 ``next_successor_index`` 保存进 cursor。兄弟
    状态不会在一次扩展中全部物化；资源边界触发时 cursor 原样保留并可
    写入 checkpoint，因此不会把未探索空间静默当成空集。
    """

    policy = resource_policy or CandidateDiscoveryResourcePolicy()
    effective_states = max_search_states
    if policy.max_search_states is not None:
        effective_states = min(effective_states, policy.max_search_states)
    sample_every = max(1, policy.sample_every)
    conditional = tuple(
        sorted(
            (edge for edge in may_edges if edge.kind != "source_ppo"),
            key=lambda edge: (edge.source, edge.target, edge.kind, edge.relation_id),
        )
    )
    event_by_id = {event.event_id: event for event in events}
    by_source: dict[str, list[_LabeledEdge]] = defaultdict(list)
    targets_by_thread: dict[int, set[str]] = defaultdict(set)
    for edge in conditional:
        by_source[edge.source].append(edge)
        source_event = event_by_id.get(edge.source)
        if source_event is not None:
            targets_by_thread[source_event.thread_id].add(edge.source)
    for values in by_source.values():
        values.sort(key=lambda edge: (edge.target, edge.kind, edge.relation_id))
    oracle = _ReachabilityOracle.build(
        events,
        source_ppo,
        cache_sources=False,
        cache_paths=False,
    )
    binding_digest = _discovery_binding_digest(events, may_edges, source_ppo, binding_scope)
    candidates: list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]] = []
    skeleton_edges: dict[tuple[str, str, str], _LabeledEdge] = {}
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    rejection_reasons: Counter[str] = Counter()
    frontier: deque[_LazyStructuredState] = deque()
    pending_seed_indices: deque[int] = deque()
    for index, seed in enumerate(conditional):
        component = components.get(seed.source)
        if component not in cyclic_components or components.get(seed.target) != component:
            rejection_reasons["seed_outside_cyclic_scc"] += 1
            continue
        pending_seed_indices.append(index)

    def admit_seed() -> bool:
        if not pending_seed_indices:
            return False
        index = pending_seed_indices.popleft()
        seed = conditional[index]
        root = _LazyPathNode(
            seed.target,
            seed,
            _LazyPathNode(seed.source, None, None, 0),
            1,
        )
        frontier.append(
            _LazyStructuredState(
                seed_index=index,
                start=seed.source,
                current=seed.target,
                path=root,
                used_relations=frozenset((seed.relation_id,)),
            )
        )
        return True

    frontier_limit = policy.max_in_memory_frontier
    explored = 0
    if policy.resume_checkpoint:
        restored = _restore_discovery_checkpoint(
            policy.resume_checkpoint,
            binding_digest=binding_digest,
        )
        frontier = restored["frontier"]
        pending_seed_indices = restored["pending_seed_indices"]
        candidates = restored["candidates"]
        seen = restored["seen"]
        skeleton_edges = restored["skeleton_edges"]
        rejection_reasons = restored["rejection_reasons"]
        seeds_visited = restored["seeds_visited"]
        explored = restored["explored"]
    else:
        # 初始只装入有限数量的 seed。其余 seed 作为轻量索引保留，达到内存边界
        # 时仍能在 checkpoint 中恢复，而不是被丢弃。
        while pending_seed_indices and (frontier_limit is None or len(frontier) < frontier_limit):
            admit_seed()

    truncated = False
    termination_reason: str | None = None
    if policy.resume_checkpoint:
        # restored above; this branch is kept explicit so a future schema
        # cannot silently reset the progress ledger.
        seeds_visited = set(seeds_visited)
    else:
        seeds_visited = set()
    memory_samples: list[dict[str, object]] = []
    frontier_peak = len(frontier)
    successors_generated = 0
    started = time.perf_counter()
    checkpoint_size = 0

    def sample() -> None:
        nonlocal frontier_peak
        frontier_peak = max(frontier_peak, len(frontier))
        item = _structured_memory_sample(
            frontier,
            oracle,
            pending_seed_indices=pending_seed_indices,
            seen=seen,
            candidates=candidates,
            skeleton_edges=skeleton_edges,
        )
        item["expanded_states"] = explored
        item["pending_seed_indices"] = len(pending_seed_indices)
        item["successors_generated"] = successors_generated
        memory_samples.append(item)
        if policy.progress_path:
            progress = {
                "schema_version": "candidate-discovery-progress-v1",
                "timestamp": time.time(),
                "binding_digest": binding_digest,
                "expanded_states": explored,
                "frontier_size": len(frontier),
                "pending_seed_count": len(pending_seed_indices),
                "candidate_count": len(candidates),
                "canonical_count": len(seen),
                "successors_generated": successors_generated,
                "memory_components": item.get("memory_components", {}),
                "current_rss_mb": item["rss_mb"],
                "peak_rss_mb": item["rss_mb"],
                "elapsed_ms": int((time.perf_counter() - started) * 1000),
                "termination_reason": None,
                "diagnostic_only": True,
            }
            progress_path = Path(policy.progress_path)
            progress_path.parent.mkdir(parents=True, exist_ok=True)
            progress_path.write_text(json.dumps(progress, sort_keys=True), encoding="utf-8")

    def limit_hit() -> str | None:
        if policy.max_wall_time_ms is not None and (time.perf_counter() - started) * 1000 >= policy.max_wall_time_ms:
            return "max_wall_time"
        rss = _rss_mb()
        if policy.max_rss_mb is not None and rss is not None and rss >= policy.max_rss_mb:
            return "max_rss_mb"
        if frontier_limit is not None and len(frontier) >= frontier_limit and pending_seed_indices:
            # The current queue can still be searched; this is only a hard
            # stop when a successor needs another resident cursor.
            return None
        return None

    while frontier and not truncated:
        if explored >= effective_states:
            truncated = True
            termination_reason = "max_search_states"
            break
        state = frontier.popleft()
        reason = limit_hit()
        if reason is not None:
            frontier.appendleft(state)
            truncated = True
            termination_reason = reason
            break
        transition = _structured_successor_at(
            state,
            oracle=oracle,
            targets_by_thread=targets_by_thread,
            by_source=by_source,
            components=components,
            rejection_reasons=rejection_reasons,
        )
        if transition is None or state.path.depth >= max_cycle_length:
            if transition is None:
                rejection_reasons["state_exhausted"] += 1
            else:
                rejection_reasons["max_cycle_length"] += 1
            if pending_seed_indices and (frontier_limit is None or len(frontier) < frontier_limit):
                admit_seed()
            if explored and explored % sample_every == 0:
                sample()
            continue
        explored += 1
        successors_generated += 1
        seeds_visited.add(state.seed_index)
        next_index = state.next_successor_index + 1
        # 保留当前 cursor，之后继续消费下一个后继。若同时加入 child 会
        # 超过内存边界，则不消费 transition，原状态已在本轮前 pop，因而
        # 可以原样恢复，不会丢候选。
        child_needed = transition.next_edge is not None and not transition.candidate
        additional = 1 + (1 if child_needed else 0)
        if frontier_limit is not None and len(frontier) + additional > frontier_limit:
            frontier.appendleft(state)
            explored -= 1
            successors_generated -= 1
            truncated = True
            termination_reason = "max_in_memory_frontier"
            break
        frontier.append(
            _LazyStructuredState(
                seed_index=state.seed_index,
                start=state.start,
                current=state.current,
                path=state.path,
                used_relations=state.used_relations,
                next_successor_index=next_index,
            )
        )
        reach_edge = transition.reach_edge
        next_edge = transition.next_edge
        if transition.candidate:
            path_nodes, path_edges = _path_materialize(state.path)
            completed = path_edges + (reach_edge,) + ((next_edge,) if next_edge is not None else ())
            if any(edge.kind not in {"source_ppo", "ppo_reachability"} for edge in completed):
                key = (path_nodes, tuple(edge.relation_id for edge in completed))
                if key not in seen:
                    seen.add(key)
                    candidates.append((path_nodes, completed))
                    for edge in completed:
                        skeleton_edges[(edge.source, edge.target, edge.kind)] = edge
                    if len(candidates) >= max_cycles:
                        truncated = True
                        termination_reason = "max_cycles"
                        break
            else:
                rejection_reasons["ppo_only_cycle"] += 1
        else:
            if next_edge is None:
                rejection_reasons["missing_child_edge"] += 1
            else:
                child_path = _LazyPathNode(
                    next_edge.target,
                    next_edge,
                    _LazyPathNode(
                        reach_edge.target,
                        reach_edge,
                        state.path,
                        state.path.depth + 1,
                    ),
                    state.path.depth + 2,
                )
                # reach_edge.target is the endpoint already represented by the
                # current state only when the summary skips a PPO segment. The
                # child path therefore appends both summary and conditional edge.
                frontier.append(
                    _LazyStructuredState(
                        seed_index=state.seed_index,
                        start=state.start,
                        current=next_edge.target,
                        path=child_path,
                        used_relations=state.used_relations | frozenset((next_edge.relation_id,)),
                    )
                )
                skeleton_edges[(next_edge.source, next_edge.target, next_edge.kind)] = next_edge
        if pending_seed_indices and (frontier_limit is None or len(frontier) < frontier_limit):
            admit_seed()
        if explored and explored % sample_every == 0:
            sample()

    if not truncated and not frontier and pending_seed_indices:
        # This can only happen when a caller supplied a zero-sized frontier;
        # retain the distinction from a complete empty search.
        truncated = True
        termination_reason = "max_in_memory_frontier"
    if truncated and policy.checkpoint_path:
        checkpoint_size = _write_discovery_checkpoint(
            policy.checkpoint_path,
            binding_digest=binding_digest,
            explored=explored,
            candidates=candidates,
            seen=seen,
            skeleton_edges=skeleton_edges,
            frontier=frontier,
            pending_seed_indices=pending_seed_indices,
            rejection_reasons=rejection_reasons,
            seeds_visited=seeds_visited,
        )
    if profile is not None:
        cached_queries = oracle.query_count
        profile.update(
            {
                "scheduler": "bounded_lazy_p15",
                "fair_seed_scheduling": True,
                "conditional_seed_count": len(conditional),
                "seeds_visited": len(seeds_visited),
                "ppo_reachability_queries": cached_queries,
                "ppo_reachability_cache_hits": oracle.cache_hit_count,
                "path_expansions": successors_generated,
                "successors_generated": successors_generated,
                "rejected_cycles": sum(rejection_reasons.values()),
                "rejection_reasons": dict(sorted(rejection_reasons.items())),
                "generated_skeletons": len(candidates),
                "unique_skeletons": len(seen),
                "remaining_frontier": len(frontier) + len(pending_seed_indices) if truncated else 0,
                "search_truncated": truncated,
                "max_cycle_length": max_cycle_length,
                "max_search_states": effective_states,
                "frontier_peak": frontier_peak,
                "memory_samples": tuple(memory_samples),
                "estimated_frontier_bytes": (
                    memory_samples[-1].get("estimated_frontier_bytes")
                    if memory_samples
                    else None
                ),
                "estimated_state_bytes": (
                    memory_samples[-1].get("estimated_state_bytes")
                    if memory_samples
                    else None
                ),
                "estimated_path_bytes": (
                    memory_samples[-1].get("estimated_path_bytes")
                    if memory_samples
                    else None
                ),
                "estimated_reachability_cache_bytes": (
                    memory_samples[-1].get("estimated_reachability_cache_bytes")
                    if memory_samples
                    else None
                ),
                "memory_components": (
                    memory_samples[-1].get("memory_components", {})
                    if memory_samples
                    else {}
                ),
                "resource_limit_reached": termination_reason in {
                    "max_in_memory_frontier",
                    "max_rss_mb",
                    "max_wall_time",
                },
                "termination_reason": termination_reason,
                "resumable": bool(truncated and policy.checkpoint_path),
                "checkpoint_path": policy.checkpoint_path if checkpoint_size else None,
                "checkpoint_binding_digest": binding_digest if checkpoint_size else None,
                "spill_size_bytes": checkpoint_size,
            }
        )
    if policy.progress_path:
        final_progress = {
            "schema_version": "candidate-discovery-progress-v1",
            "timestamp": time.time(),
            "binding_digest": binding_digest,
            "expanded_states": explored,
            "frontier_size": len(frontier),
            "pending_seed_count": len(pending_seed_indices),
            "candidate_count": len(candidates),
            "canonical_count": len(seen),
            "successors_generated": successors_generated,
            "memory_components": (
                memory_samples[-1].get("memory_components", {})
                if memory_samples
                else {}
            ),
            "current_rss_mb": _rss_mb(),
            "peak_rss_mb": _rss_mb(),
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "termination_reason": termination_reason,
            "diagnostic_only": True,
        }
        progress_path = Path(policy.progress_path)
        progress_path.parent.mkdir(parents=True, exist_ok=True)
        progress_path.write_text(json.dumps(final_progress, sort_keys=True), encoding="utf-8")
    return candidates, explored, truncated, tuple(skeleton_edges.values())


def _cycle_local_ids(cycle_edges: tuple[_LabeledEdge, ...]) -> set[str]:
    ids: set[str] = set()
    for edge in cycle_edges:
        ids.update((edge.source, edge.target))
        ids.update(edge.witness_path)
    return ids


def _required_local_source_edges(
    cycle_edges: tuple[_LabeledEdge, ...],
) -> set[Edge]:
    required: set[Edge] = set()
    for edge in cycle_edges:
        if edge.kind in {"source_ppo", "ppo_reachability"}:
            if edge.witness_path:
                required.update(zip(edge.witness_path, edge.witness_path[1:]))
            else:
                required.add((edge.source, edge.target))
        elif edge.kind in {"rf", "fr", "coherence"}:
            # source_conditions 将同端点的候选标签合并成一个条件；要求
            # 端点边被选中即可，同时由 LocalCycleObligationSet 保留该
            # read 的完整 RF domain，避免把“选中一条”误写成“只有一条”。
            required.add((edge.source, edge.target))
    return required


def _component_nodes(components: dict[str, int]) -> dict[int, set[str]]:
    result: dict[int, set[str]] = defaultdict(set)
    for node, component in components.items():
        result[component].add(node)
    return result


def _cyclic_component_count(
    nodes: tuple[str, ...], edges: tuple[_LabeledEdge, ...]
) -> int:
    components = _strongly_connected_components(nodes, edges)
    grouped = _component_nodes(components)
    return sum(
        len(values) > 1
        or any(
            edge.source == edge.target
            and components.get(edge.source) == component
            for edge in edges
        )
        for component, values in grouped.items()
    )


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


def _local_status(result: str, execute_solver: bool) -> GraphFirstQueryStatus:
    if not execute_solver:
        return GraphFirstQueryStatus.NOT_RUN
    if result == "sat":
        return GraphFirstQueryStatus.SAT_CANDIDATE
    if result == "unsat":
        return GraphFirstQueryStatus.UNSAT_LOCAL
    return GraphFirstQueryStatus.UNKNOWN_LOCAL


def _feasibility_status(result: str) -> LocalCycleStatus:
    if result == "sat":
        return LocalCycleStatus.FEASIBLE
    if result == "unsat":
        return LocalCycleStatus.INFEASIBLE
    return LocalCycleStatus.UNKNOWN


def _build_candidate_violation_cycle(
    *,
    cycle_id: str,
    cycle_edges: tuple[_LabeledEdge, ...],
    event_by_id: dict[str, TraceEvent],
) -> CandidateViolationCycle:
    """把普通图环提升成当前 source/target 查询语义的候选。"""

    skeleton = _compress_ppo_runs(cycle_edges)
    classified: list[CandidateViolationEdge] = []
    unresolved: list[str] = []
    rf_dependencies: set[str] = set()
    fr_dependencies: set[str] = set()
    co_dependencies: set[str] = set()
    ppo_paths: list[tuple[str, ...]] = []
    boundaries: set[str] = set()
    for edge in skeleton:
        left = event_by_id.get(edge.source)
        right = event_by_id.get(edge.target)
        witness_events = tuple(
            event_by_id[event_id]
            for event_id in edge.witness_path
            if event_id in event_by_id
        )
        boundary_ids = tuple(
            event.event_id
            for event in (left, right, *witness_events)
            if event is not None and event.kind.is_boundary
        )
        if boundary_ids:
            boundaries.update(boundary_ids)
        if edge.kind in {"source_ppo", "ppo_reachability"}:
            relation_type = "ppo_reachability"
            ppo_paths.append(edge.witness_path)
        elif edge.kind in {"rf", "fr", "coherence"}:
            relation_type = edge.kind
        else:
            relation_type = "unresolved"
            unresolved.append(f"unsupported relation family: {edge.kind}")
        if relation_type == "rf":
            rf_dependencies.update(edge.relation_ids)
        elif relation_type == "fr":
            fr_dependencies.update(edge.relation_ids)
        elif relation_type == "coherence":
            co_dependencies.update(edge.relation_ids)
        classified.append(
            CandidateViolationEdge(
                source_event=edge.source,
                target_event=edge.target,
                relation_type=relation_type,
                side="source",
                conditional=relation_type != "ppo_reachability",
                relation_ids=edge.relation_ids,
                rf_candidate_ids=edge.relation_ids if relation_type == "rf" else (),
                fr_consequence_ids=edge.relation_ids if relation_type == "fr" else (),
                co_dependency_ids=(
                    edge.relation_ids if relation_type == "coherence" else ()
                ),
                ppo_reachability_path=edge.witness_path,
                boundary_dependency_ids=boundary_ids,
                unresolved_dependency_reasons=(
                    (f"unsupported relation family: {edge.kind}",)
                    if relation_type == "unresolved"
                    else ()
                ),
            )
        )
    nodes = tuple(edge.source for edge in cycle_edges) + (
        cycle_edges[0].source,
    )
    return CandidateViolationCycle(
        cycle_id=cycle_id,
        cycle_nodes=nodes,
        ordered_edges=tuple(classified),
        rf_dependencies=tuple(sorted(rf_dependencies)),
        fr_dependencies=tuple(sorted(fr_dependencies)),
        co_dependencies=tuple(sorted(co_dependencies)),
        ppo_reachability_dependencies=tuple(ppo_paths),
        fence_rmw_futex_dependencies=tuple(sorted(boundaries)),
        unresolved_dependencies=tuple(sorted(set(unresolved))),
    )


def _compress_ppo_runs(
    cycle_edges: tuple[_LabeledEdge, ...],
) -> tuple[_LabeledEdge, ...]:
    """用 reduced PPO 中的路径摘要表示环，不把完整 PPO 链写进 skeleton。"""

    compressed: list[_LabeledEdge] = []
    index = 0
    while index < len(cycle_edges):
        current = cycle_edges[index]
        if current.kind not in {"source_ppo", "ppo_reachability"}:
            compressed.append(current)
            index += 1
            continue
        if current.kind == "ppo_reachability":
            compressed.append(current)
            index += 1
            continue
        start = current.source
        target = current.target
        labels = list(current.relation_ids or (current.relation_id,))
        path = [start, target]
        index += 1
        while index < len(cycle_edges):
            following = cycle_edges[index]
            if following.kind != "source_ppo" or following.source != target:
                break
            target = following.target
            path.append(target)
            labels.extend(following.relation_ids or (following.relation_id,))
            index += 1
        compressed.append(
            _LabeledEdge(
                start,
                target,
                "source_ppo",
                labels[0],
                tuple(dict.fromkeys(labels)),
                tuple(path),
            )
        )
        # The next non-PPO edge starts at the summarized target. The raw graph
        # search has already checked adjacency, so a missing join is a
        # diagnostic unresolved dependency rather than an invented edge.
    return tuple(compressed)


def _build_local_obligations(
    candidate: CandidateViolationCycle,
    *,
    cycle_edges: tuple[_LabeledEdge, ...],
    events: tuple[TraceEvent, ...],
    witness: LocalCycleWitness | None,
    query_event_ids: tuple[str, ...] = (),
) -> LocalCycleObligationSet:
    values = _candidate_relations(events)
    by_id = {item.relation_id: item for item in values}
    selected_rf_values = set(candidate.rf_dependencies)
    if witness is not None:
        selected_rf_values = {
            item.relation_id
            for item in values
            if item.kind == "rf"
            and any(
                item.owner_event_id == read
                and item.event_ids[0] == write
                and item.address == address
                and item.size == size
                for read, write, address, size in witness.rf_assignments
            )
        }
    selected_rf = tuple(sorted(selected_rf_values))
    selected_reads = (
        {read for read, _, _, _ in witness.rf_assignments}
        if witness is not None
        else {
            by_id[item].owner_event_id
            for item in selected_rf
            if item in by_id and by_id[item].kind == "rf"
        }
    )
    rf_domain = tuple(
        sorted(
            item.relation_id
            for item in values
            if item.kind == "rf" and item.owner_event_id in selected_reads
        )
    )
    required_fr = tuple(sorted(candidate.fr_dependencies))
    required_co = tuple(sorted(candidate.co_dependencies))
    return LocalCycleObligationSet(
        cycle_id=candidate.cycle_id,
        query_event_ids=tuple(sorted(query_event_ids)),
        selected_rf_relation_ids=selected_rf,
        rf_candidate_domain_ids=rf_domain,
        required_fr_relation_ids=required_fr,
        required_co_relation_ids=required_co,
        ppo_witness_paths=tuple(
            edge.ppo_reachability_path
            for edge in candidate.ordered_edges
            if edge.relation_type == "ppo_reachability"
        ),
        boundary_event_ids=candidate.fence_rmw_futex_dependencies,
        unresolved_dependencies=candidate.unresolved_dependencies,
        rf_exclusivity_preserved=(
            selected_reads <= {item.owner_event_id for item in values if item.kind == "rf"}
            and set(selected_rf) <= set(rf_domain)
        ),
    )


def _build_local_witness(
    candidate: CandidateViolationCycle,
    *,
    cycle_edges: tuple[_LabeledEdge, ...],
    local_result: object,
) -> LocalCycleWitness | None:
    witness = getattr(local_result, "witness", None)
    if witness is None:
        return None
    return LocalCycleWitness(
        cycle_id=candidate.cycle_id,
        rf_assignments=tuple(
            (
                item.read_event,
                item.write_event,
                item.address,
                item.size,
            )
            for item in witness.read_from
        ),
        co_assignments=tuple(witness.coherence),
        fr_consequences=tuple(
            (edge.source, edge.target)
            for edge in cycle_edges
            if edge.kind == "fr"
        ),
        ppo_reachability_witnesses=candidate.ppo_reachability_dependencies,
        ordering_assignment=tuple(
            (edge.source, edge.target) for edge in cycle_edges
        ),
        cycle_edges=tuple(
            (edge.source, edge.target) for edge in cycle_edges
        ),
        source_cycle=witness.source_cycle,
        model_snapshot=witness.model_snapshot,
    )


def _blocking_clause(
    candidate: CandidateViolationCycle,
    obligations: LocalCycleObligationSet,
    solver_result: str,
) -> CandidateBlockingClause:
    literals = tuple(
        sorted(
            set(obligations.selected_rf_relation_ids)
            | set(obligations.required_fr_relation_ids)
            | set(obligations.required_co_relation_ids)
            | {"ppo:" + ">".join(path) for path in obligations.ppo_witness_paths}
        )
    )
    key_payload = {
        "cycle_id": candidate.cycle_id,
        "literals": literals,
    }
    exact_key = hashlib.sha256(
        json.dumps(key_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return CandidateBlockingClause(
        cycle_id=candidate.cycle_id,
        literals=literals,
        solver_result=solver_result,
        exact_candidate_key=exact_key,
        verified_unsat=solver_result == "unsat",
        replayable=solver_result == "unsat",
    )


def _co_reaches(
    pairs: tuple[tuple[str, str], ...], source: str, target: str
) -> bool:
    """按 witness 中的相邻 CO 边检查偏序可达，而不是只认直接边。"""

    if source == target:
        return True
    mutable: dict[str, list[str]] = defaultdict(list)
    for left, right in pairs:
        mutable[left].append(right)
    adjacency = {left: tuple(rights) for left, rights in mutable.items()}
    pending: deque[str] = deque([source])
    visited = {source}
    while pending:
        current = pending.popleft()
        for neighbor in adjacency.get(current, ()):
            if neighbor == target:
                return True
            if neighbor not in visited:
                visited.add(neighbor)
                pending.append(neighbor)
    return False


def _read_parts_for_replay(
    read: TraceEvent, writes: tuple[TraceEvent, ...]
) -> tuple[tuple[int, int], ...]:
    """独立重建 checker 的按字节 read-part 边界，用于校验 witness。"""

    boundaries = {read.address, read.end_address}
    for write in writes:
        if write.overlaps(read):
            boundaries.add(max(read.address, write.address))
            boundaries.add(min(read.end_address, write.end_address))
    ordered = sorted(boundaries)
    return tuple(
        (left, right - left)
        for left, right in zip(ordered, ordered[1:])
        if right > left
    )


def _fr_relation_parts(
    events: tuple[TraceEvent, ...],
) -> dict[str, tuple[str, int, int, str]]:
    """把 FR identity 映射回 read-part，避免用整个 Load 的 RF 代替切片 RF。"""

    memory = tuple(event for event in events if event.kind.is_memory)
    reads = tuple(event for event in memory if event.kind.is_read)
    writes = tuple(event for event in memory if event.kind.is_write)
    result: dict[str, tuple[str, int, int, str]] = {}
    for read in reads:
        for part_index, (address, size) in enumerate(
            _read_parts_for_replay(read, writes)
        ):
            end = address + size
            for later in writes:
                if (
                    later.address >= end
                    or later.end_address <= address
                    or later.event_id == read.event_id
                ):
                    continue
                relation_id = (
                    f"fr:{read.event_id}:{part_index}:{later.event_id}:"
                    f"{address}:{size}"
                )
                result[relation_id] = (read.event_id, address, size, later.event_id)
    return result


@dataclass(frozen=True, slots=True)
class _LocalModelReplay:
    model_valid: bool
    full_window_closed: bool
    rf_valid: bool
    fr_valid: bool
    co_valid: bool
    boundary_valid: bool
    source_valid: bool
    target_valid: bool
    failures: tuple[CandidateReplayFailure, ...]


def _replay_local_symbolic_model(
    candidate: CandidateViolationCycle,
    obligations: LocalCycleObligationSet,
    witness: LocalCycleWitness,
    *,
    source_reduced: frozenset[Edge],
    target_reduced: frozenset[Edge],
    events: tuple[TraceEvent, ...],
) -> _LocalModelReplay:
    """独立重建有限编码的 RF/CO/FR 和 cycle 约束，再核验完整模型。"""

    failures: list[CandidateReplayFailure] = []

    def reject(
        kind: CandidateReplayFailureKind,
        obligation_id: str,
        predicate: str,
        detail: str,
    ) -> None:
        failures.append(
            CandidateReplayFailure(
                kind=kind,
                obligation_id=obligation_id,
                predicate=predicate,
                detail=detail,
            )
        )

    snapshot = witness.model_snapshot
    if snapshot is None:
        reject(
            CandidateReplayFailureKind.LOCAL_MODEL_INCOMPLETE,
            candidate.cycle_id,
            "model-snapshot-present",
            "完整模型未随 witness 保存",
        )
        return _LocalModelReplay(False, False, False, False, False, False, False, False, tuple(failures))

    variables = snapshot.variables
    semantic_ids = [item.semantic_id for item in variables]
    serialized = [item.model_dump(mode="json") for item in variables]
    actual_digest = hashlib.sha256(
        json.dumps(serialized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    model_valid = (
        snapshot.schema_version == "local-symbolic-model-v1"
        and snapshot.complete
        and snapshot.expected_variable_count == len(variables)
        and len(set(semantic_ids)) == len(semantic_ids)
        and actual_digest == snapshot.digest
        and witness.cycle_id == candidate.cycle_id == obligations.cycle_id
    )
    if not model_valid:
        reject(
            CandidateReplayFailureKind.WITNESS_SERIALIZATION_ERROR,
            candidate.cycle_id,
            "model-snapshot-integrity",
            "模型快照版本、完整标记、变量唯一性、数量、摘要或候选绑定不匹配",
        )

    event_by_id = {event.event_id: event for event in events}
    query_ids = tuple(obligations.query_event_ids)
    query_events = tuple(
        sorted(
            (event_by_id[item] for item in query_ids if item in event_by_id),
            key=lambda event: (event.thread_id, event.sequence, event.event_id),
        )
    )
    query_set = set(query_ids)
    full_window_closed = (
        bool(query_ids)
        and len(query_set) == len(query_ids)
        and query_set == set(event_by_id)
        and len(query_events) == len(events)
    )
    if len(query_events) != len(query_ids):
        model_valid = False
        reject(
            CandidateReplayFailureKind.BINDING_MISMATCH,
            candidate.cycle_id,
            "query-event-binding",
            "局部查询引用了输入窗口中不存在的事件",
        )
    if not full_window_closed:
        reject(
            CandidateReplayFailureKind.LOCAL_MODEL_INCOMPLETE,
            candidate.cycle_id,
            "full-window-event-closure",
            f"局部 SAT 只覆盖 {len(query_set)} / {len(event_by_id)} 个窗口事件；未覆盖事件的 RF/FR/CO 与 target cycle 尚未证明",
        )

    values = {item.semantic_id: item.value for item in variables}
    memory = tuple(event for event in query_events if event.kind.is_memory)
    reads = tuple(event for event in memory if event.kind.is_read)
    writes = tuple(event for event in memory if event.kind.is_write)
    expected_semantics = {
        *(f"target_rank:{event.event_id}" for event in query_events),
        *(f"cycle_node:{event.event_id}" for event in query_events),
        *(f"coherence_rank:{event.event_id}" for event in writes),
    }
    read_parts: list[tuple[TraceEvent, int, int, tuple[TraceEvent, ...]]] = []
    for read in reads:
        for part_index, (address, size) in enumerate(_read_parts_for_replay(read, writes)):
            candidates = tuple(
                write
                for write in writes
                if write.address <= address
                and write.end_address >= address + size
                and not (write.thread_id == read.thread_id and write.sequence >= read.sequence)
            )
            read_parts.append((read, address, size, candidates))
            expected_semantics.add(
                "rf_choice:" + json.dumps(
                    [read.event_id, part_index, address, size], separators=(",", ":")
                )
            )

    local_source = {edge for edge in source_reduced if edge[0] in query_set and edge[1] in query_set}
    local_target = {edge for edge in target_reduced if edge[0] in query_set and edge[1] in query_set}
    conditional_pairs: set[Edge] = set()
    local_relations = _candidate_relations(query_events)
    for relation in local_relations:
        if relation.kind == "rf":
            writer, read = relation.event_ids
            if event_by_id[writer].thread_id != event_by_id[read].thread_id:
                conditional_pairs.add((writer, read))
        elif relation.kind in {"fr", "coherence"}:
            conditional_pairs.add(relation.event_ids)
    cycle_edge_pairs = local_source | conditional_pairs
    expected_semantics.update(
        "cycle_edge:" + json.dumps([left, right], separators=(",", ":"))
        for left, right in cycle_edge_pairs
    )
    variable_by_semantic = {item.semantic_id: item for item in variables}
    expected_integer_ids = {
        item
        for item in expected_semantics
        if item.startswith(("target_rank:", "coherence_rank:", "rf_choice:"))
    }
    expected_boolean_ids = expected_semantics - expected_integer_ids
    serialized_smt_names = [item.smt_name for item in variables]
    sorts_valid = (
        len(set(serialized_smt_names)) == len(serialized_smt_names)
        and all(
            variable_by_semantic[item].sort == "Int"
            for item in expected_integer_ids & set(variable_by_semantic)
        )
        and all(
            variable_by_semantic[item].sort == "Bool"
            for item in expected_boolean_ids & set(variable_by_semantic)
        )
    )
    if not sorts_valid:
        model_valid = False
        reject(
            CandidateReplayFailureKind.WITNESS_SERIALIZATION_ERROR,
            candidate.cycle_id,
            "model-variable-sorts",
            "模型变量名重复或变量 sort 与独立重建的 Int/Bool 清单不符",
        )
    if set(semantic_ids) != expected_semantics:
        model_valid = False
        missing = sorted(expected_semantics - set(semantic_ids))
        extra = sorted(set(semantic_ids) - expected_semantics)
        reject(
            CandidateReplayFailureKind.LOCAL_MODEL_INCOMPLETE,
            candidate.cycle_id,
            "decision-variable-inventory",
            f"模型决策变量清单与独立重建的编码不符；missing={missing[:8]}, extra={extra[:8]}",
        )

    def integer_value(semantic_id: str) -> int | None:
        raw = values.get(semantic_id)
        try:
            return int(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None

    def boolean_value(semantic_id: str) -> bool | None:
        raw = values.get(semantic_id)
        if raw is None or raw.lower() not in {"true", "false"}:
            return None
        return raw.lower() == "true"

    selected_by_part: dict[tuple[str, int, int], str | None] = {}
    rf_valid = True
    expected_rf_assignments: set[tuple[str, str | None, int, int]] = set()
    fr_parts = _fr_relation_parts(query_events)
    for read, address, size, candidates in read_parts:
        part_index = sum(
            1
            for prior_read, prior_address, prior_size, _ in read_parts
            if prior_read.event_id == read.event_id
            and (prior_address, prior_size) < (address, size)
        )
        semantic_id = "rf_choice:" + json.dumps(
            [read.event_id, part_index, address, size], separators=(",", ":")
        )
        choice = integer_value(semantic_id)
        if choice is None or choice < -1 or choice >= len(candidates):
            rf_valid = False
            reject(
                CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE,
                semantic_id,
                "rf-choice-domain",
                f"RF choice 缺失或超出完整候选域 {semantic_id}={values.get(semantic_id)!r}",
            )
            continue
        source = candidates[choice].event_id if choice >= 0 else None
        selected_by_part[(read.event_id, address, size)] = source
        expected_rf_assignments.add((read.event_id, source, address, size))
    actual_rf_assignments = {
        (read, write, address, size) for read, write, address, size in witness.rf_assignments
    }
    if len(actual_rf_assignments) != len(witness.rf_assignments) or actual_rf_assignments != expected_rf_assignments:
        rf_valid = False
        reject(
            CandidateReplayFailureKind.WITNESS_SERIALIZATION_ERROR,
            candidate.cycle_id,
            "rf-model-projection",
            "序列化的 RF witness 与完整模型里的每个 read-part choice 不一致",
        )

    co_rank: dict[str, int] = {}
    co_valid = True
    for write in writes:
        rank = integer_value(f"coherence_rank:{write.event_id}")
        if rank is None:
            co_valid = False
            reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, f"co:{write.event_id}", "co-rank-present", "缺少写事件的 coherence rank")
        else:
            co_rank[write.event_id] = rank
    remaining = set(range(len(writes)))
    overlap_groups: list[tuple[TraceEvent, ...]] = []
    while remaining:
        seed = remaining.pop()
        component = {seed}
        pending = [seed]
        while pending:
            current = pending.pop()
            attached = {other for other in remaining if writes[current].overlaps(writes[other])}
            remaining.difference_update(attached)
            component.update(attached)
            pending.extend(attached)
        overlap_groups.append(tuple(writes[index] for index in sorted(component)))
    expected_co_chain: set[Edge] = set()
    for group in overlap_groups:
        ranks = [co_rank[item.event_id] for item in group if item.event_id in co_rank]
        if len(ranks) != len(group) or sorted(ranks) != list(range(len(group))):
            co_valid = False
            reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, candidate.cycle_id, "co-rank-total-order", "overlap-connected writes do not have a complete distinct coherence order")
            continue
        ordered = tuple(sorted(group, key=lambda item: co_rank[item.event_id]))
        expected_co_chain.update((left.event_id, right.event_id) for left, right in zip(ordered, ordered[1:]))
    for left in writes:
        for right in writes:
            if (
                left.thread_id == right.thread_id
                and left.sequence < right.sequence
                and left.overlaps(right)
                and left.event_id in co_rank
                and right.event_id in co_rank
                and co_rank[left.event_id] >= co_rank[right.event_id]
            ):
                co_valid = False
                reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, f"co:{left.event_id}->{right.event_id}", "same-thread-co-order", "coherence rank reverses same-thread overlapping stores")
    if set(witness.co_assignments) != expected_co_chain:
        co_valid = False
        reject(CandidateReplayFailureKind.WITNESS_SERIALIZATION_ERROR, candidate.cycle_id, "co-model-projection", "序列化的 CO rank chain 与完整模型不一致")

    active_rf: set[Edge] = set()
    active_fr: set[Edge] = set()
    active_co: set[Edge] = set()
    fr_valid = True
    for (read_id, address, size), source_id in selected_by_part.items():
        read = event_by_id[read_id]
        part_end = address + size
        for later in writes:
            if later.address >= part_end or later.end_address <= address or later.event_id == read_id:
                continue
            if source_id is None:
                active_fr.add((read_id, later.event_id))
            elif (
                source_id in co_rank
                and later.event_id in co_rank
                and event_by_id[source_id].overlaps(later)
                and co_rank[source_id] < co_rank[later.event_id]
            ):
                active_fr.add((read_id, later.event_id))
    for (read_id, address, size), source_id in selected_by_part.items():
        if source_id is not None and event_by_id[source_id].thread_id != event_by_id[read_id].thread_id:
            active_rf.add((source_id, read_id))
    for left in writes:
        for right in writes:
            if (
                left.event_id != right.event_id
                and left.overlaps(right)
                and left.event_id in co_rank
                and right.event_id in co_rank
                and co_rank[left.event_id] < co_rank[right.event_id]
            ):
                active_co.add((left.event_id, right.event_id))

    active_conditional = active_rf | active_fr | active_co
    source_edges = local_source | active_conditional
    source_cycle = find_cycle(source_edges)
    source_valid = bool(source_cycle)
    if witness.source_cycle and witness.source_cycle != source_cycle:
        # 有多个合法环时只要求序列化的环本身每条边有效且闭合。
        source_valid = (
            len(witness.source_cycle) > 1
            and witness.source_cycle[0] == witness.source_cycle[-1]
            and all(
                (left, right) in source_edges
                for left, right in zip(witness.source_cycle, witness.source_cycle[1:])
            )
        )
    for edge in candidate.ordered_edges:
        if edge.relation_type == "rf":
            matching = set(edge.rf_candidate_ids or edge.relation_ids) & {
                relation.relation_id
                for relation in local_relations
                if relation.kind == "rf"
                and selected_by_part.get((relation.owner_event_id, relation.address, relation.size))
                == relation.event_ids[0]
            }
            if not matching:
                source_valid = False
                reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, ",".join(edge.rf_candidate_ids or edge.relation_ids), "candidate-rf-activation", "候选 cycle 的 RF label 未被模型实际选中")
        elif edge.relation_type == "fr":
            if not (set(edge.fr_consequence_ids or edge.relation_ids) & {
                relation_id for relation_id, (_, _, _, later) in fr_parts.items()
                if relation_id in obligations.required_fr_relation_ids
                and (fr_parts[relation_id][0], later) in active_fr
            }):
                source_valid = False
                reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, ",".join(edge.fr_consequence_ids or edge.relation_ids), "candidate-fr-activation", "候选 cycle 的 FR label 未由选定 RF/CO 派生")
        elif edge.relation_type == "coherence" and (edge.source_event, edge.target_event) not in active_co:
            source_valid = False
            reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, ",".join(edge.co_dependency_ids or edge.relation_ids), "candidate-co-activation", "候选 cycle 的 CO label 未由模型 coherence order 派生")
    required_pairs = {
        (edge.source_event, edge.target_event)
        for edge in candidate.ordered_edges
        if edge.relation_type != "ppo_reachability"
    }
    selected_model_edges = {
        pair
        for pair in cycle_edge_pairs
        if boolean_value("cycle_edge:" + json.dumps(list(pair), separators=(",", ":"))) is True
    }
    selected_node_values = {
        event.event_id: boolean_value(f"cycle_node:{event.event_id}")
        for event in query_events
    }
    if any(value is None for value in selected_node_values.values()):
        source_valid = False
        reject(CandidateReplayFailureKind.WITNESS_SERIALIZATION_ERROR, candidate.cycle_id, "cycle-node-model-values", "cycle node selector 缺少 Bool 模型值")
    for event_id in selected_node_values:
        incoming = sum(right == event_id for _, right in selected_model_edges)
        outgoing = sum(left == event_id for left, _ in selected_model_edges)
        expected_degree = 1 if selected_node_values[event_id] else 0
        if incoming != expected_degree or outgoing != expected_degree:
            source_valid = False
            reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, f"cycle-node:{event_id}", "balanced-cycle-degree", "模型 cycle selector 的入/出度不符合 checker 的 balanced-cycle 约束")
    if not required_pairs <= selected_model_edges:
        source_valid = False
        reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, candidate.cycle_id, "required-cycle-edge-selection", "Z3 模型没有选择候选骨架要求的全部 source cycle edges")
    model_cycle = find_cycle(selected_model_edges)
    if not model_cycle:
        source_valid = False
        reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, candidate.cycle_id, "selected-source-cycle", "完整模型中选择的 source edge 集没有形成闭环")
    for left, right in selected_model_edges:
        if (left, right) not in source_edges:
            source_valid = False
            reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, f"edge:{left}->{right}", "selected-edge-activation", "模型选择了未被 PPO/RF/FR/CO 条件激活的 source edge")
    if any(boolean_value("cycle_edge:" + json.dumps([left, right], separators=(",", ":"))) is None for left, right in cycle_edge_pairs):
        source_valid = False
        reject(CandidateReplayFailureKind.WITNESS_SERIALIZATION_ERROR, candidate.cycle_id, "cycle-edge-model-values", "cycle edge selector 缺少 Bool 模型值")
    target_rank = {
        event.event_id: integer_value(f"target_rank:{event.event_id}")
        for event in query_events
    }
    target_edges = local_target | active_conditional
    target_valid = all(value is not None for value in target_rank.values())
    for left, right in target_edges:
        if target_rank.get(left) is None or target_rank.get(right) is None or target_rank[left] >= target_rank[right]:
            target_valid = False
            reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, f"edge:{left}->{right}", "target-rank-order", "模型 target rank 未满足激活的 target ordering edge")
    if find_cycle(target_edges):
        target_valid = False
        reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, candidate.cycle_id, "target-acyclicity", "由完整 RF/FR/CO witness 重建的 target relation graph 含环")

    boundary_valid = set(candidate.fence_rmw_futex_dependencies) <= query_set
    if not boundary_valid:
        reject(CandidateReplayFailureKind.FENCE_RMW_FUTEX_CONSTRAINT_MISSING, candidate.cycle_id, "boundary-query-closure", "Fence/RMW/FUTEX dependency 不在 local solver event universe")
    for read in reads:
        if read.kind.name != "ATOMIC_RMW":
            continue
        for _, address, size, _ in (part for part in read_parts if part[0].event_id == read.event_id):
            source_id = selected_by_part.get((read.event_id, address, size), "__unassigned__")
            if source_id == "__unassigned__" or read.event_id not in co_rank:
                boundary_valid = False
                reject(CandidateReplayFailureKind.FENCE_RMW_FUTEX_CONSTRAINT_MISSING, f"rmw:{read.event_id}:{address}:{size}", "rmw-rf-co", "RMW read lacks a closed RF/CO assignment")
            elif source_id is None and co_rank[read.event_id] != 0:
                boundary_valid = False
                reject(CandidateReplayFailureKind.FENCE_RMW_FUTEX_CONSTRAINT_MISSING, f"rmw:{read.event_id}:{address}:{size}", "rmw-initial-co", "RMW reading initial state is not first in coherence")
            elif source_id is not None and co_rank.get(read.event_id) != co_rank.get(source_id, -2) + 1:
                boundary_valid = False
                reject(CandidateReplayFailureKind.FENCE_RMW_FUTEX_CONSTRAINT_MISSING, f"rmw:{read.event_id}:{address}:{size}", "rmw-immediate-predecessor", "RMW read source is not the immediate coherence predecessor")

    return _LocalModelReplay(
        model_valid=model_valid,
        full_window_closed=full_window_closed,
        rf_valid=rf_valid,
        fr_valid=fr_valid,
        co_valid=co_valid,
        boundary_valid=boundary_valid,
        source_valid=source_valid,
        target_valid=target_valid,
        failures=tuple(failures),
    )


def replay_candidate_cycle(
    graph,
    certificate,
    candidate: CandidateViolationCycle,
    obligations: LocalCycleObligationSet,
    witness: LocalCycleWitness | None,
    *,
    source_reduced: frozenset[Edge],
    target_reduced: frozenset[Edge],
    events: tuple[TraceEvent, ...],
) -> CandidateCycleReplay:
    """独立校验候选环；不复用 local solver 的内部状态。"""

    reasons: list[str] = []
    failures: list[CandidateReplayFailure] = []

    def reject(
        kind: CandidateReplayFailureKind,
        obligation_id: str,
        predicate: str,
        detail: str,
    ) -> None:
        reasons.append(detail)
        failures.append(
            CandidateReplayFailure(
                kind=kind,
                obligation_id=obligation_id,
                predicate=predicate,
                detail=detail,
            )
        )

    reduction_replay = replay_ppo_reduction(graph, certificate)
    if not reduction_replay.accepted:
        reject(
            CandidateReplayFailureKind.BINDING_MISMATCH,
            candidate.cycle_id,
            "ppo-certificate-replay",
            "PPO reduction certificate replay failed: " + "; ".join(reduction_replay.reasons),
        )
    expected_source = _reduced_edges(
        graph.source_edges, certificate.source.removed_edges
    )
    expected_target = _reduced_edges(
        graph.target_edges, certificate.target.removed_edges
    )
    if expected_source != source_reduced:
        reject(CandidateReplayFailureKind.BINDING_MISMATCH, candidate.cycle_id, "source-ppo-binding", "source PPO input does not match certificate replay")
    if expected_target != target_reduced:
        reject(CandidateReplayFailureKind.BINDING_MISMATCH, candidate.cycle_id, "target-ppo-binding", "target PPO input does not match certificate replay")
    cycle_closed = bool(candidate.cycle_nodes) and candidate.cycle_nodes[0] == candidate.cycle_nodes[-1]
    if not cycle_closed:
        reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, candidate.cycle_id, "cycle-closure", "candidate cycle nodes are not closed")
    edge_pairs = [(edge.source_event, edge.target_event) for edge in candidate.ordered_edges]
    if edge_pairs and any(
        left[1] != right[0] for left, right in zip(edge_pairs, edge_pairs[1:])
    ):
        cycle_closed = False
        reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, candidate.cycle_id, "edge-contiguity", "candidate edge order is not contiguous")
    ppo_valid = True
    for edge in candidate.ordered_edges:
        if edge.relation_type != "ppo_reachability":
            continue
        path = edge.ppo_reachability_path
        if len(path) < 2 or not all(
            (left, right) in source_reduced for left, right in zip(path, path[1:])
        ):
            ppo_valid = False
            reject(CandidateReplayFailureKind.PPO_WITNESS_INVALID, f"ppo:{edge.source_event}->{edge.target_event}", "reduced-edge-path", f"missing PPO witness for {edge.source_event}->{edge.target_event}")
    event_by_id = {event.event_id: event for event in events}
    relations = {item.relation_id: item for item in _candidate_relations(events)}
    rf_valid = True
    for relation_id in obligations.selected_rf_relation_ids:
        relation = relations.get(relation_id)
        if relation is None or relation.kind != "rf":
            rf_valid = False
            reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, relation_id, "candidate-domain-membership", f"RF candidate is absent: {relation_id}")
        elif event_by_id[relation.event_ids[0]].thread_id == event_by_id[relation.event_ids[1]].thread_id:
            rf_valid = False
            reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, relation_id, "cross-thread-rf", f"RF candidate is not cross-thread: {relation_id}")
    if candidate.rf_dependencies and not obligations.selected_rf_relation_ids:
        rf_valid = False
        reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, candidate.cycle_id, "candidate-rf-assignment", "candidate RF edge has no witness assignment")
    assignments = witness.rf_assignments if witness is not None else ()
    by_part: dict[tuple[str, int, int], str | None] = {}
    rf_exclusive = witness is not None and obligations.rf_exclusivity_preserved
    for read, write, address, size in assignments:
        key = (read, address, size)
        previous = by_part.setdefault(key, write)
        if previous != write:
            rf_exclusive = False
            reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, f"rf:{read}:{address}:{size}", "exactly-one", f"RF part has multiple assignments: {read}:{address}:{size}")
    if witness is None:
        rf_exclusive = False
        reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, candidate.cycle_id, "solver-model-witness", "local solver did not provide an RF witness")
    assigned_reads = {read for read, _, _, _ in assignments}
    selected_reads = {read for read, _, _, _ in assignments}
    expected_domain = {
        item.relation_id
        for item in relations.values()
        if item.kind == "rf" and item.owner_event_id in selected_reads
    }
    if set(obligations.rf_candidate_domain_ids) != expected_domain:
        rf_exclusive = False
        reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, candidate.cycle_id, "complete-rf-domain", "RF candidate domain is incomplete or has extra relations")
    if not selected_reads <= assigned_reads:
        rf_exclusive = False
        reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, candidate.cycle_id, "rf-read-assignment", "RF witness does not assign every selected read")
    assigned_pairs = {(write, read) for read, write, _, _ in assignments if write is not None}
    selected_cycle_rf = set(candidate.rf_dependencies) & set(obligations.selected_rf_relation_ids)
    for edge in candidate.ordered_edges:
        if edge.relation_type != "rf":
            continue
        edge_ids = set(edge.rf_candidate_ids or edge.relation_ids)
        realized = edge_ids & selected_cycle_rf
        if not realized:
            rf_valid = False
            reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, ",".join(sorted(edge_ids)) or candidate.cycle_id, "candidate-edge-rf-selection", f"candidate RF edge {edge.source_event}->{edge.target_event} is not selected by the witness")
        selected_pairs = {
            relations[item].event_ids
            for item in realized
            if item in relations and relations[item].kind == "rf"
        }
        if not selected_pairs <= assigned_pairs:
            rf_valid = False
            reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, ",".join(sorted(realized)) or candidate.cycle_id, "rf-witness-source", "RF witness does not realize the candidate edge's selected source")

    co_pairs = witness.co_assignments if witness is not None else ()
    fr_valid = True
    selected_writes = {
        (read, address, size): write
        for read, write, address, size in assignments
    }
    fr_parts = _fr_relation_parts(events)
    for relation_id in obligations.required_fr_relation_ids:
        relation = relations.get(relation_id)
        part = fr_parts.get(relation_id)
        if relation is None or relation.kind != "fr" or part is None:
            fr_valid = False
            reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, relation_id, "fr-relation-inventory", f"FR consequence is absent: {relation_id}")
            continue
        read_id, address, size, later_id = part
        source_id = selected_writes.get((read_id, address, size), "__unassigned__")
        later = event_by_id.get(later_id)
        read = event_by_id.get(read_id)
        if source_id == "__unassigned__":
            fr_valid = False
            reject(CandidateReplayFailureKind.RF_ASSIGNMENT_INCOMPLETE, relation_id, "fr-read-part-rf", f"FR obligation has no RF assignment for its read-part: {relation_id}")
        elif (
            read is None
            or later is None
            or address >= later.end_address
            or address + size <= later.address
        ):
            fr_valid = False
            reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, relation_id, "fr-byte-overlap", f"FR relation does not overlap its read-part and later write: {relation_id}")
        elif source_id is None:
            # 读初始值时，初始写在 coherence 中先于所有普通写。
            pass
        else:
            source = event_by_id.get(source_id)
            if source is None or not source.overlaps(later):
                fr_valid = False
                reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, relation_id, "fr-source-overlap", f"selected RF source does not overlap the later write: {relation_id}")
            elif source_id == later_id or not _co_reaches(co_pairs, source_id, later_id):
                fr_valid = False
                reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, relation_id, "fr-co-order", f"FR witness lacks the required CO order: {relation_id}")

    co_valid = True
    for left_id, right_id in co_pairs:
        left, right = event_by_id.get(left_id), event_by_id.get(right_id)
        # co_assignments 是 overlap-connected 写的 rank 顺序见证；相邻 rank
        # 项本身可以不重叠，真正的 CO edge 只由重叠且 rank 有序的 pair 派生。
        if left is None or right is None or not left.kind.is_write or not right.kind.is_write:
            co_valid = False
            reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, f"co:{left_id}->{right_id}", "co-rank-witness-events", f"CO rank witness references a missing/non-write event: {left_id}->{right_id}")
    if find_cycle(set(co_pairs)):
        co_valid = False
        reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, candidate.cycle_id, "co-acyclicity", "CO witness contains a cycle")
    for relation_id in obligations.required_co_relation_ids:
        relation = relations.get(relation_id)
        if relation is None or relation.kind != "coherence":
            co_valid = False
            reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, relation_id, "co-relation-inventory", f"CO candidate is absent: {relation_id}")
        elif not _co_reaches(co_pairs, relation.event_ids[0], relation.event_ids[1]):
            co_valid = False
            reject(CandidateReplayFailureKind.FR_CO_INCONSISTENT, relation_id, "co-rank-order", f"CO witness lacks the required order: {relation_id}")
    boundary_valid = all(item in event_by_id for item in candidate.fence_rmw_futex_dependencies)
    if not boundary_valid:
        reject(CandidateReplayFailureKind.FENCE_RMW_FUTEX_CONSTRAINT_MISSING, candidate.cycle_id, "boundary-event-presence", "boundary dependency references an unknown event")

    local_source_ids = set(candidate.cycle_nodes)
    for edge in candidate.ordered_edges:
        local_source_ids.update(edge.ppo_reachability_path)
    local_source_edges = {
        edge
        for edge in source_reduced
        if edge[0] in local_source_ids and edge[1] in local_source_ids
    }
    local_source_edges.update(
        (edge.source_event, edge.target_event)
        for edge in candidate.ordered_edges
        if edge.relation_type != "ppo_reachability"
    )
    source_valid = bool(edge_pairs) and any(
        edge.relation_type != "ppo_reachability"
        for edge in candidate.ordered_edges
    ) and bool(find_cycle(local_source_edges))
    if not source_valid:
        reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, candidate.cycle_id, "source-bad-cycle", "candidate does not close a source-side cycle")
    target_edges = set(target_reduced)
    if witness is not None:
        target_edges.update(
            (edge.source_event, edge.target_event)
            for edge in candidate.ordered_edges
            if edge.relation_type != "ppo_reachability"
        )
        target_edges.update(witness.fr_consequences)
        target_edges.update(
            (left_id, right_id)
            for left_id, right_id in witness.co_assignments
            if left_id in event_by_id
            and right_id in event_by_id
            and event_by_id[left_id].overlaps(event_by_id[right_id])
        )
    target_valid = not bool(find_cycle(target_edges))
    if not target_valid:
        reject(CandidateReplayFailureKind.SOURCE_TARGET_SEMANTIC_CONFLICT, candidate.cycle_id, "target-acyclicity", "target ordering condition has a cycle")

    model_result = None
    if witness is not None and witness.model_snapshot is not None:
        model_result = _replay_local_symbolic_model(
            candidate,
            obligations,
            witness,
            source_reduced=source_reduced,
            target_reduced=target_reduced,
            events=events,
        )
        failures.extend(model_result.failures)
        reasons.extend(item.detail for item in model_result.failures)
        rf_valid = model_result.rf_valid
        rf_exclusive = model_result.rf_valid
        fr_valid = model_result.fr_valid
        co_valid = model_result.co_valid
        boundary_valid = model_result.boundary_valid
        source_valid = model_result.source_valid
        target_valid = model_result.target_valid
    if candidate.unresolved_dependencies:
        reject(
            CandidateReplayFailureKind.FENCE_RMW_FUTEX_CONSTRAINT_MISSING,
            candidate.cycle_id,
            "unresolved-boundary-or-relation",
            "candidate contains unresolved dependencies: "
            + ", ".join(candidate.unresolved_dependencies),
        )

    accepted = (
        witness is not None
        and cycle_closed
        and ppo_valid
        and rf_valid
        and rf_exclusive
        and fr_valid
        and co_valid
        and boundary_valid
        and source_valid
        and target_valid
        and (
            model_result is None
            or (model_result.model_valid and model_result.full_window_closed)
        )
        and not candidate.unresolved_dependencies
    )
    status = (
        CandidateCycleReplayStatus.ACCEPTED
        if accepted
        else CandidateCycleReplayStatus.REJECTED
        if witness is not None
        else CandidateCycleReplayStatus.NOT_RUN
    )
    return CandidateCycleReplay(
        cycle_id=candidate.cycle_id,
        status=status,
        cycle_closed=cycle_closed,
        ppo_reachability_valid=ppo_valid,
        rf_candidates_valid=rf_valid,
        rf_exclusivity_valid=rf_exclusive,
        fr_consequences_valid=fr_valid,
        co_valid=co_valid,
        boundary_ordering_valid=boundary_valid,
        source_violation_valid=source_valid,
        target_condition_valid=target_valid,
        model_snapshot_valid=(model_result.model_valid if model_result is not None else None),
        full_window_closed=(model_result.full_window_closed if model_result is not None else None),
        failures=tuple(dict.fromkeys(failures)),
        reasons=tuple(dict.fromkeys(reasons)),
    )


__all__ = [
    "characterize_graph_first_window",
    "graph_first_trace",
    "replay_candidate_cycle",
]
