from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from bmo_check_dynamic.model import (
    CandidateBlockingClause,
    CandidateCycleReplay,
    CandidateCycleReplayStatus,
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
    candidates, explored, truncated, skeleton_edges = _enumerate_skeleton_cycles(
        window.events,
        labeled,
        source_reduced,
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
        candidate = _build_candidate_violation_cycle(
            cycle_id=f"{window.window_id}:cycle-{index:04d}",
            cycle_edges=cycle_edges,
            event_by_id=event_by_id,
        )
        local_witness = _build_local_witness(
            candidate,
            cycle_edges=cycle_edges,
            local_result=local_result,
        )
        # RF/CO 的端点也必须成为 local query 的必要条件；否则 solver
        # 可能用另一条 conditional edge 闭合一个不同的环，而 replay
        # 看到的却仍是 producer 声称的 candidate。
        obligations = _build_local_obligations(
            candidate,
            cycle_edges=cycle_edges,
            events=window.events,
            witness=local_witness,
        )
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
        blocking = (
            _blocking_clause(candidate, obligations, observation.result)
            if query.feasibility_status is LocalCycleStatus.INFEASIBLE
            else None
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
                blocking_clause=blocking,
            )
        )
        # Keep the result variable visible in this diagnostic route: the
        # observation is intentionally the only accepted summary of the query.
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

    @classmethod
    def build(
        cls,
        events: tuple[TraceEvent, ...],
        edges: frozenset[Edge],
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
        )

    def path(self, source: str, target: str) -> tuple[str, ...] | None:
        key = (source, target)
        if key in self.path_cache:
            return self.path_cache[key]
        if source == target:
            self.path_cache[key] = ()
            return ()
        first, last = self.events.get(source), self.events.get(target)
        if first is None or last is None or first.thread_id != last.thread_id:
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
                            self.path_cache[key] = None
                            return None
                        path.append(previous)
                    path.reverse()
                    value = tuple(path)
                    self.path_cache[key] = value
                    return value
                pending.append(neighbor)
        self.path_cache[key] = None
        return None

    def reachable_sources(
        self,
        source: str,
        targets_by_thread: dict[int, set[str]],
    ) -> dict[str, tuple[str, ...]]:
        cached = self.source_cache.get(source)
        if cached is not None:
            return cached
        event = self.events.get(source)
        if event is None:
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
        self.source_cache[source] = found
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
) -> tuple[
    list[tuple[tuple[str, ...], tuple[_LabeledEdge, ...]]],
    int,
    bool,
    tuple[_LabeledEdge, ...],
]:
    """从 conditional edges 出发，懒查询 PPO reachability 并生成 skeleton。"""

    conditional = tuple(edge for edge in may_edges if edge.kind != "source_ppo")
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
    selected_reads = {
        by_id[item].owner_event_id
        for item in selected_rf
        if item in by_id and by_id[item].kind == "rf"
    }
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
    reduction_replay = replay_ppo_reduction(graph, certificate)
    if not reduction_replay.accepted:
        reasons.append("PPO reduction certificate replay failed")
    expected_source = _reduced_edges(
        graph.source_edges, certificate.source.removed_edges
    )
    expected_target = _reduced_edges(
        graph.target_edges, certificate.target.removed_edges
    )
    if expected_source != source_reduced:
        reasons.append("source PPO input does not match certificate replay")
    if expected_target != target_reduced:
        reasons.append("target PPO input does not match certificate replay")
    cycle_closed = bool(candidate.cycle_nodes) and candidate.cycle_nodes[0] == candidate.cycle_nodes[-1]
    if not cycle_closed:
        reasons.append("candidate cycle nodes are not closed")
    edge_pairs = [(edge.source_event, edge.target_event) for edge in candidate.ordered_edges]
    if edge_pairs and any(
        left[1] != right[0] for left, right in zip(edge_pairs, edge_pairs[1:])
    ):
        cycle_closed = False
        reasons.append("candidate edge order is not contiguous")
    ppo_valid = True
    for edge in candidate.ordered_edges:
        if edge.relation_type != "ppo_reachability":
            continue
        path = edge.ppo_reachability_path
        if len(path) < 2 or not all(
            (left, right) in source_reduced for left, right in zip(path, path[1:])
        ):
            ppo_valid = False
            reasons.append(f"missing PPO witness for {edge.source_event}->{edge.target_event}")
    event_by_id = {event.event_id: event for event in events}
    relations = {item.relation_id: item for item in _candidate_relations(events)}
    rf_valid = True
    for relation_id in obligations.selected_rf_relation_ids:
        relation = relations.get(relation_id)
        if relation is None or relation.kind != "rf":
            rf_valid = False
            reasons.append(f"RF candidate is absent: {relation_id}")
        elif event_by_id[relation.event_ids[0]].thread_id == event_by_id[relation.event_ids[1]].thread_id:
            rf_valid = False
            reasons.append(f"RF candidate is not cross-thread: {relation_id}")
    if candidate.rf_dependencies and not obligations.selected_rf_relation_ids:
        rf_valid = False
        reasons.append("candidate RF edge has no witness assignment")
    if not set(obligations.selected_rf_relation_ids) <= set(candidate.rf_dependencies):
        rf_valid = False
        reasons.append("RF witness selected a relation outside the candidate edge")
    assignments = witness.rf_assignments if witness is not None else ()
    by_part: dict[tuple[str, int, int], str | None] = {}
    rf_exclusive = witness is not None and obligations.rf_exclusivity_preserved
    for read, write, address, size in assignments:
        key = (read, address, size)
        previous = by_part.setdefault(key, write)
        if previous != write:
            rf_exclusive = False
            reasons.append(f"RF part has multiple assignments: {read}:{address}:{size}")
    if witness is None:
        rf_exclusive = False
        reasons.append("local solver did not provide an RF witness")
    assigned_reads = {read for read, _, _, _ in assignments}
    selected_reads = {
        relations[item].owner_event_id
        for item in obligations.selected_rf_relation_ids
        if item in relations and relations[item].kind == "rf"
    }
    expected_domain = {
        item.relation_id
        for item in relations.values()
        if item.kind == "rf" and item.owner_event_id in selected_reads
    }
    if set(obligations.rf_candidate_domain_ids) != expected_domain:
        rf_exclusive = False
        reasons.append("RF candidate domain is incomplete or has extra relations")
    if not selected_reads <= assigned_reads:
        rf_exclusive = False
        reasons.append("RF witness does not assign every selected read")
    assigned_pairs = {(write, read) for read, write, _, _ in assignments if write is not None}
    selected_pairs = {
        relations[item].event_ids
        for item in obligations.selected_rf_relation_ids
        if item in relations and relations[item].kind == "rf"
    }
    if not selected_pairs <= assigned_pairs:
        rf_valid = False
        reasons.append("RF witness does not realize every selected candidate")

    co_pairs = witness.co_assignments if witness is not None else ()
    fr_valid = True
    selected_writes = {read: write for read, write, _, _ in assignments}
    for relation_id in obligations.required_fr_relation_ids:
        relation = relations.get(relation_id)
        if relation is None or relation.kind != "fr":
            fr_valid = False
            reasons.append(f"FR consequence is absent: {relation_id}")
            continue
        read_id, later_id = relation.event_ids
        source_id = selected_writes.get(read_id)
        source = event_by_id.get(source_id) if source_id is not None else None
        later = event_by_id.get(later_id)
        if source is None or later is None or not source.overlaps(later):
            fr_valid = False
            reasons.append(f"FR source does not overlap later write: {relation_id}")
        elif source_id == later_id or not _co_reaches(co_pairs, source_id, later_id):
            fr_valid = False
            reasons.append(f"FR witness lacks the required CO order: {relation_id}")

    co_valid = True
    for left_id, right_id in co_pairs:
        left, right = event_by_id.get(left_id), event_by_id.get(right_id)
        if left is None or right is None or not left.overlaps(right):
            co_valid = False
            reasons.append(f"CO pair is not overlapping: {left_id}->{right_id}")
    if find_cycle(set(co_pairs)):
        co_valid = False
        reasons.append("CO witness contains a cycle")
    for relation_id in obligations.required_co_relation_ids:
        relation = relations.get(relation_id)
        if relation is None or relation.kind != "coherence":
            co_valid = False
            reasons.append(f"CO candidate is absent: {relation_id}")
        elif not _co_reaches(co_pairs, relation.event_ids[0], relation.event_ids[1]):
            co_valid = False
            reasons.append(f"CO witness lacks the required order: {relation_id}")
    boundary_valid = all(item in event_by_id for item in candidate.fence_rmw_futex_dependencies)
    if not boundary_valid:
        reasons.append("boundary dependency references an unknown event")

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
        reasons.append("candidate does not close a source-side cycle")
    target_edges = set(target_reduced)
    if witness is not None:
        target_edges.update(
            (edge.source_event, edge.target_event)
            for edge in candidate.ordered_edges
            if edge.relation_type != "ppo_reachability"
        )
        target_edges.update(witness.fr_consequences)
        target_edges.update(witness.co_assignments)
    target_valid = not bool(find_cycle(target_edges))
    if not target_valid:
        reasons.append("target ordering condition has a cycle")

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
        reasons=tuple(dict.fromkeys(reasons)),
    )


__all__ = [
    "characterize_graph_first_window",
    "graph_first_trace",
    "replay_candidate_cycle",
]
