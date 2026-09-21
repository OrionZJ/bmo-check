from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from bmo_check_dynamic.model import (
    EventKind,
    TraceEvent,
    WindowGraphAddress,
    WindowGraphDiagnostics,
    WindowGraphNode,
)

from .windows import AnalysisWindow, WindowInclusionReason, _biconnected_components


Edge = tuple[str, str]


@dataclass(frozen=True, slots=True)
class _GraphEdges:
    communication: frozenset[Edge]
    program_order: frozenset[Edge]
    boundary: frozenset[Edge]

    @property
    def all(self) -> frozenset[Edge]:
        return self.communication | self.program_order | self.boundary


def characterize_window_graph(
    window: AnalysisWindow,
    *,
    top_n: int = 16,
) -> WindowGraphDiagnostics:
    """表征当前窗口实际构造出的关系图，不改变窗口或 proof 输入。

    ``build_windows`` 只把通信端点、同线程端点序和最小 boundary 放进窗口。
    这里按 ``event_inclusions`` 重建同一组边，并把三类边分开统计，避免把
    “节点很多”误报成“所有节点都参与通信”。
    """

    if top_n < 1:
        raise ValueError("top_n must be positive")
    events = {event.event_id: event for event in window.events}
    edges = _reconstruct_edges(window, events)
    graph: dict[str, set[str]] = {event_id: set() for event_id in events}
    for left, right in edges.all:
        if left not in graph or right not in graph or left == right:
            continue
        graph[left].add(right)
        graph[right].add(left)

    degrees = sorted((len(neighbors) for neighbors in graph.values()), reverse=True)
    p95_index = max(0, (95 * len(degrees) + 99) // 100 - 1)
    components = _connected_components(graph)
    biconnected = _biconnected_components(graph)
    isolated = sum(not neighbors for neighbors in graph.values())
    biconnected_sizes = [len(component) for component in biconnected]
    biconnected_edges = [
        sum(
            1
            for left in component
            for right in graph[left]
            if right in component and left < right
        )
        for component in biconnected
    ]
    if isolated:
        biconnected_sizes.extend([1] * isolated)
        biconnected_edges.extend([0] * isolated)

    node_details = []
    for event_id, degree in sorted(
        ((event_id, len(neighbors)) for event_id, neighbors in graph.items()),
        key=lambda item: (-item[1], item[0]),
    )[:top_n]:
        event = events[event_id]
        node_details.append(
            WindowGraphNode(
                event_id=event_id,
                thread_id=event.thread_id,
                sequence=event.sequence,
                kind=event.kind.name,
                degree=degree,
                communication_degree=_node_degree(edges.communication, event_id),
                program_order_degree=_node_degree(edges.program_order, event_id),
                boundary_degree=_node_degree(edges.boundary, event_id),
            )
        )

    address_counts: Counter[tuple[int, int]] = Counter(
        (event.address, event.size)
        for event in window.events
        if event.kind.is_memory and event.size > 0
    )
    address_edge_counts: Counter[tuple[int, int]] = Counter(
        (edge.address, edge.size) for edge in window.communication_edges
    )
    address_kinds: dict[tuple[int, int], Counter[str]] = defaultdict(Counter)
    for event in window.events:
        if event.kind.is_memory and event.size > 0:
            address_kinds[(event.address, event.size)][event.kind.name] += 1
    address_details = tuple(
        WindowGraphAddress(
            address=address,
            size=size,
            event_count=count,
            communication_edge_count=address_edge_counts[(address, size)],
            load_count=address_kinds[(address, size)][EventKind.LOAD.name],
            store_count=address_kinds[(address, size)][EventKind.STORE.name],
        )
        for (address, size), count in sorted(
            address_counts.items(),
            key=lambda item: (-item[1], item[0][0], item[0][1]),
        )[:top_n]
    )

    return WindowGraphDiagnostics(
        node_count=len(graph),
        communication_edge_count=len(edges.communication),
        program_order_edge_count=len(edges.program_order),
        boundary_edge_count=len(edges.boundary),
        graph_edge_count=len(edges.all),
        connected_component_count=len(components),
        biconnected_component_count=len(biconnected_sizes),
        articulation_node_count=len(_articulation_nodes(graph)),
        max_degree=max(degrees, default=0),
        p95_degree=degrees[p95_index] if degrees else 0,
        max_biconnected_component_nodes=max(biconnected_sizes, default=0),
        max_biconnected_component_edges=max(biconnected_edges, default=0),
        top_degree_nodes=tuple(node_details),
        top_address_classes=address_details,
    )


def _reconstruct_edges(
    window: AnalysisWindow,
    events: dict[str, TraceEvent],
) -> _GraphEdges:
    communication: set[Edge] = set()
    for edge in window.communication_edges:
        communication.add(_canonical_edge(edge.first_event, edge.second_event))

    endpoint_ids = {
        inclusion.event_id
        for inclusion in window.event_inclusions
        if WindowInclusionReason.COMMUNICATION_ENDPOINT in inclusion.reasons
    }
    if not endpoint_ids:
        endpoint_ids = {
            event_id
            for edge in window.communication_edges
            for event_id in (edge.first_event, edge.second_event)
        }
    endpoint_by_thread: dict[int, list[TraceEvent]] = defaultdict(list)
    for event_id in endpoint_ids:
        event = events.get(event_id)
        if event is not None:
            endpoint_by_thread[event.thread_id].append(event)
    program_order: set[Edge] = set()
    for values in endpoint_by_thread.values():
        values.sort(key=lambda event: (event.sequence, event.event_id))
        program_order.update(
            _canonical_edge(left.event_id, right.event_id)
            for left, right in zip(values, values[1:])
        )

    boundary_ids = {
        inclusion.event_id
        for inclusion in window.event_inclusions
        if WindowInclusionReason.ORDERING_BOUNDARY in inclusion.reasons
    }
    if not boundary_ids:
        boundary_ids = {
            event.event_id
            for event in events.values()
            if event.kind.is_boundary and event.event_id not in endpoint_ids
        }
    boundary_edges: set[Edge] = set()
    for boundary_id in boundary_ids:
        boundary = events.get(boundary_id)
        if boundary is None:
            continue
        category = _boundary_category(boundary.kind)
        thread_events = sorted(
            endpoint_by_thread.get(boundary.thread_id, ()),
            key=lambda event: (event.sequence, event.event_id),
        )
        before = [
            event
            for event in thread_events
            if event.sequence < boundary.sequence
            and _boundary_accepts(category, event.kind)
        ]
        after = [
            event
            for event in thread_events
            if event.sequence > boundary.sequence
            and _boundary_accepts(category, event.kind)
        ]
        if not before or not after:
            continue
        for event in (*before, *after):
            boundary_edges.add(_canonical_edge(boundary_id, event.event_id))

    return _GraphEdges(
        frozenset(communication),
        frozenset(program_order),
        frozenset(boundary_edges),
    )


def _canonical_edge(left: str, right: str) -> Edge:
    return (left, right) if left < right else (right, left)


def _node_degree(edges: frozenset[Edge], event_id: str) -> int:
    return sum(event_id in edge for edge in edges)


def _connected_components(graph: dict[str, set[str]]) -> tuple[frozenset[str], ...]:
    unseen = set(graph)
    components: list[frozenset[str]] = []
    while unseen:
        root = min(unseen)
        pending = [root]
        unseen.remove(root)
        component = {root}
        while pending:
            node = pending.pop()
            for neighbor in graph[node]:
                if neighbor in unseen:
                    unseen.remove(neighbor)
                    component.add(neighbor)
                    pending.append(neighbor)
        components.append(frozenset(component))
    return tuple(components)


def _articulation_nodes(graph: dict[str, set[str]]) -> set[str]:
    discovery: dict[str, int] = {}
    low: dict[str, int] = {}
    parent: dict[str, str | None] = {}
    articulation: set[str] = set()
    clock = 0

    def visit(node: str) -> None:
        nonlocal clock
        clock += 1
        discovery[node] = low[node] = clock
        children = 0
        for neighbor in sorted(graph[node]):
            if neighbor not in discovery:
                parent[neighbor] = node
                children += 1
                visit(neighbor)
                low[node] = min(low[node], low[neighbor])
                if parent.get(node) is None and children > 1:
                    articulation.add(node)
                if parent.get(node) is not None and low[neighbor] >= discovery[node]:
                    articulation.add(node)
            elif neighbor != parent.get(node):
                low[node] = min(low[node], discovery[neighbor])

    for node in sorted(graph):
        if node not in discovery:
            parent[node] = None
            visit(node)
    return articulation


def _boundary_category(kind: EventKind) -> str:
    if kind in {EventKind.ATOMIC_RMW, EventKind.FUTEX_WAIT, EventKind.MFENCE}:
        return "full"
    if kind == EventKind.LFENCE:
        return "read"
    return "write"


def _boundary_accepts(category: str, kind: EventKind) -> bool:
    if category == "full":
        return kind.is_memory
    if category == "read":
        return kind.is_read
    return kind.is_write


__all__ = ["characterize_window_graph"]
