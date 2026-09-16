from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass

from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.storage import TraceStore

from .communication import (
    CompactCommunicationEdges,
    CommunicationEdge,
    CommunicationEndpoint,
)


@dataclass(frozen=True, slots=True)
class AnalysisWindow:
    window_id: str
    events: tuple[TraceEvent, ...]
    communication_edges: tuple[CommunicationEdge, ...]


def build_windows(
    store: TraceStore,
    edges: tuple[CommunicationEdge, ...] | CompactCommunicationEdges,
    *,
    max_events: int,
) -> tuple[tuple[AnalysisWindow, ...], tuple[str, ...]]:
    if isinstance(edges, CompactCommunicationEdges):
        return _build_compact_windows(store, edges, max_events=max_events)

    # 通信边很多时，直接用 event_id 字符串建图会同时保留大量字符串、哈希表
    # 和集合节点。这里先把本次窗口中的事件编号成整数，图的语义不变，
    # 但把主要内存开销从 Python 字符串降到整数集合；超限分量仍会返回 UNKNOWN。
    node_ids: dict[str, int] = {}
    graph: dict[int, set[int]] = defaultdict(set)

    def intern(event_id: str) -> int:
        node_id = node_ids.get(event_id)
        if node_id is None:
            node_id = len(node_ids)
            node_ids[event_id] = node_id
        return node_id

    edge_nodes: list[tuple[int, int, CommunicationEdge]] = []
    for edge in edges:
        first = intern(edge.first_event)
        second = intern(edge.second_event)
        graph[first].add(second)
        graph[second].add(first)
        edge_nodes.append((first, second, edge))
    endpoint_ids = {
        event_id
        for edge in edges
        for event_id in (edge.first_event, edge.second_event)
    }
    endpoint_facts = _edge_endpoint_facts(edges)
    if endpoint_facts is None:
        # 手工构造的边没有扫描时缓存的位置，仍从数据库读取真实事件。
        endpoint_facts = {
            event.event_id: CommunicationEndpoint(
                event.event_id, event.thread_id, event.sequence, event.kind
            )
            for event in store.get_events(endpoint_ids)
        }
    endpoints_by_thread: dict[int, list[CommunicationEndpoint]] = defaultdict(list)
    for endpoint in endpoint_facts.values():
        endpoints_by_thread[endpoint.thread_id].append(endpoint)
    # 不同地址仍可通过同一线程的程序序组成内存序环，不能分到独立窗口。
    for thread_events in endpoints_by_thread.values():
        thread_events.sort(key=lambda endpoint: endpoint.sequence)
        for left, right in zip(thread_events, thread_events[1:]):
            left_id = intern(left.event_id)
            right_id = intern(right.event_id)
            graph[left_id].add(right_id)
            graph[right_id].add(left_id)
        if len(thread_events) < 2:
            continue
        boundaries = store.boundaries_between(
            thread_events[0].thread_id,
            thread_events[0].sequence,
            thread_events[-1].sequence,
        )
        for boundary in boundaries:
            category = _boundary_category(boundary.kind)
            before = [
                endpoint
                for endpoint in thread_events
                if endpoint.sequence < boundary.sequence
                and _boundary_accepts(category, endpoint.kind)
            ]
            after = [
                endpoint
                for endpoint in thread_events
                if endpoint.sequence > boundary.sequence
                and _boundary_accepts(category, endpoint.kind)
            ]
            if not before or not after:
                continue
            # 分解前把 boundary 当作星形中心。否则 Fence 形成的弦可能跨过割点，
            # 两个分别判 safe 的窗口合起来却存在关系环。
            boundary_id = intern(boundary.event_id)
            graph.setdefault(boundary_id, set())
            for event in (*before, *after):
                if event.event_id == boundary.event_id:
                    continue
                event_id = intern(event.event_id)
                graph[boundary_id].add(event_id)
                graph[event_id].add(boundary_id)

    # 一个关系环只能落在同一个无向双连通分量内。按普通连接分量切分会把
    # 共享割点的长链合成巨窗，既增加枚举量，也没有提供额外反例路径。
    components = _biconnected_components(graph)
    windows: list[AnalysisWindow] = []
    unknowns: list[str] = []
    grouped_edges, unassigned_edge_count = _group_edge_nodes_by_component(
        components, edge_nodes
    )
    if unassigned_edge_count:
        unknowns.append(
            f"{unassigned_edge_count} communication edges were not assigned "
            "to a biconnected component"
        )
    for index, component_edges in enumerate(grouped_edges):
        endpoint_ids = {
            event_id
            for edge in component_edges
            for event_id in (edge.first_event, edge.second_event)
        }
        window_id = f"window-{index:06d}"
        if len(endpoint_ids) > max_events:
            # 端点数已经超过上限；再读完整访存和 Fence 只会耗时，不会让窗口可检查。
            unknowns.append(
                f"{window_id} contains at least {len(endpoint_ids)} events, "
                f"limit is {max_events}"
            )
            continue
        endpoints = store.get_events(endpoint_ids)
        ranges: dict[int, list[int]] = {}
        for event in endpoints:
            bounds = ranges.setdefault(event.thread_id, [event.sequence, event.sequence])
            bounds[0] = min(bounds[0], event.sequence)
            bounds[1] = max(bounds[1], event.sequence)
        selected = {event.event_id: event for event in endpoints}
        for thread_id, (first, last) in sorted(ranges.items()):
            thread_endpoints = sorted(
                (
                    event
                    for event in endpoints
                    if event.thread_id == thread_id
                ),
                key=lambda event: event.sequence,
            )
            boundaries = store.boundaries_between(thread_id, first, last)
            for event in _minimal_boundaries(thread_endpoints, boundaries):
                selected[event.event_id] = event
        # 没有通信边的普通访存不可能成为关系环节点。Fence/atomic 必须保留，
        # 因为它们会让两个端点在 source 和 target 中同时恢复顺序。
        events = tuple(
            sorted(selected.values(), key=lambda event: (event.thread_id, event.sequence))
        )
        if len(events) > max_events:
            unknowns.append(
                f"{window_id} contains {len(events)} events, limit is {max_events}"
            )
            continue
        windows.append(
            AnalysisWindow(window_id, events, tuple(component_edges))
        )
    return tuple(windows), tuple(unknowns)


def _build_compact_windows(
    store: TraceStore,
    edges: CompactCommunicationEdges,
    *,
    max_events: int,
) -> tuple[tuple[AnalysisWindow, ...], tuple[str, ...]]:
    """构造大轨迹窗口时只保留整数图；超过边界就提前 UNKNOWN。

    旧的字符串图路径继续服务小型/手工测试。紧凑路径先按通信边和程序序
    分解，再检查 Fence/atomic 是否可能跨越分量；无法证明没有跨越时宁可
    返回 UNKNOWN，也不把边界事件悄悄丢掉。
    """

    graph: dict[int, set[int]] = defaultdict(set)
    edge_nodes: list[tuple[int, int, int]] = []
    for index in range(edges.edge_count):
        left = int(edges.left_nodes[index])
        right = int(edges.right_nodes[index])
        graph[left].add(right)
        graph[right].add(left)
        edge_nodes.append((left, right, index))

    endpoints_by_thread: dict[int, list[int]] = defaultdict(list)
    for node in range(edges.node_count):
        endpoints_by_thread[int(edges.thread_ids[node])].append(node)
    for thread_nodes in endpoints_by_thread.values():
        thread_nodes.sort(key=lambda node: int(edges.sequences[node]))
        for left, right in zip(thread_nodes, thread_nodes[1:]):
            graph[left].add(right)
            graph[right].add(left)

    components = _biconnected_components(graph)
    memberships: dict[int, set[int]] = defaultdict(set)
    for component_index, component in enumerate(components):
        for node in component:
            memberships[node].add(component_index)

    grouped_indices: list[list[int]] = [[] for _ in components]
    unknowns: list[str] = []
    for left, right, edge_index in edge_nodes:
        left_components = memberships.get(left, set())
        right_components = memberships.get(right, set())
        matches = left_components & right_components
        if not matches:
            unknowns.append(
                f"communication edge {edge_index} was not assigned to a window"
            )
            continue
        for component_index in matches:
            grouped_indices[component_index].append(edge_index)

    # 完整 boundary-star 的跨分量效果只能在同一分量内重建。若一个边界
    # 两侧落入不同分量，缩减图无法安全判断，必须把该情况留作 UNKNOWN。
    for thread_id, thread_nodes in endpoints_by_thread.items():
        if len(thread_nodes) < 2:
            continue
        first = int(edges.sequences[thread_nodes[0]])
        last = int(edges.sequences[thread_nodes[-1]])
        for boundary in store.boundaries_between(thread_id, first, last):
            category = _boundary_category(boundary.kind)
            before = [
                node
                for node in thread_nodes
                if int(edges.sequences[node]) < boundary.sequence
                and _boundary_accepts(category, EventKind(int(edges.kinds[node])))
            ]
            after = [
                node
                for node in thread_nodes
                if int(edges.sequences[node]) > boundary.sequence
                and _boundary_accepts(category, EventKind(int(edges.kinds[node])))
            ]
            component_ids = {
                component_index
                for node in (*before, *after)
                for component_index in memberships.get(node, ())
            }
            if before and after and len(component_ids) > 1:
                unknowns.append(
                    f"boundary {boundary.event_id} crosses communication windows"
                )

    if unknowns:
        return (), tuple(dict.fromkeys(unknowns))

    windows: list[AnalysisWindow] = []
    for component_index, component_edge_indices in enumerate(grouped_indices):
        if not component_edge_indices:
            continue
        endpoint_nodes = {
            node
            for edge_index in component_edge_indices
            for node in (
                int(edges.left_nodes[edge_index]),
                int(edges.right_nodes[edge_index]),
            )
        }
        window_id = f"window-{len(windows):06d}"
        if len(endpoint_nodes) > max_events:
            unknowns.append(
                f"{window_id} contains at least {len(endpoint_nodes)} events, "
                f"limit is {max_events}"
            )
            continue
        communication_edges = tuple(
            edges.edge(edge_index) for edge_index in component_edge_indices
        )
        endpoint_ids = {
            event_id
            for edge in communication_edges
            for event_id in (edge.first_event, edge.second_event)
        }
        endpoints = store.get_events(endpoint_ids)
        ranges: dict[int, list[int]] = {}
        for event in endpoints:
            bounds = ranges.setdefault(event.thread_id, [event.sequence, event.sequence])
            bounds[0] = min(bounds[0], event.sequence)
            bounds[1] = max(bounds[1], event.sequence)
        selected = {event.event_id: event for event in endpoints}
        for thread_id, (thread_first, thread_last) in sorted(ranges.items()):
            thread_endpoints = sorted(
                (event for event in endpoints if event.thread_id == thread_id),
                key=lambda event: event.sequence,
            )
            boundaries = store.boundaries_between(thread_id, thread_first, thread_last)
            for event in _minimal_boundaries(thread_endpoints, boundaries):
                selected[event.event_id] = event
        events = tuple(
            sorted(selected.values(), key=lambda event: (event.thread_id, event.sequence))
        )
        if len(events) > max_events:
            unknowns.append(f"{window_id} contains {len(events)} events, limit is {max_events}")
            continue
        windows.append(AnalysisWindow(window_id, events, communication_edges))
    return tuple(windows), tuple(dict.fromkeys(unknowns))


def _edge_endpoint_facts(
    edges: tuple[CommunicationEdge, ...],
) -> dict[str, CommunicationEndpoint] | None:
    """复用扫描器读到的线程内位置；冲突或缺失时回退到数据库事实。"""

    facts: dict[str, CommunicationEndpoint] = {}
    for edge in edges:
        for event_id, endpoint in (
            (edge.first_event, edge.first_endpoint),
            (edge.second_event, edge.second_endpoint),
        ):
            if endpoint is None or endpoint.event_id != event_id:
                return None
            previous = facts.setdefault(event_id, endpoint)
            if previous != endpoint:
                return None
    return facts


def _group_edges_by_component(
    components: tuple[frozenset[str], ...],
    edges: tuple[CommunicationEdge, ...],
) -> tuple[tuple[tuple[CommunicationEdge, ...], ...], int]:
    """把通信边分到包含两端的分量，返回未分配边数。"""

    memberships: dict[str, set[int]] = defaultdict(set)
    for component_index, component in enumerate(components):
        for event_id in component:
            memberships[event_id].add(component_index)

    grouped: list[list[CommunicationEdge]] = [[] for _ in components]
    unassigned = 0
    for edge in edges:
        left = memberships.get(edge.first_event, set())
        right = memberships.get(edge.second_event, set())
        if len(left) > len(right):
            left, right = right, left
        matches = [
            component_index
            for component_index in left
            if component_index in right
        ]
        if not matches:
            unassigned += 1
            continue
        # 只有割点能属于多个分量；相邻端点必须共同属于同一个分量。
        # 若图分解结果有重叠，保留旧行为，把边放进每个共同分量。
        for component_index in matches:
            grouped[component_index].append(edge)
    return tuple(tuple(group) for group in grouped if group), unassigned


def _group_edge_nodes_by_component(
    components: tuple[frozenset[int], ...],
    edges: list[tuple[int, int, CommunicationEdge]],
) -> tuple[tuple[tuple[CommunicationEdge, ...], ...], int]:
    """按整数节点分量分配边，避免再次建立 event_id 字符串索引。"""

    memberships: dict[int, set[int]] = defaultdict(set)
    for component_index, component in enumerate(components):
        for node_id in component:
            memberships[node_id].add(component_index)

    grouped: list[list[CommunicationEdge]] = [[] for _ in components]
    unassigned = 0
    for left_node, right_node, edge in edges:
        left = memberships.get(left_node, set())
        right = memberships.get(right_node, set())
        if len(left) > len(right):
            left, right = right, left
        matches = [
            component_index
            for component_index in left
            if component_index in right
        ]
        if not matches:
            unassigned += 1
            continue
        for component_index in matches:
            grouped[component_index].append(edge)
    return tuple(tuple(group) for group in grouped if group), unassigned


def _minimal_boundaries(
    endpoints: list[TraceEvent], boundaries: tuple[TraceEvent, ...]
) -> tuple[TraceEvent, ...]:
    sequences = [event.sequence for event in endpoints]
    endpoint_ids = {event.event_id for event in endpoints}
    selected: dict[tuple[int, str], TraceEvent] = {}
    for boundary in boundaries:
        if boundary.event_id in endpoint_ids:
            continue
        cut = bisect_left(sequences, boundary.sequence)
        if cut == 0 or cut == len(endpoints):
            continue
        category = _boundary_category(boundary.kind)
        key = (cut, category)
        selected.setdefault(key, boundary)
    full_cuts = {cut for cut, category in selected if category == "full"}
    return tuple(
        event
        for (cut, category), event in selected.items()
        if category == "full" or cut not in full_cuts
    )


def _boundary_category(kind: EventKind) -> str:
    # Atomic 和 MFENCE 对保留端点都建立完整顺序，因此同一切点可共用一个代表。
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


def _biconnected_components(graph: dict[str, set[str]]) -> tuple[frozenset[str], ...]:
    discovery: dict[str, int] = {}
    low: dict[str, int] = {}
    edge_stack: list[tuple[str, str]] = []
    components: list[frozenset[str]] = []
    parent: dict[str, str | None] = {}
    clock = 0
    for node in sorted(graph):
        if node in discovery:
            continue
        clock += 1
        discovery[node] = low[node] = clock
        parent[node] = None
        traversal: list[tuple[str, Iterator[str]]] = [
            (node, iter(sorted(graph[node])))
        ]
        while traversal:
            current, neighbors = traversal[-1]
            try:
                neighbor = next(neighbors)
            except StopIteration:
                traversal.pop()
                ancestor = parent[current]
                if ancestor is None:
                    continue
                low[ancestor] = min(low[ancestor], low[current])
                if low[current] >= discovery[ancestor]:
                    vertices: set[str] = set()
                    while edge_stack:
                        edge = edge_stack.pop()
                        vertices.update(edge)
                        if edge == (ancestor, current):
                            break
                    components.append(frozenset(vertices))
                continue
            if neighbor == parent[current]:
                continue
            if neighbor not in discovery:
                edge_stack.append((current, neighbor))
                parent[neighbor] = current
                clock += 1
                discovery[neighbor] = low[neighbor] = clock
                traversal.append((neighbor, iter(sorted(graph[neighbor]))))
            elif discovery[neighbor] < discovery[current]:
                edge_stack.append((current, neighbor))
                low[current] = min(low[current], discovery[neighbor])
    return tuple(components)
