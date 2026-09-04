from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from bmo_check_dynamic.model import TraceEvent
from bmo_check_dynamic.storage import TraceStore

from .communication import CommunicationEdge


@dataclass(frozen=True, slots=True)
class AnalysisWindow:
    window_id: str
    events: tuple[TraceEvent, ...]
    communication_edges: tuple[CommunicationEdge, ...]


def build_windows(
    store: TraceStore,
    edges: tuple[CommunicationEdge, ...],
    *,
    max_events: int,
) -> tuple[tuple[AnalysisWindow, ...], tuple[str, ...]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        graph[edge.first_event].add(edge.second_event)
        graph[edge.second_event].add(edge.first_event)
    endpoint_ids = {
        event_id
        for edge in edges
        for event_id in (edge.first_event, edge.second_event)
    }
    endpoints_by_thread: dict[int, list[TraceEvent]] = defaultdict(list)
    for event in store.get_events(endpoint_ids):
        endpoints_by_thread[event.thread_id].append(event)
    # 不同地址仍可通过同一线程的程序序组成内存序环，不能分到独立窗口。
    for thread_events in endpoints_by_thread.values():
        thread_events.sort(key=lambda event: event.sequence)
        for left, right in zip(thread_events, thread_events[1:]):
            graph[left.event_id].add(right.event_id)
            graph[right.event_id].add(left.event_id)

    # 一个关系环只能落在同一个无向双连通分量内。按普通连接分量切分会把
    # 共享割点的长链合成巨窗，既增加枚举量，也没有提供额外反例路径。
    try:
        components = _biconnected_components(graph)
    except RecursionError:
        # 深链本身可以拆分，但递归 Tarjan 超出 Python 栈后不能带着不完整分量
        # 继续证明。先显式 UNKNOWN，后续再换成迭代遍历。
        return (), ("communication graph exceeds biconnected traversal depth",)
    grouped_edges = [
        [
            edge
            for edge in edges
            if edge.first_event in component and edge.second_event in component
        ]
        for component in components
    ]
    grouped_edges = [component for component in grouped_edges if component]

    windows: list[AnalysisWindow] = []
    unknowns: list[str] = []
    for index, component_edges in enumerate(grouped_edges):
        endpoint_ids = {
            event_id
            for edge in component_edges
            for event_id in (edge.first_event, edge.second_event)
        }
        endpoints = store.get_events(endpoint_ids)
        ranges: dict[int, list[int]] = {}
        for event in endpoints:
            bounds = ranges.setdefault(event.thread_id, [event.sequence, event.sequence])
            bounds[0] = min(bounds[0], event.sequence)
            bounds[1] = max(bounds[1], event.sequence)
        selected = {event.event_id: event for event in endpoints}
        for thread_id, (first, last) in sorted(ranges.items()):
            for event in store.boundaries_between(thread_id, first, last):
                selected[event.event_id] = event
        # 没有通信边的普通访存不可能成为关系环节点。Fence/atomic 必须保留，
        # 因为它们会让两个端点在 source 和 target 中同时恢复顺序。
        events = tuple(
            sorted(selected.values(), key=lambda event: (event.thread_id, event.sequence))
        )
        window_id = f"window-{index:06d}"
        if len(events) > max_events:
            unknowns.append(
                f"{window_id} contains {len(events)} events, limit is {max_events}"
            )
            continue
        windows.append(
            AnalysisWindow(window_id, events, tuple(component_edges))
        )
    return tuple(windows), tuple(unknowns)


def _biconnected_components(graph: dict[str, set[str]]) -> tuple[frozenset[str], ...]:
    discovery: dict[str, int] = {}
    low: dict[str, int] = {}
    edge_stack: list[tuple[str, str]] = []
    components: list[frozenset[str]] = []
    clock = 0

    def visit(node: str, parent: str | None) -> None:
        nonlocal clock
        clock += 1
        discovery[node] = low[node] = clock
        for neighbor in sorted(graph[node]):
            if neighbor == parent:
                continue
            if neighbor not in discovery:
                edge_stack.append((node, neighbor))
                visit(neighbor, node)
                low[node] = min(low[node], low[neighbor])
                if low[neighbor] >= discovery[node]:
                    vertices: set[str] = set()
                    while edge_stack:
                        edge = edge_stack.pop()
                        vertices.update(edge)
                        if edge == (node, neighbor):
                            break
                    components.append(frozenset(vertices))
            elif discovery[neighbor] < discovery[node]:
                edge_stack.append((node, neighbor))
                low[node] = min(low[node], discovery[neighbor])

    for node in sorted(graph):
        if node not in discovery:
            visit(node, None)
    return tuple(components)
