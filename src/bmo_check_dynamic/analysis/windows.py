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


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def build_windows(
    store: TraceStore,
    edges: tuple[CommunicationEdge, ...],
    *,
    max_events: int,
) -> tuple[tuple[AnalysisWindow, ...], tuple[str, ...]]:
    union = _UnionFind()
    for edge in edges:
        union.union(edge.first_event, edge.second_event)
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
            union.union(left.event_id, right.event_id)
    grouped_edges: dict[str, list[CommunicationEdge]] = defaultdict(list)
    for edge in edges:
        grouped_edges[union.find(edge.first_event)].append(edge)

    windows: list[AnalysisWindow] = []
    unknowns: list[str] = []
    for index, component_edges in enumerate(grouped_edges.values()):
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
        events = tuple(
            event
            for thread_id, (first, last) in sorted(ranges.items())
            for event in store.events_between(thread_id, first, last)
            if event.kind.is_memory or event.kind.is_boundary
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
