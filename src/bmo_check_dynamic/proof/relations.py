from __future__ import annotations

from collections import defaultdict

from bmo_check_dynamic.model import EventKind, TraceEvent

Edge = tuple[str, str]


def source_preserved_order(events: tuple[TraceEvent, ...]) -> set[Edge]:
    """x86-TSO 只允许普通 Store→Load 越过；Fence 和原子边界另行补回。"""

    edges: set[Edge] = set()
    by_thread = _by_thread(events)
    for thread_events in by_thread.values():
        for left_index, left in enumerate(thread_events):
            for right in thread_events[left_index + 1 :]:
                if not (left.kind.is_write and right.kind.is_read):
                    edges.add((left.event_id, right.event_id))
        edges.update(_boundary_edges(thread_events))
    return edges


def target_preserved_order(events: tuple[TraceEvent, ...]) -> set[Edge]:
    """普通 RVWMO 依赖暂不用于 SAFE；少放边只会让 target 过近似更保守。"""

    edges: set[Edge] = set()
    for thread_events in _by_thread(events).values():
        edges.update(_boundary_edges(thread_events))
    return edges


def _by_thread(events: tuple[TraceEvent, ...]) -> dict[int, list[TraceEvent]]:
    result: dict[int, list[TraceEvent]] = defaultdict(list)
    for event in events:
        result[event.thread_id].append(event)
    for values in result.values():
        values.sort(key=lambda event: event.sequence)
    return result


def _boundary_edges(events: list[TraceEvent]) -> set[Edge]:
    edges: set[Edge] = set()
    for index, boundary in enumerate(events):
        before, after = events[:index], events[index + 1 :]
        if boundary.kind == EventKind.LFENCE:
            edges.update(
                (left.event_id, right.event_id)
                for left in before
                if left.kind.is_read
                for right in after
                if right.kind.is_read
            )
        elif boundary.kind == EventKind.SFENCE:
            edges.update(
                (left.event_id, right.event_id)
                for left in before
                if left.kind.is_write
                for right in after
                if right.kind.is_write
            )
        elif boundary.kind == EventKind.MFENCE:
            edges.update(
                (left.event_id, right.event_id)
                for left in before
                if left.kind.is_memory
                for right in after
                if right.kind.is_memory
            )
        elif boundary.kind == EventKind.ATOMIC_RMW:
            edges.update(
                (left.event_id, boundary.event_id)
                for left in before
                if left.kind.is_memory
            )
            edges.update(
                (boundary.event_id, right.event_id)
                for right in after
                if right.kind.is_memory
            )
    return edges


def find_cycle(edges: set[Edge]) -> tuple[str, ...]:
    graph: dict[str, list[str]] = defaultdict(list)
    nodes: set[str] = set()
    for left, right in edges:
        graph[left].append(right)
        nodes.update((left, right))
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> tuple[str, ...]:
        if node in visiting:
            start = stack.index(node)
            return tuple(stack[start:] + [node])
        if node in visited:
            return ()
        visiting.add(node)
        stack.append(node)
        for target in graph[node]:
            cycle = visit(target)
            if cycle:
                return cycle
        stack.pop()
        visiting.remove(node)
        visited.add(node)
        return ()

    for node in nodes:
        cycle = visit(node)
        if cycle:
            return cycle
    return ()
