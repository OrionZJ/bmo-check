from __future__ import annotations

from collections import defaultdict

from bmo_check_dynamic.model import EventKind, TraceEvent

Edge = tuple[str, str]


def source_preserved_order(events: tuple[TraceEvent, ...]) -> set[Edge]:
    """x86-TSO 只允许普通 Store→Load 越过；Fence 和原子边界另行补回。"""

    edges: set[Edge] = set()
    by_thread = _by_thread(events)
    for thread_events in by_thread.values():
        previous_read: TraceEvent | None = None
        previous_write: TraceEvent | None = None
        for index, event in enumerate(thread_events):
            if not event.kind.is_memory:
                continue
            # 每类只连接最近前驱即可保留同样的可达关系，避免长循环生成 O(n²)
            # 条 source PPO。Store→Load 仍故意没有边。
            if event.kind.is_read and previous_read is not None:
                edges.add((previous_read.event_id, event.event_id))
            if event.kind.is_write:
                if previous_read is not None:
                    edges.add((previous_read.event_id, event.event_id))
                if previous_write is not None:
                    edges.add((previous_write.event_id, event.event_id))
            if event.kind.is_read:
                # 同一 hart 的 Store→Load 同址访问不能退回初始值；store
                # forwarding 和 RVWMO overlapping-address order 都保留这条边。
                for previous in reversed(thread_events[:index]):
                    if previous.kind.is_write and previous.overlaps(event):
                        edges.add((previous.event_id, event.event_id))
                        break
            if event.kind.is_read:
                previous_read = event
            if event.kind.is_write:
                previous_write = event
        edges.update(_boundary_edges(thread_events))
    return edges


def target_preserved_order(events: tuple[TraceEvent, ...]) -> set[Edge]:
    """只加入无需寄存器数据流也能证明的 RVWMO 顺序。"""

    edges: set[Edge] = set()
    for thread_events in _by_thread(events).values():
        memory = [event for event in thread_events if event.kind.is_memory]
        for index, right in enumerate(memory):
            # RVWMO 的 overlapping-address order 会保留同 hart 上先前访存到
            # 后续重叠 Store 的顺序；这不是从本次调度推断出来的时序。
            if right.kind.is_write:
                edges.update(
                    (left.event_id, right.event_id)
                    for left in memory[:index]
                    if left.overlaps(right)
                )
            if right.kind.is_read:
                # RVWMO 的同址 Store→Load 不能从前序写回到初始写，
                # 否则会制造不可能的 read-from 候选。
                for left in reversed(memory[:index]):
                    if left.kind.is_write and left.overlaps(right):
                        edges.add((left.event_id, right.event_id))
                        break
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
                (left.event_id, boundary.event_id)
                for left in before
                if left.kind.is_read
            )
            edges.update(
                (boundary.event_id, right.event_id)
                for right in after
                if right.kind.is_read
            )
        elif boundary.kind == EventKind.SFENCE:
            edges.update(
                (left.event_id, boundary.event_id)
                for left in before
                if left.kind.is_write
            )
            edges.update(
                (boundary.event_id, right.event_id)
                for right in after
                if right.kind.is_write
            )
        elif boundary.kind == EventKind.MFENCE:
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
        elif boundary.kind in {EventKind.ATOMIC_RMW, EventKind.FUTEX_WAIT}:
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
