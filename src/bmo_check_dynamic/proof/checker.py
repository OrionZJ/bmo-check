from __future__ import annotations

from itertools import islice, permutations, product
from time import monotonic

from bmo_check_dynamic.analysis import AnalysisWindow
from bmo_check_dynamic.model import (
    CandidateWitness,
    EventFlags,
    TraceEvent,
    WindowResult,
)

from .relations import Edge, find_cycle, source_preserved_order, target_preserved_order


def check_window(
    window: AnalysisWindow,
    *,
    max_executions: int,
    control_flow_closed: bool,
    timeout_ms: int = 10_000,
) -> WindowResult:
    deadline = monotonic() + timeout_ms / 1000
    memory = tuple(event for event in window.events if event.kind.is_memory)
    ranges = {(event.address, event.size) for event in memory}
    for edge in window.communication_edges:
        left = next(event for event in memory if event.event_id == edge.first_event)
        right = next(event for event in memory if event.event_id == edge.second_event)
        if (left.address, left.size) != (right.address, right.size):
            return WindowResult(
                window_id=window.window_id,
                event_ids=tuple(event.event_id for event in window.events),
                status="unknown",
                reason="mixed-width or partially overlapping accesses need byte-level encoding",
            )

    reads = tuple(event for event in memory if event.kind.is_read)
    writes_by_location = {
        location: tuple(
            event
            for event in memory
            if event.kind.is_write and (event.address, event.size) == location
        )
        for location in ranges
    }
    choices = tuple(
        (None,) + tuple(
            write
            for write in writes_by_location[(read.address, read.size)]
            if not (
                write.thread_id == read.thread_id and write.sequence >= read.sequence
            )
        )
        for read in reads
    )
    coherence_orders = tuple(
        tuple(_valid_coherence_orders(writes))
        for writes in writes_by_location.values()
        if len(writes) > 1
    )
    source_ppo = source_preserved_order(window.events)
    target_ppo = target_preserved_order(window.events)
    examined = 0

    rf_products = product(*choices) if choices else [()]
    co_products = product(*coherence_orders) if coherence_orders else iter(((),))
    # product 迭代器只能走一次；把通常很小的 coherence 组合保存后复用。
    co_variants = tuple(islice(co_products, max_executions + 1))
    if len(co_variants) > max_executions:
        return WindowResult(
            window_id=window.window_id,
            event_ids=tuple(event.event_id for event in window.events),
            status="unknown",
            reason=f"coherence enumeration exceeded {max_executions}",
        )
    for selected_writes in rf_products:
        rf = tuple(zip(reads, selected_writes, strict=True))
        for selected_orders in co_variants:
            if monotonic() >= deadline:
                return WindowResult(
                    window_id=window.window_id,
                    event_ids=tuple(event.event_id for event in window.events),
                    examined_executions=examined,
                    status="unknown",
                    reason=f"window checker exceeded {timeout_ms} ms",
                )
            examined += 1
            if examined > max_executions:
                return WindowResult(
                    window_id=window.window_id,
                    event_ids=tuple(event.event_id for event in window.events),
                    examined_executions=examined - 1,
                    status="unknown",
                    reason=f"execution enumeration exceeded {max_executions}",
                )
            com, coherence_pairs = _communication_relations(
                rf, selected_orders, writes_by_location
            )
            if find_cycle(target_ppo | com):
                continue
            source_cycle = find_cycle(source_ppo | com)
            if not source_cycle:
                continue
            validated = control_flow_closed and _values_match(rf)
            witness = CandidateWitness(
                window_id=window.window_id,
                read_from=tuple(
                    (read.event_id, write.event_id if write is not None else None)
                    for read, write in rf
                ),
                coherence=tuple(
                    (left.event_id, right.event_id)
                    for left, right in coherence_pairs
                ),
                source_cycle=source_cycle,
                validated=validated,
                reason=(
                    "target permits an execution rejected by x86-TSO"
                    if validated
                    else "target-only candidate needs value/control-flow validation"
                ),
            )
            return WindowResult(
                window_id=window.window_id,
                event_ids=tuple(event.event_id for event in window.events),
                examined_executions=examined,
                status="counterexample" if validated else "unknown",
                reason=witness.reason,
                witness=witness,
            )
    return WindowResult(
        window_id=window.window_id,
        event_ids=tuple(event.event_id for event in window.events),
        examined_executions=examined,
        status="safe",
        reason="no RVWMO-only execution exists in the over-approximated trace window",
    )


def _valid_coherence_orders(writes: tuple[TraceEvent, ...]):
    for order in permutations(writes):
        position = {event.event_id: index for index, event in enumerate(order)}
        if all(
            position[left.event_id] < position[right.event_id]
            for left in writes
            for right in writes
            if left.thread_id == right.thread_id and left.sequence < right.sequence
        ):
            yield order


def _communication_relations(
    rf: tuple[tuple[TraceEvent, TraceEvent | None], ...],
    selected_orders: tuple[tuple[TraceEvent, ...], ...],
    writes_by_location: dict[tuple[int, int], tuple[TraceEvent, ...]],
) -> tuple[set[Edge], tuple[tuple[TraceEvent, TraceEvent], ...]]:
    order_by_location: dict[tuple[int, int], tuple[TraceEvent, ...]] = {}
    selected = iter(selected_orders)
    for location, writes in writes_by_location.items():
        order_by_location[location] = next(selected) if len(writes) > 1 else writes

    edges: set[Edge] = set()
    coherence_pairs: list[tuple[TraceEvent, TraceEvent]] = []
    for order in order_by_location.values():
        for left, right in zip(order, order[1:]):
            edges.add((left.event_id, right.event_id))
            coherence_pairs.append((left, right))
    for read, write in rf:
        order = order_by_location[(read.address, read.size)]
        if write is not None:
            edges.add((write.event_id, read.event_id))
            index = order.index(write)
            later = order[index + 1 :]
        else:
            later = order
        edges.update((read.event_id, later_write.event_id) for later_write in later)
    return edges, tuple(coherence_pairs)


def _values_match(rf: tuple[tuple[TraceEvent, TraceEvent | None], ...]) -> bool:
    for read, write in rf:
        if write is None:
            return False
        if not (
            read.flags & EventFlags.VALUE_KNOWN
            and write.flags & EventFlags.VALUE_KNOWN
        ):
            return False
        mask = (1 << min(read.size, 8) * 8) - 1
        if read.value & mask != write.value & mask:
            return False
    return True
