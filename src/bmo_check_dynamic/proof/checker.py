from __future__ import annotations

from itertools import islice, permutations, product
from time import monotonic

import z3

from bmo_check_dynamic.analysis import AnalysisWindow
from bmo_check_dynamic.model import (
    CandidateWitness,
    EventFlags,
    EventKind,
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
    writes = tuple(event for event in memory if event.kind.is_write)
    for index, left in enumerate(writes):
        for right in writes[index + 1 :]:
            if left.overlaps(right) and _location(left) != _location(right):
                return WindowResult(
                    window_id=window.window_id,
                    event_ids=tuple(event.event_id for event in window.events),
                    status="unknown",
                    reason="overlapping mixed-width writes need byte-level coherence",
                )

    reads = tuple(event for event in memory if event.kind.is_read)
    for read in reads:
        if any(write.overlaps(read) and not _covers(write, read) for write in writes):
            return WindowResult(
                window_id=window.window_id,
                event_ids=tuple(event.event_id for event in window.events),
                status="unknown",
                reason="a read assembled from partial writes needs byte-level read-from",
            )

    write_locations = {_location(event) for event in writes}
    writes_by_location = {
        location: tuple(
            event
            for event in writes
            if _location(event) == location
        )
        for location in write_locations
    }
    choices = tuple(
        (None,) + tuple(
            write
            for write in writes
            if _covers(write, read)
            if not (
                write.thread_id == read.thread_id and write.sequence >= read.sequence
            )
        )
        for read in reads
    )
    source_ppo = source_preserved_order(window.events)
    target_ppo = target_preserved_order(window.events)
    # 先决定是否转符号求解，避免在预算检查前就物化阶乘数量的 coherence 排列。
    if len(memory) > 12 or any(len(group) > 6 for group in writes_by_location.values()):
        return _check_symbolic(
            window, reads, writes, writes_by_location, source_ppo, target_ppo,
            control_flow_closed=control_flow_closed, timeout_ms=timeout_ms,
        )
    coherence_orders = tuple(
        tuple(_valid_coherence_orders(writes))
        for writes in writes_by_location.values()
        if len(writes) > 1
    )
    examined = 0

    rf_products = product(*choices) if choices else [()]
    co_products = product(*coherence_orders) if coherence_orders else iter(((),))
    # product 迭代器只能走一次；把通常很小的 coherence 组合保存后复用。
    co_variants = tuple(islice(co_products, max_executions + 1))
    if len(co_variants) > max_executions:
        return _check_symbolic(
            window,
            reads,
            writes,
            writes_by_location,
            source_ppo,
            target_ppo,
            control_flow_closed=control_flow_closed,
            timeout_ms=timeout_ms,
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
                return _check_symbolic(
                    window,
                    reads,
                    writes,
                    writes_by_location,
                    source_ppo,
                    target_ppo,
                    control_flow_closed=control_flow_closed,
                    timeout_ms=timeout_ms,
                )
            com, coherence_pairs = _communication_relations(
                rf, selected_orders, writes_by_location, writes
            )
            if not _atomic_read_from_valid(rf, coherence_pairs):
                continue
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
    writes: tuple[TraceEvent, ...],
) -> tuple[set[Edge], tuple[tuple[TraceEvent, TraceEvent], ...]]:
    order_by_location: dict[tuple[int, int], tuple[TraceEvent, ...]] = {}
    selected = iter(selected_orders)
    for location, location_writes in writes_by_location.items():
        order_by_location[location] = (
            next(selected) if len(location_writes) > 1 else location_writes
        )

    edges: set[Edge] = set()
    coherence_pairs: list[tuple[TraceEvent, TraceEvent]] = []
    for order in order_by_location.values():
        for left, right in zip(order, order[1:]):
            edges.add((left.event_id, right.event_id))
            coherence_pairs.append((left, right))
    for read, write in rf:
        if write is not None:
            edges.add((write.event_id, read.event_id))
            order = order_by_location[_location(write)]
            index = order.index(write)
            later = tuple(
                later_write
                for later_write in order[index + 1 :]
                if later_write.overlaps(read)
            )
        else:
            later = tuple(later_write for later_write in writes if later_write.overlaps(read))
        # RMW 的读写共用一个事件节点；内部读先于内部写不是图上的自环。
        edges.update((read.event_id, later_write.event_id) for later_write in later
                     if later_write.event_id != read.event_id)
    return edges, tuple(coherence_pairs)


def _atomic_read_from_valid(
    rf: tuple[tuple[TraceEvent, TraceEvent | None], ...],
    coherence_pairs: tuple[tuple[TraceEvent, TraceEvent], ...],
) -> bool:
    predecessor = {right.event_id: left.event_id for left, right in coherence_pairs}
    for read, write in rf:
        if read.kind == EventKind.ATOMIC_RMW:
            # 其他写不能插在原子读与原子写之间，读源必须是 coherence 的紧邻前驱。
            expected = write.event_id if write is not None else None
            if predecessor.get(read.event_id) != expected:
                return False
    return True


def _values_match(rf: tuple[tuple[TraceEvent, TraceEvent | None], ...]) -> bool:
    for read, write in rf:
        # 当前记录只有一个 value，不能同时证明 RMW 的旧值和新值。
        if read.kind == EventKind.ATOMIC_RMW or (
            write is not None and write.kind == EventKind.ATOMIC_RMW
        ):
            return False
        if write is None:
            return False
        if not (
            read.flags & EventFlags.VALUE_KNOWN
            and write.flags & EventFlags.VALUE_KNOWN
        ):
            return False
        if read.size > 8 or write.size > 8:
            return False
        mask = (1 << read.size * 8) - 1
        write_shift = (read.address - write.address) * 8
        if read.value & mask != (write.value >> write_shift) & mask:
            return False
    return True


def _location(event: TraceEvent) -> tuple[int, int]:
    return event.address, event.size


def _covers(write: TraceEvent, read: TraceEvent) -> bool:
    return write.address <= read.address and write.end_address >= read.end_address


def _check_symbolic(
    window: AnalysisWindow,
    reads: tuple[TraceEvent, ...],
    writes: tuple[TraceEvent, ...],
    writes_by_location: dict[tuple[int, int], tuple[TraceEvent, ...]],
    source_ppo: set[Edge],
    target_ppo: set[Edge],
    *,
    control_flow_closed: bool,
    timeout_ms: int,
) -> WindowResult:
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    event_by_id = {event.event_id: event for event in window.events}
    nodes = tuple(sorted(event_by_id))
    topological = {node: z3.Int(f"target_rank_{index}") for index, node in enumerate(nodes)}
    solver.add(z3.Distinct(*topological.values()))
    solver.add(*(z3.And(rank >= 0, rank < len(nodes)) for rank in topological.values()))

    co_rank: dict[str, z3.ArithRef] = {}
    for location_index, location_writes in enumerate(writes_by_location.values()):
        ranks = []
        for write_index, write in enumerate(location_writes):
            rank = z3.Int(f"co_{location_index}_{write_index}")
            co_rank[write.event_id] = rank
            ranks.append(rank)
            solver.add(rank >= 0, rank < len(location_writes))
        if len(ranks) > 1:
            solver.add(z3.Distinct(*ranks))
        for left in location_writes:
            for right in location_writes:
                if left.thread_id == right.thread_id and left.sequence < right.sequence:
                    solver.add(co_rank[left.event_id] < co_rank[right.event_id])

    rf_choice: dict[str, tuple[z3.ArithRef, tuple[TraceEvent, ...]]] = {}
    conditional_edges: dict[Edge, list[z3.BoolRef]] = {}

    def add_edge(edge: Edge, condition: z3.BoolRef) -> None:
        conditional_edges.setdefault(edge, []).append(condition)

    for location_writes in writes_by_location.values():
        for left in location_writes:
            for right in location_writes:
                if left is not right:
                    add_edge(
                        (left.event_id, right.event_id),
                        co_rank[left.event_id] < co_rank[right.event_id],
                    )

    for read_index, read in enumerate(reads):
        candidates = tuple(
            write
            for write in writes
            if _covers(write, read)
            and not (
                write.thread_id == read.thread_id and write.sequence >= read.sequence
            )
        )
        choice = z3.Int(f"rf_{read_index}")
        solver.add(choice >= -1, choice < len(candidates))
        rf_choice[read.event_id] = (choice, candidates)
        if read.kind == EventKind.ATOMIC_RMW:
            solver.add(z3.Implies(choice == -1, co_rank[read.event_id] == 0))
            for index, write in enumerate(candidates):
                solver.add(z3.Implies(
                    choice == index,
                    co_rank[read.event_id] == co_rank[write.event_id] + 1,
                ))
        for index, write in enumerate(candidates):
            add_edge((write.event_id, read.event_id), choice == index)
        for later in writes:
            if not later.overlaps(read) or later.event_id == read.event_id:
                continue
            conditions: list[z3.BoolRef] = [choice == -1]
            for index, source in enumerate(candidates):
                if _location(source) != _location(later) or source is later:
                    continue
                conditions.append(
                    z3.And(
                        choice == index,
                        co_rank[source.event_id] < co_rank[later.event_id],
                    )
                )
            add_edge((read.event_id, later.event_id), z3.Or(*conditions))

    for left, right in target_ppo:
        solver.add(topological[left] < topological[right])
    for (left, right), conditions in conditional_edges.items():
        solver.add(z3.Implies(z3.Or(*conditions), topological[left] < topological[right]))

    source_conditions: dict[Edge, z3.BoolRef] = {
        edge: z3.BoolVal(True) for edge in source_ppo
    }
    for edge, conditions in conditional_edges.items():
        condition = z3.Or(*conditions)
        source_conditions[edge] = (
            z3.Or(source_conditions[edge], condition)
            if edge in source_conditions
            else condition
        )
    selected_nodes = {node: z3.Bool(f"cycle_node_{index}") for index, node in enumerate(nodes)}
    selected_edges = {
        edge: z3.Bool(f"cycle_edge_{index}")
        for index, edge in enumerate(sorted(source_conditions))
    }
    solver.add(z3.Or(*selected_nodes.values()))
    for edge, selected in selected_edges.items():
        solver.add(z3.Implies(selected, source_conditions[edge]))
    for node in nodes:
        incoming = [
            selected for (left, right), selected in selected_edges.items() if right == node
        ]
        outgoing = [
            selected for (left, right), selected in selected_edges.items() if left == node
        ]
        solver.add(z3.Sum(*[z3.If(item, 1, 0) for item in incoming]) == z3.If(selected_nodes[node], 1, 0))
        solver.add(z3.Sum(*[z3.If(item, 1, 0) for item in outgoing]) == z3.If(selected_nodes[node], 1, 0))

    status = solver.check()
    if status == z3.unknown:
        return WindowResult(
            window_id=window.window_id,
            event_ids=nodes,
            status="unknown",
            reason=f"symbolic checker returned unknown: {solver.reason_unknown()}",
        )
    if status == z3.unsat:
        return WindowResult(
            window_id=window.window_id,
            event_ids=nodes,
            examined_executions=1,
            status="safe",
            reason="symbolic target/source inclusion query is unsatisfiable",
        )

    model = solver.model()
    rf = tuple(
        (
            event_by_id[read_id],
            candidates[model.eval(choice).as_long()]
            if model.eval(choice).as_long() >= 0
            else None,
        )
        for read_id, (choice, candidates) in rf_choice.items()
    )
    coherence_orders = tuple(
        tuple(sorted(location_writes, key=lambda event: model.eval(co_rank[event.event_id]).as_long()))
        for location_writes in writes_by_location.values()
    )
    selected_source_edges = {
        edge for edge, selected in selected_edges.items() if z3.is_true(model.eval(selected))
    }
    source_cycle = find_cycle(selected_source_edges)
    coherence_pairs = tuple(
        (left, right)
        for order in coherence_orders
        for left, right in zip(order, order[1:])
    )
    validated = control_flow_closed and _values_match(rf)
    witness = CandidateWitness(
        window_id=window.window_id,
        read_from=tuple(
            (read.event_id, write.event_id if write is not None else None)
            for read, write in rf
        ),
        coherence=tuple(
            (left.event_id, right.event_id) for left, right in coherence_pairs
        ),
        source_cycle=source_cycle,
        validated=validated,
        reason=(
            "target permits an execution rejected by x86-TSO"
            if validated
            else "symbolic target-only candidate needs value/control-flow validation"
        ),
    )
    return WindowResult(
        window_id=window.window_id,
        event_ids=nodes,
        examined_executions=1,
        status="counterexample" if validated else "unknown",
        reason=witness.reason,
        witness=witness,
    )
