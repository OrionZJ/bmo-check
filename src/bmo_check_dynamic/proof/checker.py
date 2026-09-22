from __future__ import annotations

from dataclasses import dataclass
from itertools import islice, permutations, product
from time import monotonic

import z3

from bmo_check_dynamic.analysis import AnalysisWindow
from bmo_check_dynamic.model import (
    CandidateWitness,
    EventFlags,
    EventKind,
    ReadFromWitness,
    SymbolicEncodingStats,
    TraceEvent,
    WindowResult,
)

from .relations import Edge, find_cycle, source_preserved_order, target_preserved_order


@dataclass(frozen=True, slots=True)
class _ReadPart:
    event: TraceEvent
    address: int
    size: int

    @property
    def end_address(self) -> int:
        return self.address + self.size


def check_window(
    window: AnalysisWindow,
    *,
    max_executions: int,
    control_flow_closed: bool,
    timeout_ms: int = 10_000,
    max_symbolic_terms: int = 100_000,
) -> WindowResult:
    deadline = monotonic() + timeout_ms / 1000
    memory = tuple(event for event in window.events if event.kind.is_memory)
    writes = tuple(event for event in memory if event.kind.is_write)
    mixed_write_overlap = False
    for index, left in enumerate(writes):
        for right in writes[index + 1 :]:
            if left.overlaps(right) and _location(left) != _location(right):
                mixed_write_overlap = True
                # 混合宽度写必须交给同一个 overlap-component 符号模型。
                # 该模型仍会对无法证明的原子读值返回 UNKNOWN；这里不能
                # 因为其中一个写是 RMW 就提前丢弃可分析的完整覆盖关系。

    reads = tuple(event for event in memory if event.kind.is_read)
    partial_reads = False
    for read in reads:
        if any(write.overlaps(read) and not _covers(write, read) for write in writes):
            partial_reads = True
            if read.kind == EventKind.ATOMIC_RMW:
                return WindowResult(
                    window_id=window.window_id,
                    event_ids=tuple(event.event_id for event in window.events),
                    status="unknown",
                    reason="mixed-width atomic read-from is not supported",
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
    if (mixed_write_overlap or partial_reads or len(memory) > 12 or
            any(len(group) > 6 for group in writes_by_location.values())):
        return _check_symbolic(
            window, reads, writes, writes_by_location, source_ppo, target_ppo,
            control_flow_closed=control_flow_closed, timeout_ms=timeout_ms,
            max_symbolic_terms=max_symbolic_terms,
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
            max_symbolic_terms=max_symbolic_terms,
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
                    max_symbolic_terms=max_symbolic_terms,
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
                    ReadFromWitness(
                        read_event=read.event_id,
                        write_event=write.event_id if write is not None else None,
                        address=read.address,
                        size=read.size,
                    )
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


def characterize_symbolic_encoding(
    window: AnalysisWindow,
    *,
    source_ppo: set[Edge] | None = None,
    target_ppo: set[Edge] | None = None,
) -> SymbolicEncodingStats:
    """统计 symbolic encoder 规模，不启动 solver 或生成 AST。

    P8 的 shadow 路径可以传入经过证书验证的 PPO 图；正式 checker 不传这
    两个参数，因此其原有输入和 verdict 路径保持不变。
    """

    memory = tuple(event for event in window.events if event.kind.is_memory)
    reads = tuple(event for event in memory if event.kind.is_read)
    writes = tuple(event for event in memory if event.kind.is_write)
    source_ppo = (
        source_preserved_order(window.events)
        if source_ppo is None
        else source_ppo
    )
    target_ppo = (
        target_preserved_order(window.events)
        if target_ppo is None
        else target_ppo
    )
    nodes = tuple(sorted(event.event_id for event in window.events))
    coherence_groups = _overlap_components(writes)
    coherence_pair_count = sum(
        1
        for group in coherence_groups
        for left in group
        for right in group
        if left is not right and left.overlaps(right)
    )
    conditional_edges: set[Edge] = set()
    conditional_edge_additions = 0
    conditional_term_weight = 0
    rf_part_count = 0
    rf_candidate_count = 0
    cross_thread_rf_edge_count = 0
    from_read_candidate_count = 0
    for read in reads:
        for part in _read_parts(read, writes):
            rf_part_count += 1
            candidates = tuple(
                write
                for write in writes
                if write.address <= part.address
                and write.end_address >= part.end_address
                and not (
                    write.thread_id == read.thread_id and write.sequence >= read.sequence
                )
            )
            rf_candidate_count += len(candidates)
            cross_thread_rf_edge_count += sum(
                write.thread_id != read.thread_id for write in candidates
            )
            for later in writes:
                if (
                    later.address >= part.end_address
                    or later.end_address <= part.address
                    or later.event_id == read.event_id
                ):
                    continue
                condition_count = 1
                for source in candidates:
                    if not source.overlaps(later) or source is later:
                        continue
                    condition_count += 1
                from_read_candidate_count += 1
                conditional_edge_additions += 1
                conditional_edges.add((read.event_id, later.event_id))
                conditional_term_weight += 3 + condition_count

    for group in coherence_groups:
        for left in group:
            for right in group:
                if left is right or not left.overlaps(right):
                    continue
                conditional_edge_additions += 1
                conditional_edges.add((left.event_id, right.event_id))
                conditional_term_weight += 4

    initial_formula_terms = len(nodes) * 3 + len(source_ppo) * 4 + len(target_ppo)
    return SymbolicEncodingStats(
        window_id=window.window_id,
        event_count=len(window.events),
        memory_event_count=len(memory),
        read_count=len(reads),
        write_count=len(writes),
        node_count=len(nodes),
        source_ppo_edge_count=len(source_ppo),
        target_ppo_edge_count=len(target_ppo),
        initial_formula_terms=initial_formula_terms,
        coherence_component_count=len(coherence_groups),
        coherence_write_count=sum(len(group) for group in coherence_groups),
        coherence_pair_count=coherence_pair_count,
        rf_part_count=rf_part_count,
        rf_candidate_count=rf_candidate_count,
        cross_thread_rf_edge_count=cross_thread_rf_edge_count,
        from_read_candidate_count=from_read_candidate_count,
        conditional_edge_additions=conditional_edge_additions,
        conditional_edge_count=len(conditional_edges),
        conditional_term_weight=conditional_term_weight,
        cycle_edge_count=len(source_ppo | conditional_edges),
        cycle_node_count=len(nodes),
        estimated_formula_terms=initial_formula_terms + conditional_term_weight,
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
            # 本线程 Load 可以从 store buffer 转发；只有跨线程 rf 才进入全局
            # happens-before。把 rfi 也加边会错误收紧 source 和 target。
            if write.thread_id != read.thread_id:
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
    max_symbolic_terms: int,
) -> WindowResult:
    deadline = monotonic() + timeout_ms / 1000

    def timed_out() -> WindowResult:
        return WindowResult(
            window_id=window.window_id,
            event_ids=tuple(event.event_id for event in window.events),
            status="unknown",
            reason=f"symbolic formula construction exceeded {timeout_ms} ms",
        )

    def formula_limited() -> WindowResult:
        return WindowResult(
            window_id=window.window_id,
            event_ids=tuple(event.event_id for event in window.events),
            status="unknown",
            reason=f"symbolic formula exceeds {max_symbolic_terms} terms",
        )

    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    event_by_id = {event.event_id: event for event in window.events}
    nodes = tuple(sorted(event_by_id))
    # 一个 PPO edge 后续至少出现在 rank 约束、source 条件和 cycle 选择中。
    # 用保守权重在创建 Z3 AST 前拒绝巨窗，避免“项数不多但重复引用很多”的低估。
    formula_terms = len(nodes) * 3 + len(source_ppo) * 4 + len(target_ppo)
    if formula_terms > max_symbolic_terms:
        return formula_limited()
    topological = {node: z3.Int(f"target_rank_{index}") for index, node in enumerate(nodes)}
    # 有向图无环只要求每条边的 rank 严格递增。无关节点可以共享 rank；强迫
    # 数千个节点全异会制造一个与 memory model 无关的排列问题。

    coherence_groups = _overlap_components(writes)
    co_rank: dict[str, z3.ArithRef] = {}
    for location_index, location_writes in enumerate(coherence_groups):
        if monotonic() >= deadline:
            return timed_out()
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
                if (left.overlaps(right) and left.thread_id == right.thread_id and
                        left.sequence < right.sequence):
                    solver.add(co_rank[left.event_id] < co_rank[right.event_id])

    rf_choice: dict[
        tuple[str, int], tuple[_ReadPart, z3.ArithRef, tuple[TraceEvent, ...]]
    ] = {}
    conditional_edges: dict[Edge, list[z3.BoolRef]] = {}

    def add_edge(edge: Edge, condition: z3.BoolRef, *, weight: int = 4) -> bool:
        nonlocal formula_terms
        formula_terms += weight
        if formula_terms > max_symbolic_terms:
            return False
        conditional_edges.setdefault(edge, []).append(condition)
        return True

    for location_writes in coherence_groups:
        if monotonic() >= deadline:
            return timed_out()
        for left in location_writes:
            for right in location_writes:
                if left is not right and left.overlaps(right):
                    if not add_edge(
                        (left.event_id, right.event_id),
                        co_rank[left.event_id] < co_rank[right.event_id],
                    ):
                        return formula_limited()

    choice_index = 0
    for read in reads:
        if monotonic() >= deadline:
            return timed_out()
        for part_index, part in enumerate(_read_parts(read, writes)):
            candidates = tuple(
                write
                for write in writes
                if write.address <= part.address
                and write.end_address >= part.end_address
                and not (
                    write.thread_id == read.thread_id and write.sequence >= read.sequence
                )
            )
            choice = z3.Int(f"rf_{choice_index}")
            choice_index += 1
            solver.add(choice >= -1, choice < len(candidates))
            rf_choice[(read.event_id, part_index)] = (part, choice, candidates)
            if read.kind == EventKind.ATOMIC_RMW:
                solver.add(z3.Implies(choice == -1, co_rank[read.event_id] == 0))
                for index, write in enumerate(candidates):
                    solver.add(z3.Implies(
                        choice == index,
                        co_rank[read.event_id] == co_rank[write.event_id] + 1,
                    ))
            for index, write in enumerate(candidates):
                if (write.thread_id != read.thread_id and
                        not add_edge((write.event_id, read.event_id), choice == index)):
                    return formula_limited()
            for later in writes:
                if (later.address >= part.end_address or
                        later.end_address <= part.address or
                        later.event_id == read.event_id):
                    continue
                conditions: list[z3.BoolRef] = [choice == -1]
                for index, source in enumerate(candidates):
                    if not source.overlaps(later) or source is later:
                        continue
                    conditions.append(
                        z3.And(
                            choice == index,
                            co_rank[source.event_id] < co_rank[later.event_id],
                        )
                    )
                if not add_edge(
                    (read.event_id, later.event_id),
                    z3.Or(*conditions),
                    weight=3 + len(conditions),
                ):
                    return formula_limited()

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
    incoming_by_node: dict[str, list[z3.BoolRef]] = {node: [] for node in nodes}
    outgoing_by_node: dict[str, list[z3.BoolRef]] = {node: [] for node in nodes}
    for edge, selected in selected_edges.items():
        solver.add(z3.Implies(selected, source_conditions[edge]))
        outgoing_by_node[edge[0]].append(selected)
        incoming_by_node[edge[1]].append(selected)
    for node in nodes:
        if monotonic() >= deadline:
            return timed_out()
        incoming = incoming_by_node[node]
        outgoing = outgoing_by_node[node]
        solver.add(z3.Sum(*[z3.If(item, 1, 0) for item in incoming]) == z3.If(selected_nodes[node], 1, 0))
        solver.add(z3.Sum(*[z3.If(item, 1, 0) for item in outgoing]) == z3.If(selected_nodes[node], 1, 0))

    remaining_ms = max(1, int((deadline - monotonic()) * 1000))
    solver.set(timeout=remaining_ms)
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
    sliced_rf = tuple(
        (
            part,
            candidates[model.eval(choice).as_long()]
            if model.eval(choice).as_long() >= 0
            else None,
        )
        for part, choice, candidates in rf_choice.values()
    )
    coherence_orders = tuple(
        tuple(sorted(location_writes, key=lambda event: model.eval(co_rank[event.event_id]).as_long()))
        for location_writes in coherence_groups
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
    validated = control_flow_closed and _slice_values_match(sliced_rf)
    witness = CandidateWitness(
        window_id=window.window_id,
        read_from=tuple(
            ReadFromWitness(
                read_event=part.event.event_id,
                write_event=write.event_id if write is not None else None,
                address=part.address,
                size=part.size,
            )
            for part, write in sliced_rf
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


def _overlap_components(
    writes: tuple[TraceEvent, ...],
) -> tuple[tuple[TraceEvent, ...], ...]:
    """把共享任一字节的写放进同一个 coherence rank 空间。"""

    remaining = set(range(len(writes)))
    components: list[tuple[TraceEvent, ...]] = []
    while remaining:
        seed = remaining.pop()
        component = {seed}
        pending = [seed]
        while pending:
            current = pending.pop()
            connected = {
                other
                for other in remaining
                if writes[current].overlaps(writes[other])
            }
            remaining.difference_update(connected)
            component.update(connected)
            pending.extend(connected)
        components.append(tuple(writes[index] for index in sorted(component)))
    return tuple(components)


def _read_parts(
    read: TraceEvent, writes: tuple[TraceEvent, ...]
) -> tuple[_ReadPart, ...]:
    boundaries = {read.address, read.end_address}
    for write in writes:
        if not write.overlaps(read):
            continue
        boundaries.add(max(read.address, write.address))
        boundaries.add(min(read.end_address, write.end_address))
    ordered = sorted(boundaries)
    return tuple(
        _ReadPart(read, left, right - left)
        for left, right in zip(ordered, ordered[1:])
    )


def _slice_values_match(
    rf: tuple[tuple[_ReadPart, TraceEvent | None], ...],
) -> bool:
    for part, write in rf:
        read = part.event
        if read.kind == EventKind.ATOMIC_RMW or write is None:
            return False
        if write.kind == EventKind.ATOMIC_RMW:
            return False
        if not (
            read.flags & EventFlags.VALUE_KNOWN
            and write.flags & EventFlags.VALUE_KNOWN
        ):
            return False
        if read.size > 8 or write.size > 8:
            return False
        mask = (1 << part.size * 8) - 1
        read_shift = (part.address - read.address) * 8
        write_shift = (part.address - write.address) * 8
        if (read.value >> read_shift) & mask != (write.value >> write_shift) & mask:
            return False
    return True
