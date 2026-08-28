from __future__ import annotations

from dataclasses import dataclass
from time import monotonic

import networkx as nx
import z3

from bmo_check.model import (
    AddressKind,
    CheckerConclusion,
    CheckerLimits,
    CheckerReport,
    CoherenceChoice,
    CounterexampleEvent,
    CounterexampleTrace,
    EventKind,
    MemoryEvent,
    Ordering,
    ReadFromChoice,
    SharedMemorySlice,
)


BACKEND_NAME = "bmo-check-z3-axiomatic"
BACKEND_VERSION = "1"


@dataclass(frozen=True)
class _RelationAssignment:
    # read_from 保存 load ID 到 store ID；None 表示该对象的初始写。
    read_from: dict[str, str | None]
    # coherence 保存每个对象上已经定向的 store 对。
    coherence: tuple[tuple[str, str, str], ...]
    # booleans 用于阻塞已经检查过的同一组 rf/co 选择。
    booleans: tuple[tuple[z3.BoolRef, bool], ...]


@dataclass(frozen=True)
class _Encoding:
    # solver 包含某个 memory model 对有限执行的全部约束。
    solver: z3.Solver
    # relation_variables 只含 rf/co；rank 是可替换的拓扑见证。
    relation_variables: tuple[z3.BoolRef, ...]
    # rf_variables 让 model 可以还原每个 load 读自哪里。
    rf_variables: dict[str, tuple[tuple[str | None, z3.BoolRef], ...]]
    # co_variables 用规范化 pair 保存 store coherence 方向。
    co_variables: dict[tuple[str, str, str], z3.BoolRef]
    # fixed_edges 用来解释 source 比 target 多出的 preserved order。
    fixed_edges: tuple[tuple[str, str, str], ...]


def _is_read(event: MemoryEvent) -> bool:
    return event.kind in {EventKind.LOAD, EventKind.ATOMIC_RMW}


def _is_write(event: MemoryEvent) -> bool:
    return event.kind in {EventKind.STORE, EventKind.ATOMIC_RMW}


def _is_memory(event: MemoryEvent) -> bool:
    return _is_read(event) or _is_write(event)


def _object_id(event: MemoryEvent) -> str:
    address = event.address
    assert address is not None
    return (
        f"{event.module_sha256}:{address.kind.value}:"
        f"{address.base}:{address.offset}:{event.size}"
    )


def _validate_supported_slice(
    shared_slice: SharedMemorySlice, limits: CheckerLimits
) -> tuple[str, ...]:
    unsupported: list[str] = []
    events = shared_slice.events
    roles = {event.thread_role for event in events if event.thread_role is not None}
    if len(events) > limits.max_events:
        unsupported.extend(event.id for event in events[limits.max_events :])
    if len(roles) > limits.max_threads:
        allowed_roles = set(sorted(roles)[: limits.max_threads])
        unsupported.extend(
            event.id for event in events if event.thread_role not in allowed_roles
        )

    allowed_non_memory = {
        EventKind.FENCE,
        EventKind.THREAD_CREATE,
        EventKind.THREAD_JOIN,
        EventKind.ACQUIRE,
        EventKind.RELEASE,
        EventKind.BARRIER,
    }
    intervals: dict[tuple[str, str], list[tuple[int, int, str]]] = {}
    for event in events:
        if event.thread_role is None:
            unsupported.append(event.id)
            continue
        if not _is_memory(event):
            if event.kind not in allowed_non_memory:
                unsupported.append(event.id)
            continue
        address = event.address
        if (
            address is None
            or address.kind != AddressKind.GLOBAL
            or address.base is None
            or address.offset is None
            or event.size not in {1, 2, 4, 8}
            or address.offset % event.size != 0
        ):
            unsupported.append(event.id)
            continue
        key = (event.module_sha256, address.base)
        intervals.setdefault(key, []).append(
            (address.offset, address.offset + event.size, event.id)
        )

    # 首版只接受完全相同或完全分离的访问区间，避免 mixed-size 被错分对象。
    for accesses in intervals.values():
        for index, first in enumerate(accesses):
            for second in accesses[index + 1 :]:
                overlap = max(first[0], second[0]) < min(first[1], second[1])
                identical = first[:2] == second[:2]
                if overlap and not identical:
                    unsupported.extend((first[2], second[2]))

    event_ids = {event.id for event in events}
    graph = nx.DiGraph()
    graph.add_nodes_from(event_ids)
    for edge in shared_slice.program_order:
        if edge.source_event in event_ids and edge.target_event in event_ids:
            graph.add_edge(edge.source_event, edge.target_event)
        else:
            # 悬空边说明 slice 与事件集合不是同一份产物，不能静默忽略。
            unsupported.extend((edge.source_event, edge.target_event))
    for edge in shared_slice.synchronization:
        if (
            not edge.complete
            or edge.source_event not in event_ids
            or edge.target_event not in event_ids
        ):
            unsupported.extend((edge.source_event, edge.target_event))
    if not nx.is_directed_acyclic_graph(graph):
        unsupported.extend(event_ids)
    else:
        closure = nx.transitive_closure(graph)
        for role in roles:
            role_events = [event.id for event in events if event.thread_role == role]
            # 不完整的每线程顺序会让 target 出现伪执行，因此不能用于反例。
            for index, first in enumerate(role_events):
                for second in role_events[index + 1 :]:
                    if not closure.has_edge(first, second) and not closure.has_edge(second, first):
                        unsupported.extend((first, second))
    return tuple(dict.fromkeys(unsupported))


def _program_order_closure(
    shared_slice: SharedMemorySlice,
) -> tuple[tuple[str, str], ...]:
    graph = nx.DiGraph()
    graph.add_nodes_from(event.id for event in shared_slice.events)
    graph.add_edges_from(
        (edge.source_event, edge.target_event)
        for edge in shared_slice.program_order
    )
    closure = nx.transitive_closure_dag(graph)
    return tuple(closure.edges())


def _ordering_edges(
    shared_slice: SharedMemorySlice, model: str
) -> tuple[tuple[str, str, str], ...]:
    events = {event.id: event for event in shared_slice.events}
    po = _program_order_closure(shared_slice)
    edges: set[tuple[str, str, str]] = set()

    for before_id, after_id in po:
        before = events[before_id]
        after = events[after_id]
        if model == "x86-tso":
            pure_store = _is_write(before) and not _is_read(before)
            pure_load = _is_read(after) and not _is_write(after)
            if not (pure_store and pure_load):
                edges.add((before_id, after_id, "x86 preserved program order"))
        elif _is_memory(before) and _is_memory(after):
            if _object_id(before) == _object_id(after):
                edges.add((before_id, after_id, "RVWMO same-address order"))
            elif (
                _is_read(before)
                and _is_write(after)
                and not bool(after.provenance.get("dependencies_complete"))
            ):
                # RISC-V 会保留 load 到后续 store 的 data/address/control 依赖。
                # 依赖恢复未闭合时先保留这条边，防止 checker 制造伪反例。
                edges.add((before_id, after_id, "conservative unresolved dependency"))

    for event in shared_slice.events:
        dependencies = event.provenance.get("dependencies", ())
        if model == "rvwmo" and isinstance(dependencies, (list, tuple)):
            for source in dependencies:
                if isinstance(source, str) and source in events:
                    edges.add((source, event.id, "RVWMO dependency"))

        ordering = event.source_ordering if model == "x86-tso" else event.target_ordering
        if event.kind == EventKind.ATOMIC_RMW:
            ordering = Ordering.FULL if model == "x86-tso" else ordering
        if event.kind == EventKind.BARRIER:
            ordering = Ordering.FULL
        if event.kind == EventKind.ACQUIRE and ordering == Ordering.UNKNOWN:
            ordering = Ordering.ACQUIRE
        if event.kind == EventKind.RELEASE and ordering == Ordering.UNKNOWN:
            ordering = Ordering.RELEASE

        predecessors = [events[source] for source, target in po if target == event.id]
        successors = [events[target] for source, target in po if source == event.id]
        for predecessor in predecessors:
            if _orders_before(ordering, predecessor):
                edges.add((predecessor.id, event.id, f"{model} {ordering.value}"))
        for successor in successors:
            if _orders_after(ordering, successor):
                edges.add((event.id, successor.id, f"{model} {ordering.value}"))

    for edge in shared_slice.synchronization:
        if edge.complete and edge.source_event in events and edge.target_event in events:
            edges.add((edge.source_event, edge.target_event, f"synchronization: {edge.kind}"))
    return tuple(sorted(edges))


def _orders_before(ordering: Ordering, predecessor: MemoryEvent) -> bool:
    if ordering in {Ordering.RELEASE, Ordering.ACQ_REL, Ordering.FULL}:
        return _is_memory(predecessor)
    if ordering in {Ordering.FENCE_RR, Ordering.FENCE_RW}:
        return _is_read(predecessor)
    if ordering in {Ordering.FENCE_WW, Ordering.FENCE_WR}:
        return _is_write(predecessor)
    return False


def _orders_after(ordering: Ordering, successor: MemoryEvent) -> bool:
    if ordering in {Ordering.ACQUIRE, Ordering.ACQ_REL, Ordering.FULL}:
        return _is_memory(successor)
    if ordering in {Ordering.FENCE_RR, Ordering.FENCE_WR}:
        return _is_read(successor)
    if ordering in {Ordering.FENCE_RW, Ordering.FENCE_WW}:
        return _is_write(successor)
    return False


def _build_encoding(
    shared_slice: SharedMemorySlice,
    model_name: str,
    timeout_ms: int,
    fixed: _RelationAssignment | None = None,
) -> _Encoding:
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    events = {event.id: event for event in shared_slice.events}
    memory_events = [event for event in shared_slice.events if _is_memory(event)]
    ranks = {
        event.id: z3.Int(f"{model_name}_rank_{index}")
        for index, event in enumerate(shared_slice.events)
    }
    if ranks:
        solver.add(z3.Distinct(*ranks.values()))
        for rank in ranks.values():
            solver.add(rank >= 0, rank < len(ranks))

    fixed_edges = _ordering_edges(shared_slice, model_name)
    for source, target, _reason in fixed_edges:
        solver.add(ranks[source] < ranks[target])

    by_object: dict[str, list[MemoryEvent]] = {}
    for event in memory_events:
        by_object.setdefault(_object_id(event), []).append(event)

    relation_variables: list[z3.BoolRef] = []
    co_variables: dict[tuple[str, str, str], z3.BoolRef] = {}
    for object_id, object_events in by_object.items():
        stores = [event for event in object_events if _is_write(event)]
        for index, first in enumerate(stores):
            for second in stores[index + 1 :]:
                variable = z3.Bool(f"{model_name}_co_{first.id}_{second.id}")
                co_variables[(object_id, first.id, second.id)] = variable
                relation_variables.append(variable)
                solver.add(z3.Implies(variable, ranks[first.id] < ranks[second.id]))
                solver.add(z3.Implies(z3.Not(variable), ranks[second.id] < ranks[first.id]))

    rf_variables: dict[str, tuple[tuple[str | None, z3.BoolRef], ...]] = {}
    for load in (event for event in memory_events if _is_read(event)):
        object_id = _object_id(load)
        stores = [
            event
            for event in by_object[object_id]
            if _is_write(event) and event.id != load.id
        ]
        choices: list[tuple[str | None, z3.BoolRef]] = []
        for source in [None, *(store.id for store in stores)]:
            suffix = "initial" if source is None else source
            variable = z3.Bool(f"{model_name}_rf_{load.id}_{suffix}")
            choices.append((source, variable))
            relation_variables.append(variable)
        solver.add(z3.PbEq([(variable, 1) for _source, variable in choices], 1))
        rf_variables[load.id] = tuple(choices)

        for source, variable in choices:
            if source is not None:
                solver.add(z3.Implies(variable, ranks[source] < ranks[load.id]))
            for store in stores:
                if source is None:
                    later = z3.BoolVal(True)
                elif store.id == source:
                    continue
                else:
                    later = _co_before(co_variables, object_id, source, store.id)
                solver.add(
                    z3.Implies(z3.And(variable, later), ranks[load.id] < ranks[store.id])
                )

        if load.kind == EventKind.ATOMIC_RMW:
            # RMW 必须紧跟其读到的写；否则会把 LR/SC 错拆成普通 load/store。
            for source, variable in choices:
                for store in stores:
                    if source is None:
                        solver.add(z3.Implies(variable, ranks[load.id] < ranks[store.id]))
                    elif store.id != source:
                        between = z3.And(
                            _co_before(co_variables, object_id, source, store.id),
                            _co_before(co_variables, object_id, store.id, load.id),
                        )
                        solver.add(z3.Implies(variable, z3.Not(between)))

    if fixed is not None:
        for load_id, source_id in fixed.read_from.items():
            for candidate, variable in rf_variables[load_id]:
                solver.add(variable == (candidate == source_id))
        fixed_co = {(obj, before, after) for obj, before, after in fixed.coherence}
        for (object_id, first, second), variable in co_variables.items():
            solver.add(variable == ((object_id, first, second) in fixed_co))

    return _Encoding(
        solver=solver,
        relation_variables=tuple(relation_variables),
        rf_variables=rf_variables,
        co_variables=co_variables,
        fixed_edges=fixed_edges,
    )


def _co_before(
    variables: dict[tuple[str, str, str], z3.BoolRef],
    object_id: str,
    first: str,
    second: str,
) -> z3.BoolRef:
    if first == second:
        return z3.BoolVal(False)
    direct = variables.get((object_id, first, second))
    if direct is not None:
        return direct
    reverse = variables[(object_id, second, first)]
    return z3.Not(reverse)


def _assignment(encoding: _Encoding, model: z3.ModelRef) -> _RelationAssignment:
    read_from: dict[str, str | None] = {}
    booleans: list[tuple[z3.BoolRef, bool]] = []
    for load_id, choices in encoding.rf_variables.items():
        for source, variable in choices:
            value = z3.is_true(model.eval(variable, model_completion=True))
            booleans.append((variable, value))
            if value:
                read_from[load_id] = source
    coherence: list[tuple[str, str, str]] = []
    for key, variable in encoding.co_variables.items():
        value = z3.is_true(model.eval(variable, model_completion=True))
        booleans.append((variable, value))
        object_id, first, second = key
        coherence.append(
            (object_id, first, second) if value else (object_id, second, first)
        )
    return _RelationAssignment(
        read_from=read_from,
        coherence=tuple(sorted(coherence)),
        booleans=tuple(booleans),
    )


def _source_cycle(
    shared_slice: SharedMemorySlice,
    assignment: _RelationAssignment,
    fixed_edges: tuple[tuple[str, str, str], ...],
) -> tuple[str, ...]:
    graph = nx.DiGraph()
    graph.add_nodes_from(event.id for event in shared_slice.events)
    graph.add_edges_from((source, target) for source, target, _reason in fixed_edges)
    for load, store in assignment.read_from.items():
        if store is not None:
            graph.add_edge(store, load)
    for _object_id_value, before, after in assignment.coherence:
        graph.add_edge(before, after)
    by_id = {event.id: event for event in shared_slice.events}
    stores_by_object: dict[str, list[str]] = {}
    for event in shared_slice.events:
        if _is_write(event):
            stores_by_object.setdefault(_object_id(event), []).append(event.id)
    for load, source in assignment.read_from.items():
        object_id = _object_id(by_id[load])
        if source is None:
            # 初始写在所有显式 store 前，因此 load 读初值会产生到每个 store 的 fr 边。
            for store in stores_by_object.get(object_id, ()):
                if store != load:
                    graph.add_edge(load, store)
            continue
        for co_object, before, after in assignment.coherence:
            if co_object != object_id:
                continue
            if before == source:
                graph.add_edge(load, after)
    cycle = nx.find_cycle(graph)
    return tuple([cycle[0][0], *(target for _source, target in cycle)])


def _trace(
    shared_slice: SharedMemorySlice,
    assignment: _RelationAssignment,
    source_edges: tuple[tuple[str, str, str], ...],
    target_edges: tuple[tuple[str, str, str], ...],
) -> CounterexampleTrace:
    target_pairs = {(source, target) for source, target, _reason in target_edges}
    missing = tuple(
        f"{source} -> {target}: {reason}"
        for source, target, reason in source_edges
        if (source, target) not in target_pairs
    )
    object_ids = {
        event.id: _object_id(event) if _is_memory(event) else None
        for event in shared_slice.events
    }
    events = tuple(
        CounterexampleEvent(
            event_id=event.id,
            thread_role=event.thread_role or "<unknown>",
            module=event.module,
            module_sha256=event.module_sha256,
            pc=event.pc,
            kind=event.kind,
            object_id=object_ids[event.id],
            source_ordering=event.source_ordering,
            target_ordering=event.target_ordering,
        )
        for event in shared_slice.events
    )
    read_from = tuple(
        ReadFromChoice(
            load_event=load,
            store_event=store,
            object_id=object_ids[load] or "<none>",
        )
        for load, store in sorted(assignment.read_from.items())
    )
    coherence = tuple(
        CoherenceChoice(
            before_store=before,
            after_store=after,
            object_id=object_id,
        )
        for object_id, before, after in assignment.coherence
    )
    return CounterexampleTrace(
        events=events,
        read_from=read_from,
        coherence=coherence,
        source_cycle=_source_cycle(shared_slice, assignment, source_edges),
        missing_ordering=missing,
    )


def check_finite_portability(
    shared_slice: SharedMemorySlice, limits: CheckerLimits
) -> tuple[CheckerReport, CounterexampleTrace | None]:
    unsupported = _validate_supported_slice(shared_slice, limits)
    assumptions = (
        "one finite occurrence per MemoryEvent",
        "aligned 1/2/4/8-byte accesses with exact Global alias classes",
        "x86-TSO and RVWMO axiomatic rf/co/fr comparison",
        "RVWMO dependency edges must be present in event provenance",
    )
    if unsupported:
        return (
            CheckerReport(
                backend=BACKEND_NAME,
                backend_version=BACKEND_VERSION,
                limits=limits,
                conclusion=CheckerConclusion.INCOMPLETE,
                reason="the shared-memory slice is outside the finite checker support set",
                unsupported_events=unsupported,
                assumptions=assumptions,
            ),
            None,
        )

    started = monotonic()
    target = _build_encoding(shared_slice, "rvwmo", limits.timeout_ms)
    examined = 0
    while examined < limits.max_executions:
        remaining_ms = limits.timeout_ms - int((monotonic() - started) * 1000)
        if remaining_ms <= 0:
            return _incomplete_report(limits, examined, assumptions, "the portability checker reached its timeout"), None
        target.solver.set(timeout=remaining_ms)
        target_status = target.solver.check()
        if target_status == z3.unknown:
            return _incomplete_report(
                limits,
                examined,
                assumptions,
                f"target solver returned unknown: {target.solver.reason_unknown()}",
            ), None
        if target_status == z3.unsat:
            return (
                CheckerReport(
                    backend=BACKEND_NAME,
                    backend_version=BACKEND_VERSION,
                    limits=limits,
                    conclusion=CheckerConclusion.BOUNDED_EXHAUSTED,
                    examined_executions=examined,
                    reason="all rf/co executions in the finite model were checked",
                    assumptions=assumptions,
                ),
                None,
            )

        assignment = _assignment(target, target.solver.model())
        examined += 1
        source = _build_encoding(shared_slice, "x86-tso", remaining_ms, assignment)
        source_status = source.solver.check()
        if source_status == z3.unknown:
            return _incomplete_report(
                limits,
                examined,
                assumptions,
                f"source solver returned unknown: {source.solver.reason_unknown()}",
            ), None
        if source_status == z3.unsat:
            trace = _trace(
                shared_slice,
                assignment,
                source.fixed_edges,
                target.fixed_edges,
            )
            return (
                CheckerReport(
                    backend=BACKEND_NAME,
                    backend_version=BACKEND_VERSION,
                    limits=limits,
                    conclusion=CheckerConclusion.TARGET_ONLY,
                    examined_executions=examined,
                    reason="RVWMO accepts an rf/co execution rejected by x86-TSO",
                    assumptions=assumptions,
                ),
                trace,
            )

        if assignment.booleans:
            target.solver.add(
                z3.Or(
                    *(variable != value for variable, value in assignment.booleans)
                )
            )
        else:
            # 没有 rf/co 选择时只有一个执行，不能靠 rank 的不同排列重复枚举。
            target.solver.add(z3.BoolVal(False))

    return _incomplete_report(
        limits,
        examined,
        assumptions,
        "the target execution enumeration reached max_executions",
    ), None


def _incomplete_report(
    limits: CheckerLimits,
    examined: int,
    assumptions: tuple[str, ...],
    reason: str,
) -> CheckerReport:
    return CheckerReport(
        backend=BACKEND_NAME,
        backend_version=BACKEND_VERSION,
        limits=limits,
        conclusion=CheckerConclusion.INCOMPLETE,
        examined_executions=examined,
        reason=reason,
        assumptions=assumptions,
    )
