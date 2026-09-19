"""动态 trace window 的固定执行表征接口。

它只把已有关系函数应用到调用者给出的 ``rf/co``，不会用 observed value
去生成静态证明，也不改变 ``check_window`` 的 TRACE_SAFE 判定流程。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from bmo_check_core import (
    AccessRange,
    ExecutionRelations,
    MemoryAccessKind,
    MemoryOperation,
    MemoryRelation,
    RelationKind,
)
from bmo_check_dynamic.analysis import AnalysisWindow
from bmo_check_dynamic.model import EventKind, TraceEvent

from .checker import _atomic_read_from_valid, _communication_relations
from .relations import find_cycle, source_preserved_order, target_preserved_order


@dataclass(frozen=True, slots=True)
class FixedModelResult:
    """一个固定 ``rf/co`` 赋值在某个动态关系模型下的结果。"""

    model: str
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class FixedExecutionResult:
    """同一固定执行在 x86-TSO 与 RVWMO 下的独立结果。"""

    source: FixedModelResult
    target: FixedModelResult


def _location_labels(
    window: AnalysisWindow,
    object_locations: Mapping[str, tuple[int, int]] | None,
) -> dict[tuple[int, int], str]:
    """把动态地址绑定到唯一 object label，拒绝同址多标签猜测。"""

    locations = {
        (event.address, event.size)
        for event in window.events
        if event.kind.is_write
    }
    labels = {
        location: f"0x{location[0]:x}/{location[1]}"
        for location in locations
    }
    if object_locations is None:
        return labels
    for label, location in sorted(object_locations.items()):
        if location not in locations:
            continue
        previous = labels[location]
        if previous != f"0x{location[0]:x}/{location[1]}" and previous != label:
            raise ValueError(f"dynamic location has ambiguous object labels: {location!r}")
        labels[location] = label
    return labels


def _canonical_operations(
    window: AnalysisWindow,
    object_locations: Mapping[str, tuple[int, int]] | None,
) -> dict[str, MemoryOperation]:
    labels = _location_labels(window, object_locations)
    operations: dict[str, MemoryOperation] = {}
    for event in window.events:
        if not event.kind.is_memory:
            continue
        if event.kind is EventKind.LOAD:
            kind = MemoryAccessKind.LOAD
        elif event.kind is EventKind.STORE:
            kind = MemoryAccessKind.STORE
        elif event.kind is EventKind.ATOMIC_RMW:
            kind = MemoryAccessKind.RMW
        else:
            raise ValueError(
                f"event {event.event_id!r} is outside the canonical relation kernel"
            )
        location = (event.address, event.size)
        object_id = labels.get(location, f"0x{event.address:x}/{event.size}")
        operations[event.event_id] = MemoryOperation(
            event_id=event.event_id,
            thread_id=str(event.thread_id),
            sequence=event.sequence,
            access=AccessRange(object_id=object_id, offset=0, size=event.size),
            kind=kind,
        )
    return operations


def canonicalize_fixed_relations(
    window: AnalysisWindow,
    *,
    read_from: Mapping[str, str | None],
    coherence: tuple[tuple[str, str, str], ...] = (),
    from_read: tuple[tuple[str, str, str], ...] = (),
    object_locations: Mapping[str, tuple[int, int]] | None = None,
) -> ExecutionRelations:
    """把动态 fixed-execution 的旧关系输入转换成 typed relation。"""

    operations = _canonical_operations(window, object_locations)
    events = {event.event_id: event for event in window.events}

    def operation(event_id: str) -> MemoryOperation:
        try:
            return operations[event_id]
        except KeyError as error:
            raise ValueError(f"relation references unknown event {event_id!r}") from error

    labels = _location_labels(window, object_locations)
    labels_by_location = {label: location for location, label in labels.items()}

    def check_label(label: str, first: str, second: str) -> None:
        if label not in labels_by_location:
            raise ValueError(f"relation references unknown dynamic object label {label!r}")
        first_event = events.get(first)
        second_event = events.get(second)
        if first_event is None or second_event is None:
            raise ValueError("relation references an unknown dynamic event")
        expected = labels_by_location[label]
        if (first_event.address, first_event.size) != expected:
            raise ValueError("relation object label does not match source event")
        if (second_event.address, second_event.size) != expected:
            raise ValueError("relation object label does not match target event")

    return ExecutionRelations(
        read_from=tuple(
            MemoryRelation(
                RelationKind.READ_FROM,
                None if source_id is None else operation(source_id),
                operation(load_id),
            )
            for load_id, source_id in sorted(read_from.items())
        ),
        coherence=tuple(
            (
                check_label(label, before, after),
                MemoryRelation(RelationKind.COHERENCE, operation(before), operation(after)),
            )[1]
            for label, before, after in coherence
        ),
        from_read=tuple(
            (
                check_label(label, read, after),
                MemoryRelation(RelationKind.FROM_READ, operation(read), operation(after)),
            )[1]
            for label, read, after in from_read
        ),
    )


def _legacy_relations(
    window: AnalysisWindow,
    relations: ExecutionRelations,
    object_locations: Mapping[str, tuple[int, int]] | None,
) -> tuple[Mapping[str, str | None], tuple[tuple[str, str, str], ...], tuple[tuple[str, str, str], ...], dict[str, tuple[int, int]]]:
    expected = _canonical_operations(window, object_locations)
    events = {event.event_id: event for event in window.events}
    if not relations.all_exact_width:
        raise ValueError("typed relation is outside the exact-width support boundary")

    def event_id(operation: MemoryOperation) -> str:
        if expected.get(operation.event_id) != operation:
            raise ValueError(
                f"typed relation endpoint {operation.event_id!r} does not match window"
            )
        return operation.event_id

    read_from = {
        event_id(relation.target):
        (None if relation.source is None else event_id(relation.source))
        for relation in relations.read_from
    }
    coherence = tuple(
        (
            relation.source.access.object_id,
            event_id(relation.source),
            event_id(relation.target),
        )
        for relation in relations.coherence
        if relation.source is not None
    )
    from_read = tuple(
        (
            relation.target.access.object_id,
            event_id(relation.source),
            event_id(relation.target),
        )
        for relation in relations.from_read
        if relation.source is not None
    )
    derived_locations = dict(object_locations or {})
    for operation in (*relations.read_from, *relations.coherence, *relations.from_read):
        for endpoint in (operation.source, operation.target):
            if endpoint is not None and endpoint.access.object_id not in derived_locations:
                event = events[event_id(endpoint)]
                derived_locations[endpoint.access.object_id] = (event.address, event.size)
    return read_from, coherence, from_read, derived_locations


def _unknown(model: str, reason: str) -> FixedModelResult:
    return FixedModelResult(model=model, status="unknown", reason=reason)


def _allowed(model: str, edges: set[tuple[str, str]]) -> FixedModelResult:
    cycle = find_cycle(edges)
    if cycle:
        return FixedModelResult(
            model=model,
            status="forbidden",
            reason="fixed relation graph contains a cycle: " + " -> ".join(cycle),
        )
    return FixedModelResult(
        model=model,
        status="allowed",
        reason="fixed relation graph is acyclic under the dynamic model",
    )


def check_fixed_execution(
    window: AnalysisWindow,
    *,
    read_from: Mapping[str, str | None] | None = None,
    coherence: tuple[tuple[str, str, str], ...] = (),
    from_read: tuple[tuple[str, str, str], ...] = (),
    object_locations: Mapping[str, tuple[int, int]] | None = None,
    relations: ExecutionRelations | None = None,
) -> FixedExecutionResult:
    """在既定 trace window 上检查固定 ``rf/co``，不枚举其它关系。"""

    if relations is not None:
        if read_from is not None or coherence or from_read:
            reason = "typed relations cannot be mixed with legacy relation arguments"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        if not isinstance(relations, ExecutionRelations):
            reason = "typed relations must be an ExecutionRelations value"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        try:
            read_from, coherence, from_read, derived_locations = _legacy_relations(
                window, relations, object_locations
            )
            object_locations = derived_locations
        except ValueError as error:
            reason = f"typed relation binding is incomplete: {error}"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
    elif read_from is None:
        reason = "fixed execution requires legacy or typed relation input"
        return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    events = {event.event_id: event for event in window.events}
    memory = tuple(event for event in window.events if event.kind.is_memory)
    reads = {event.event_id for event in memory if event.kind.is_read}
    writes = {event.event_id for event in memory if event.kind.is_write}
    if set(read_from) != reads:
        reason = "fixed rf assignment must cover every dynamic load/RMW exactly once"
        return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    writes_by_location: dict[tuple[int, int], tuple[TraceEvent, ...]] = {}
    locations = sorted(
        {(event.address, event.size) for event in memory if event.kind.is_write}
    )
    for location in locations:
        writes_by_location[location] = tuple(
            event for event in memory if event.kind.is_write
            and (event.address, event.size) == location
        )
    location_by_event = {
        event.event_id: (event.address, event.size)
        for event in memory
    }
    for load_id, store_id in read_from.items():
        if load_id not in reads:
            reason = f"rf references a non-load event {load_id!r}"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        if store_id is not None and (
            store_id not in writes
            or location_by_event[store_id] != location_by_event[load_id]
        ):
            reason = f"rf source does not match the dynamic load location: {load_id!r} <- {store_id!r}"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    location_labels = {
        location: f"0x{location[0]:x}/{location[1]}"
        for location in writes_by_location
    }
    if object_locations is not None:
        for label, location in object_locations.items():
            if location in writes_by_location:
                location_labels[location] = label

    selected_orders: list[tuple[TraceEvent, ...]] = []
    known_labels = set(location_labels.values())
    if any(label not in known_labels for label, _before, _after in coherence):
        reason = "coherence references an unknown dynamic object label"
        return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
    for location, location_writes in sorted(writes_by_location.items()):
        object_label = location_labels[location]
        pairs = {
            (before, after)
            for coherence_label, before, after in coherence
            if coherence_label == object_label
        }
        expected = len(location_writes) * (len(location_writes) - 1) // 2
        if len(pairs) != expected:
            reason = f"coherence assignment is incomplete for dynamic location {location!r}"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        by_id = {event.event_id: event for event in location_writes}
        if any(left not in by_id or right not in by_id for left, right in pairs):
            reason = "coherence references a different dynamic location"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        incoming = {event_id: 0 for event_id in by_id}
        outgoing: dict[str, set[str]] = {event_id: set() for event_id in by_id}
        for left, right in pairs:
            outgoing[left].add(right)
            incoming[right] += 1
        order: list[TraceEvent] = []
        ready = sorted(event_id for event_id, degree in incoming.items() if degree == 0)
        while ready:
            event_id = ready.pop(0)
            order.append(by_id[event_id])
            for target in sorted(outgoing[event_id]):
                incoming[target] -= 1
                if incoming[target] == 0:
                    ready.append(target)
                    ready.sort()
        if len(order) != len(location_writes):
            reason = "coherence relation is cyclic or not a total order"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        if len(location_writes) > 1:
            selected_orders.append(tuple(order))

    rf = tuple(
        (events[load_id], events[store_id] if store_id is not None else None)
        for load_id, store_id in sorted(read_from.items())
    )
    # _communication_relations 使用精确 location 分组；对象标签只在入口处
    # 绑定到地址，避免同名 fixture object 把两个运行时对象混在一起。
    communication, communication_coherence = _communication_relations(
        rf,
        tuple(selected_orders),
        writes_by_location,
        tuple(event for event in memory if event.kind.is_write),
    )
    if not _atomic_read_from_valid(
        rf,
        communication_coherence,
    ):
        reason = "fixed coherence does not make an atomic read-from adjacent"
        return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    if from_read:
        expected_from_read: set[tuple[str, str, str]] = set()
        order_by_location = {
            (order[0].address, order[0].size): order
            for order in selected_orders
            if order
        }
        for read, write in rf:
            location = location_by_event[read.event_id]
            order = order_by_location.get(location, tuple(writes_by_location[location]))
            later = (
                order[order.index(write) + 1 :]
                if write is not None
                else order
            )
            expected_from_read.update(
                (location_labels[location], read.event_id, later_write.event_id)
                for later_write in later
            )
        if set(from_read) != expected_from_read:
            reason = "explicit from-read relation does not match the rf/co assignment"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    source = source_preserved_order(window.events)
    target = target_preserved_order(window.events)
    return FixedExecutionResult(
        _allowed("x86-tso", source | communication),
        _allowed("rvwmo", target | communication),
    )


__all__ = [
    "FixedExecutionResult",
    "FixedModelResult",
    "canonicalize_fixed_relations",
    "check_fixed_execution",
]
