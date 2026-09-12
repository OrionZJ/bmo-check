"""动态 trace window 的固定执行表征接口。

它只把已有关系函数应用到调用者给出的 ``rf/co``，不会用 observed value
去生成静态证明，也不改变 ``check_window`` 的 TRACE_SAFE 判定流程。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

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
    read_from: Mapping[str, str | None],
    coherence: tuple[tuple[str, str, str], ...] = (),
    object_locations: Mapping[str, tuple[int, int]] | None = None,
) -> FixedExecutionResult:
    """在既定 trace window 上检查固定 ``rf/co``，不枚举其它关系。"""

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

    source = source_preserved_order(window.events)
    target = target_preserved_order(window.events)
    return FixedExecutionResult(
        _allowed("x86-tso", source | communication),
        _allowed("rvwmo", target | communication),
    )


__all__ = ["FixedExecutionResult", "FixedModelResult", "check_fixed_execution"]
