from __future__ import annotations

from collections import defaultdict

from bmo_check_dynamic.model import (
    EventKind,
    SlicePartition,
    SliceObligation,
    SliceObligationKind,
    SlicePlan,
    SlicePlanStatus,
    TraceEvent,
    stable_obligation_id,
)
from bmo_check_dynamic.proof.relations import (
    source_preserved_order,
    target_preserved_order,
)

from .windows import AnalysisWindow


def build_obligation_inventory(
    window: AnalysisWindow,
) -> tuple[SliceObligation, ...]:
    """枚举当前 checker 输入中可观察的最小 obligation 集合。

    这不是新的 memory-model 编码，也不会缩减窗口。它把事件存在性、通信
    边、PPO、read-from 候选域、coherence 域和 fence/atomic 边界写成稳定的
    类型化记录，供后续切片验证器核对“删掉了什么”。
    """

    obligations: list[SliceObligation] = []
    events = tuple(
        sorted(window.events, key=lambda event: (event.thread_id, event.sequence, event.event_id))
    )
    for event in events:
        obligations.append(
            _obligation(
                window,
                SliceObligationKind.EVENT_PRESENCE,
                (event.event_id,),
                "event-presence",
            )
        )

    for edge in sorted(
        window.communication_edges,
        key=lambda item: (item.first_event, item.second_event, item.address, item.size),
    ):
        obligations.append(
            _obligation(
                window,
                SliceObligationKind.COMMUNICATION_EDGE,
                (edge.first_event, edge.second_event),
                f"address={edge.address};size={edge.size}",
            )
        )

    for kind, relations in (
        (SliceObligationKind.SOURCE_PPO, source_preserved_order(window.events)),
        (SliceObligationKind.TARGET_PPO, target_preserved_order(window.events)),
    ):
        for left, right in sorted(relations):
            obligations.append(
                _obligation(window, kind, (left, right), "preserved-order")
            )

    memory = tuple(event for event in events if event.kind.is_memory)
    writes = tuple(event for event in memory if event.kind.is_write)
    for read in (event for event in memory if event.kind.is_read):
        candidates = tuple(
            write
            for write in writes
            if _covers(write, read)
            and not (
                write.thread_id == read.thread_id
                and write.sequence >= read.sequence
            )
        )
        obligations.append(
            _obligation(
                window,
                SliceObligationKind.READ_FROM_DOMAIN,
                (read.event_id, *(write.event_id for write in candidates)),
                f"candidates={len(candidates)}",
            )
        )

    for group in _overlap_write_domains(writes):
        obligations.append(
            _obligation(
                window,
                SliceObligationKind.COHERENCE_DOMAIN,
                tuple(event.event_id for event in group),
                f"writes={len(group)}",
            )
        )

    for event in events:
        if event.kind.is_boundary:
            obligations.append(
                _obligation(
                    window,
                    SliceObligationKind.BOUNDARY,
                    (event.event_id,),
                    f"kind={event.kind.name}",
                )
            )

    return tuple(sorted(obligations, key=lambda item: item.obligation_id))


def plan_obligation_preserving_split(window: AnalysisWindow) -> SlicePlan:
    """只在 obligation 图没有跨边时提出分区，绝不按事件数量硬切。

    该计划尚未改变 ``AnalysisWindow`` 或 checker 调用。它首先验证当前
    inventory 的超边闭包：同一 obligation 中的所有事件必须落在同一分区。
    这样 SB 这类共享 hub 会明确得到 ``NO_SAFE_SPLIT``，而不是被粗暴切开。
    """

    obligations = build_obligation_inventory(window)
    event_ids = tuple(
        event.event_id
        for event in sorted(
            window.events,
            key=lambda event: (event.thread_id, event.sequence, event.event_id),
        )
    )
    parent = {event_id: event_id for event_id in event_ids}

    def find(event_id: str) -> str:
        root = event_id
        while parent[root] != root:
            root = parent[root]
        while parent[event_id] != event_id:
            next_id = parent[event_id]
            parent[event_id] = root
            event_id = next_id
        return root

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for obligation in obligations:
        anchor = obligation.event_ids[0]
        for event_id in obligation.event_ids[1:]:
            union(anchor, event_id)

    component_events: dict[str, list[str]] = defaultdict(list)
    for event_id in event_ids:
        component_events[find(event_id)].append(event_id)
    component_obligations: dict[str, list[str]] = defaultdict(list)
    cross_partition: list[str] = []
    for obligation in obligations:
        roots = {find(event_id) for event_id in obligation.event_ids}
        if len(roots) != 1:
            cross_partition.append(obligation.obligation_id)
            continue
        component_obligations[next(iter(roots))].append(obligation.obligation_id)

    if cross_partition:
        return SlicePlan(
            window_id=window.window_id,
            status=SlicePlanStatus.NO_SAFE_SPLIT,
            source_event_count=len(event_ids),
            partition_count=1,
            largest_partition_event_count=len(event_ids),
            cross_partition_obligation_ids=tuple(sorted(cross_partition)),
            reason="obligation inventory contains a cross-partition relation",
            complete=False,
        )

    partitions = []
    for index, root in enumerate(sorted(component_events)):
        values = tuple(component_events[root])
        partitions.append(
            SlicePartition(
                partition_id=f"{window.window_id}-part-{index:06d}",
                event_ids=values,
                obligation_ids=tuple(sorted(component_obligations[root])),
            )
        )
    status = (
        SlicePlanStatus.SPLIT_PROVEN
        if len(partitions) > 1
        else SlicePlanStatus.NO_SAFE_SPLIT
    )
    reason = (
        "obligation graph has independent components; checker integration remains "
        "disabled"
        if status is SlicePlanStatus.SPLIT_PROVEN
        else "all window events are connected by at least one checker obligation"
    )
    return SlicePlan(
        window_id=window.window_id,
        status=status,
        source_event_count=len(event_ids),
        partition_count=len(partitions),
        partitions=tuple(partitions),
        largest_partition_event_count=max(
            (len(partition.event_ids) for partition in partitions), default=0
        ),
        reason=reason,
        complete=False,
    )


def _obligation(
    window: AnalysisWindow,
    kind: SliceObligationKind,
    event_ids: tuple[str, ...],
    detail: str,
) -> SliceObligation:
    scoped_detail = f"window={window.window_id};{detail}"
    return SliceObligation(
        obligation_id=stable_obligation_id(kind, event_ids, scoped_detail),
        kind=kind,
        event_ids=event_ids,
        detail=scoped_detail,
    )


def _covers(write: TraceEvent, read: TraceEvent) -> bool:
    return write.address <= read.address and write.end_address >= read.end_address


def _overlap_write_domains(
    writes: tuple[TraceEvent, ...],
) -> tuple[tuple[TraceEvent, ...], ...]:
    """按实际字节重叠建立 coherence 候选域。"""

    remaining = set(range(len(writes)))
    domains: list[tuple[TraceEvent, ...]] = []
    while remaining:
        seed = min(remaining)
        remaining.remove(seed)
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
            pending.extend(sorted(connected))
        domains.append(
            tuple(
                sorted(
                    (writes[index] for index in component),
                    key=lambda event: (event.thread_id, event.sequence, event.event_id),
                )
            )
        )
    return tuple(domains)


__all__ = ["build_obligation_inventory", "plan_obligation_preserving_split"]
