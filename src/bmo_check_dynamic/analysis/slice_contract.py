from __future__ import annotations

from collections import defaultdict

from bmo_check_dynamic.model import (
    EventKind,
    SliceObligation,
    SliceObligationKind,
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


__all__ = ["build_obligation_inventory"]
