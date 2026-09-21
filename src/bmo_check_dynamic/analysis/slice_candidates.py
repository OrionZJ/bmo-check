from __future__ import annotations

from collections import defaultdict
from hashlib import sha256

from bmo_check_dynamic.model import (
    CandidateSlice,
    EventKind,
    SliceCandidateGroup,
    SliceObligation,
    SliceRemovalLedgerEntry,
    TraceEvent,
)

from .slice_contract import build_obligation_inventory
from .windows import AnalysisWindow, WindowInclusionReason


def build_candidate_slice(window: AnalysisWindow) -> CandidateSlice:
    """生成不改变 checker 输入的候选切片表征。

    目前只报告同线程、同地址、同宽度的重复普通 Load。通信端点保留为
    blocked candidate；非端点 Load 也只是写入 ``proposed_event_ids``，没有
    从 ``retained_event_ids`` 删除。没有独立 proof fact 时结果永远是不完整
    的 candidate-only。
    """

    source_events = tuple(
        sorted(window.events, key=lambda event: (event.thread_id, event.sequence, event.event_id))
    )
    source_ids = tuple(event.event_id for event in source_events)
    endpoint_ids = _inclusion_ids(window, WindowInclusionReason.COMMUNICATION_ENDPOINT)
    if not endpoint_ids:
        endpoint_ids = {
            event_id
            for edge in window.communication_edges
            for event_id in (edge.first_event, edge.second_event)
        }
    boundary_ids = _inclusion_ids(window, WindowInclusionReason.ORDERING_BOUNDARY)
    if not boundary_ids:
        boundary_ids = {
            event.event_id
            for event in source_events
            if event.kind.is_boundary and event.event_id not in endpoint_ids
        }

    groups_by_key: dict[tuple[int, int, int, EventKind], list[TraceEvent]] = defaultdict(list)
    for event in source_events:
        if event.kind == EventKind.LOAD and event.size > 0:
            groups_by_key[(event.thread_id, event.address, event.size, event.kind)].append(event)

    groups: list[SliceCandidateGroup] = []
    proposed_ids: set[str] = set()
    blocked_ids: set[str] = set()
    obligations = build_obligation_inventory(window)
    obligations_by_event: dict[str, list[str]] = defaultdict(list)
    for obligation in obligations:
        for event_id in obligation.event_ids:
            obligations_by_event[event_id].append(obligation.obligation_id)

    ledger: list[SliceRemovalLedgerEntry] = []
    for key, values in sorted(groups_by_key.items()):
        if len(values) < 2:
            continue
        thread_id, address, size, kind = key
        values.sort(key=lambda event: (event.sequence, event.event_id))
        endpoint_values = tuple(event for event in values if event.event_id in endpoint_ids)
        blocked = {event.event_id for event in endpoint_values}
        # 保留一个代表只用于形成候选建议；这些事件仍然留在 retained_event_ids。
        proposed = {
            event.event_id
            for event in values[1:]
            if event.event_id not in endpoint_ids
            and event.event_id not in boundary_ids
        }
        proposed_ids.update(proposed)
        blocked_ids.update(blocked)
        group_id = "group-" + sha256(
            f"{window.window_id}|{thread_id}|{address}|{size}|{kind.name}".encode()
        ).hexdigest()[:24]
        reason = (
            "repeated load candidate; communication endpoints remain blocked and "
            "no RF/PPO closure proof is available"
        )
        groups.append(
            SliceCandidateGroup(
                group_id=group_id,
                thread_id=thread_id,
                address=address,
                size=size,
                kind=kind.name,
                event_count=len(values),
                communication_endpoint_count=len(endpoint_values),
                boundary_count=sum(event.event_id in boundary_ids for event in values),
                proposed_event_ids=tuple(sorted(proposed)),
                blocked_event_ids=tuple(sorted(blocked)),
                reason=reason,
            )
        )

    for event_id in sorted(proposed_ids):
        ledger.append(
            SliceRemovalLedgerEntry(
                event_id=event_id,
                obligation_ids=tuple(sorted(set(obligations_by_event[event_id]))),
                reason="candidate-only; no independent proof fact",
            )
        )

    return CandidateSlice(
        window_id=window.window_id,
        source_event_count=len(source_ids),
        source_event_ids=source_ids,
        retained_event_ids=source_ids,
        proposed_event_ids=tuple(sorted(proposed_ids)),
        removed_event_ids=(),
        obligations=obligations,
        removal_ledger=tuple(ledger),
        groups=tuple(groups),
        complete=False,
    )


def build_candidate_slices(
    windows: tuple[AnalysisWindow, ...],
) -> tuple[CandidateSlice, ...]:
    return tuple(build_candidate_slice(window) for window in windows)


def _inclusion_ids(
    window: AnalysisWindow,
    reason: WindowInclusionReason,
) -> set[str]:
    return {
        inclusion.event_id
        for inclusion in window.event_inclusions
        if reason in inclusion.reasons
    }


__all__ = ["build_candidate_slice", "build_candidate_slices"]
