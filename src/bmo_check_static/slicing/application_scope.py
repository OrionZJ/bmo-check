from __future__ import annotations

from bmo_check_static.model import (
    AddressKind,
    EventKind,
    MemoryEvent,
    ProofObject,
    ProofReason,
    SharedMemorySlice,
)


def _is_runtime_boundary(event: MemoryEvent, executable_sha256: str) -> bool:
    """识别显式契约覆盖的运行库 effect。

    application scope 只把已经命名为运行库内部状态的调用移出应用通信图。
    未命名的 opaque call、syscall 和未知地址仍然留在 slice 中，避免把一个
    可能访问应用对象的外部调用误当成安全。
    """

    if event.module_sha256 != executable_sha256:
        return True
    if event.kind != EventKind.OPAQUE_CALL:
        return False
    return (
        event.provenance.get("runtime_internal") is True
        or (
            event.address is not None
            and event.address.provenance.get("runtime_internal") is True
        )
    )


def _unknown_is_removed(unknown: object, removed: set[str]) -> bool:
    details = getattr(unknown, "details", {})
    event_id = details.get("event_id")
    if isinstance(event_id, str):
        return event_id in removed
    event_ids = details.get("event_ids")
    return (
        isinstance(event_ids, list)
        and bool(event_ids)
        and all(isinstance(item, str) and item in removed for item in event_ids)
    )


def restrict_to_application_scope(
    shared_slice: SharedMemorySlice,
    *,
    executable_sha256: str,
) -> SharedMemorySlice:
    """构造显式 application scope 的共享切片。

    这不是把未知事实改成 SAFE。只有 effect contract 已将调用绑定到运行库
    私有对象时才移除它；普通应用事件、未摘要调用和 syscall 仍按原规则阻塞
    证明。被移除的每个事件都留下 proof object，证书可以复核这个边界。
    """

    removed_events = tuple(
        event
        for event in shared_slice.events
        if _is_runtime_boundary(event, executable_sha256)
    )
    if not removed_events:
        return shared_slice

    removed_ids = {event.id for event in removed_events}
    events = tuple(event for event in shared_slice.events if event.id not in removed_ids)
    program_order = tuple(
        edge
        for edge in shared_slice.program_order
        if edge.source_event not in removed_ids
        and edge.target_event not in removed_ids
    )
    # 删除运行库调用后，不能留下指向已删除节点的 pthread 边。
    # 否则 checker 会把边的两个端点都当成缺失事件，连仍然有效的 join
    # 也会被误报成不支持输入。
    synchronization = tuple(
        edge
        for edge in shared_slice.synchronization
        if edge.source_event not in removed_ids
        and edge.target_event not in removed_ids
    )
    conflicts = tuple(
        conflict
        for conflict in shared_slice.conflicts
        if conflict.first_event not in removed_ids
        and conflict.second_event not in removed_ids
    )
    unknowns = tuple(
        unknown
        for unknown in shared_slice.unknowns
        if not _unknown_is_removed(unknown, removed_ids)
    )
    proof = ProofObject(
        id="proof:application-runtime-boundary",
        reason=ProofReason.APPLICATION_RUNTIME_BOUNDARY,
        event_ids=tuple(sorted(removed_ids)),
        supporting_facts=(
            "application scope was explicitly requested",
            "each removed call is bound to a named runtime-internal object",
            "ordinary application events and unsummarized calls remain in the slice",
            "runtime LOCK/XCHG/Fence behavior remains covered by the DBT contract",
        ),
    )
    unknown_event_count = sum(
        event.kind
        in {EventKind.OPAQUE_CALL, EventKind.SYSCALL, EventKind.UNKNOWN_MEMORY_EFFECT}
        or (
            event.address is not None
            and event.address.kind == AddressKind.UNKNOWN
        )
        for event in events
    )
    coverage = shared_slice.coverage.model_copy(
        update={
            "remaining_shared_events": len(events),
            "unknown_events": unknown_event_count,
        }
    )
    return shared_slice.model_copy(
        update={
            "events": events,
            "program_order": program_order,
            "synchronization": synchronization,
            "conflicts": conflicts,
            "proof_objects": (*shared_slice.proof_objects, proof),
            "coverage": coverage,
            "unknowns": unknowns,
        }
    )
