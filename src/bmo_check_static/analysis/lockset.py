from __future__ import annotations

from collections import defaultdict, deque

from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    EventKind,
    MemoryEvent,
    ProgramOrderEdge,
)


_LOCKED_MEMORY_KINDS = frozenset(
    {EventKind.LOAD, EventKind.STORE, EventKind.ATOMIC_RMW}
)
_UNKNOWN_BOUNDARIES = frozenset(
    {
        EventKind.OPAQUE_CALL,
        EventKind.SYSCALL,
        EventKind.UNKNOWN_MEMORY_EFFECT,
    }
)


def _concrete_lock_key(address: AbstractAddress | None) -> tuple[str, str, int | None] | None:
    """只接受能在不同路径上唯一识别的锁对象。

    loaded pointer、未知地址和带间接 provenance 的值可能在不同线程指向
    不同 mutex；把它们合并会让一个线程持锁的事实错误地覆盖另一个对象。
    """

    if address is None or address.kind not in {
        AddressKind.GLOBAL,
        AddressKind.HEAP,
        AddressKind.STACK,
        AddressKind.TLS,
    }:
        return None
    if address.base is None or address.provenance.get("base_indirect") is True:
        return None
    return (address.kind.value, address.base, address.offset)


def _transfer(event: MemoryEvent, held: frozenset[tuple[str, str, int | None]]) -> frozenset[tuple[str, str, int | None]]:
    if event.kind == EventKind.ACQUIRE:
        lock = _concrete_lock_key(event.address)
        # Unknown acquire 不能增加任何已持有锁；后续访问只有在另一条
        # 已知路径上也持有同一把锁时才会被证明。
        return held | {lock} if lock is not None else frozenset()
    if event.kind == EventKind.RELEASE:
        lock = _concrete_lock_key(event.address)
        # 不知道释放的是哪把锁时，继续携带旧 lockset 会把临界区延长到
        # 解锁之后；清空它只会减少可剪枝事件，不会造成 false SAFE。
        return held - {lock} if lock is not None else frozenset()
    if event.kind in _UNKNOWN_BOUNDARIES:
        # 未知 helper 可能在内部解锁、重入或访问任意应用对象。不能把
        # 调用前的 lockset 跨过这个边界传给后续访存。
        return frozenset()
    return held


def prove_definite_locksets(
    events: tuple[MemoryEvent, ...],
    program_order: tuple[ProgramOrderEdge, ...],
) -> dict[str, frozenset[tuple[str, str, int | None]]]:
    """计算每个事件入口处沿所有已恢复路径都持有的具体锁集合。

    这是一个只使用 CFG 程序序边的 must 分析。路径合流取交集，缺失的
    interprocedural 边和未知同步自然变成空集合，因此它只能漏掉证明，不能
    把未验证的临界区当成已验证临界区。
    """

    by_id = {event.id: event for event in events}
    predecessors: dict[str, set[str]] = defaultdict(set)
    successors: dict[str, set[str]] = defaultdict(set)
    for edge in program_order:
        first = by_id.get(edge.source_event)
        second = by_id.get(edge.target_event)
        if first is None or second is None or first.thread_role != second.thread_role:
            continue
        successors[first.id].add(second.id)
        predecessors[second.id].add(first.id)

    by_role: dict[str, list[str]] = defaultdict(list)
    for event in events:
        if event.thread_role is not None:
            by_role[event.thread_role].append(event.id)

    in_sets: dict[str, frozenset[tuple[str, str, int | None]]] = {}
    for role, role_ids in by_role.items():
        role_set = set(role_ids)
        roots = [event_id for event_id in role_ids if not predecessors[event_id] & role_set]
        # 纯环 CFG 没有入口事件。把每个节点当作空集合入口，避免把一圈
        # lock/unlock 反推成“循环入口已持锁”。
        if not roots:
            roots = list(role_ids)
        work = deque(roots)
        for event_id in roots:
            in_sets[event_id] = frozenset()
        while work:
            event_id = work.popleft()
            event = by_id[event_id]
            out_set = _transfer(event, in_sets[event_id])
            for successor in successors.get(event_id, set()) & role_set:
                previous = in_sets.get(successor)
                candidate = (
                    out_set
                    if previous is None
                    else frozenset(previous & out_set)
                )
                if previous != candidate:
                    in_sets[successor] = candidate
                    work.append(successor)

    return in_sets


def lock_protection_candidates(
    events: tuple[MemoryEvent, ...],
    locksets: dict[str, frozenset[tuple[str, str, int | None]]],
) -> tuple[tuple[str, str, int | None], ...]:
    """返回一组普通访存共同受保护的具体锁；空元组表示无法证明。"""

    if not events or any(event.kind not in _LOCKED_MEMORY_KINDS for event in events):
        return ()
    candidates: set[tuple[str, str, int | None]] | None = None
    for event in events:
        held = locksets.get(event.id, frozenset())
        if not held:
            return ()
        candidates = set(held) if candidates is None else candidates & held
        if not candidates:
            return ()
    return tuple(sorted(candidates))


__all__ = ["lock_protection_candidates", "prove_definite_locksets"]
