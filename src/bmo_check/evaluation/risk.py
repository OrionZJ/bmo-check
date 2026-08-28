from __future__ import annotations

import networkx as nx

from bmo_check.model import (
    AddressKind,
    EventKind,
    MemoryEvent,
    RiskFinding,
    SharedMemorySlice,
)


_BARRIERS = {
    EventKind.ATOMIC_RMW,
    EventKind.FENCE,
    EventKind.ACQUIRE,
    EventKind.RELEASE,
    EventKind.BARRIER,
    EventKind.OPAQUE_CALL,
    EventKind.SYSCALL,
    EventKind.UNKNOWN_MEMORY_EFFECT,
}


def _object_id(event: MemoryEvent) -> str | None:
    address = event.address
    if (
        address is None
        or address.kind != AddressKind.GLOBAL
        or address.base is None
        or address.offset is None
        or event.size is None
    ):
        return None
    return (
        f"{event.module_sha256}:Global:{address.base}:"
        f"{address.offset}:{event.size}"
    )


def _has_blocking_event(
    reachable: dict[str, set[str]],
    events: dict[str, MemoryEvent],
    source: str,
    target: str,
) -> bool:
    for event_id, event in events.items():
        if event_id in {source, target} or event.kind not in _BARRIERS:
            continue
        if event_id in reachable[source] and target in reachable[event_id]:
            return True
    return False


def find_publication_risks(
    shared_slice: SharedMemorySlice,
    max_findings: int = 64,
) -> tuple[RiskFinding, ...]:
    """寻找 W(x)→W(flag) / R(flag)→R(x) 的局部弱序窗口。"""

    events = {event.id: event for event in shared_slice.events}
    graph = nx.DiGraph()
    graph.add_nodes_from(events)
    graph.add_edges_from(
        (edge.source_event, edge.target_event)
        for edge in shared_slice.program_order
        if edge.source_event in events and edge.target_event in events
    )
    reachable = {event_id: nx.descendants(graph, event_id) for event_id in events}
    writes = [event for event in events.values() if event.kind == EventKind.STORE]
    reads = [event for event in events.values() if event.kind == EventKind.LOAD]
    writer_pairs: dict[tuple[str, str], list[tuple[MemoryEvent, MemoryEvent]]] = {}
    reader_pairs: dict[tuple[str, str], list[tuple[MemoryEvent, MemoryEvent]]] = {}

    for first in writes:
        first_object = _object_id(first)
        if first_object is None:
            continue
        for second in writes:
            second_object = _object_id(second)
            if (
                first.id == second.id
                or first.thread_role != second.thread_role
                or second_object is None
                or first_object == second_object
                or second.id not in reachable[first.id]
                or _has_blocking_event(reachable, events, first.id, second.id)
            ):
                continue
            writer_pairs.setdefault((first_object, second_object), []).append(
                (first, second)
            )

    for first in reads:
        first_object = _object_id(first)
        if first_object is None:
            continue
        for second in reads:
            second_object = _object_id(second)
            if (
                first.id == second.id
                or first.thread_role != second.thread_role
                or second_object is None
                or first_object == second_object
                or second.id not in reachable[first.id]
                or _has_blocking_event(reachable, events, first.id, second.id)
            ):
                continue
            reader_pairs.setdefault((first_object, second_object), []).append(
                (first, second)
            )

    findings: list[RiskFinding] = []
    seen: set[tuple[str, ...]] = set()
    for (payload, flag), writers in writer_pairs.items():
        for writer_payload, writer_flag in writers:
            for reader_flag, reader_payload in reader_pairs.get((flag, payload), ()):
                if writer_payload.thread_role == reader_flag.thread_role:
                    continue
                event_ids = (
                    writer_payload.id,
                    writer_flag.id,
                    reader_flag.id,
                    reader_payload.id,
                )
                if event_ids in seen:
                    continue
                seen.add(event_ids)
                findings.append(
                    RiskFinding(
                        kind="PlainStorePublication",
                        event_ids=event_ids,
                        pcs=(
                            writer_payload.pc,
                            writer_flag.pc,
                            reader_flag.pc,
                            reader_payload.pc,
                        ),
                        roles=(
                            writer_payload.thread_role or "unknown",
                            reader_flag.thread_role or "unknown",
                        ),
                        objects=(payload, flag),
                        missing_orders=(
                            f"{writer_payload.id} -> {writer_flag.id}: Store->Store",
                            f"{reader_flag.id} -> {reader_payload.id}: Load->Load",
                        ),
                        reason=(
                            "mo-off lacks both x86 preserved-order edges; unrelated "
                            "Unknowns do not erase this local risk window"
                        ),
                    )
                )
                if len(findings) >= max_findings:
                    return tuple(findings)
    return tuple(findings)
