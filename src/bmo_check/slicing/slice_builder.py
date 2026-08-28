from __future__ import annotations

from collections import defaultdict

from bmo_check.model import (
    AddressKind,
    AliasRelation,
    ConflictCandidate,
    EventKind,
    MemoryEvent,
    MemoryEventReport,
    Ordering,
    ProgramOrderEdge,
    ProofReason,
    PruningCoverage,
    SharedMemorySlice,
    SharedStateReport,
    SynchronizationEdge,
    ThreadDiscoveryReport,
)


_WRITE_KINDS = {
    EventKind.STORE,
    EventKind.ATOMIC_RMW,
    EventKind.OPAQUE_CALL,
    EventKind.SYSCALL,
    EventKind.UNKNOWN_MEMORY_EFFECT,
}
_MEMORY_KINDS = _WRITE_KINDS | {EventKind.LOAD}


def _range(event: MemoryEvent) -> tuple[int, int] | None:
    address = event.address
    if address is None or address.offset is None or event.size is None:
        return None
    return address.offset, address.offset + event.size


def _alias(first: MemoryEvent, second: MemoryEvent) -> AliasRelation:
    left, right = first.address, second.address
    if left is None or right is None:
        return AliasRelation.MAY_ALIAS
    if AddressKind.UNKNOWN in {left.kind, right.kind}:
        return AliasRelation.MAY_ALIAS
    if AddressKind.AFFINE in {left.kind, right.kind}:
        return AliasRelation.MAY_ALIAS
    if left.kind != right.kind or left.base != right.base:
        return AliasRelation.NO_ALIAS
    first_range, second_range = _range(first), _range(second)
    if first_range is None or second_range is None:
        return AliasRelation.MAY_ALIAS
    if first_range[1] <= second_range[0] or second_range[1] <= first_range[0]:
        return AliasRelation.NO_ALIAS
    return AliasRelation.MUST_ALIAS


def _can_run_concurrently(first: MemoryEvent, second: MemoryEvent) -> tuple[bool, bool]:
    first_role, second_role = first.thread_role, second.thread_role
    if first_role is None or second_role is None:
        return True, False
    if first_role != second_role:
        return True, False
    # main 只有一个动态实例；worker role 可能由循环中的 create site 多次创建。
    return first_role != "main", first_role != "main"


def _conflicts(events: tuple[MemoryEvent, ...]) -> tuple[ConflictCandidate, ...]:
    candidates: list[ConflictCandidate] = []
    memory = [event for event in events if event.kind in _MEMORY_KINDS]
    for first_index, first in enumerate(memory):
        for second in memory[first_index:]:
            concurrent, same_role_instances = _can_run_concurrently(first, second)
            if not concurrent:
                continue
            if first.kind not in _WRITE_KINDS and second.kind not in _WRITE_KINDS:
                continue
            alias = _alias(first, second)
            if alias == AliasRelation.NO_ALIAS:
                continue
            candidates.append(
                ConflictCandidate(
                    first_event=first.id,
                    second_event=second.id,
                    first_role=first.thread_role or "unknown",
                    second_role=second.thread_role or "unknown",
                    alias=alias,
                    same_role_instances=same_role_instances,
                )
            )
    return tuple(candidates)


def _lifecycle_edges(
    events: tuple[MemoryEvent, ...],
    program_order: tuple[ProgramOrderEdge, ...],
    threads: ThreadDiscoveryReport,
) -> tuple[SynchronizationEdge, ...]:
    by_role: dict[str, list[MemoryEvent]] = defaultdict(list)
    by_pc_kind: dict[tuple[int, EventKind], list[MemoryEvent]] = defaultdict(list)
    for event in events:
        if event.thread_role is not None:
            by_role[event.thread_role].append(event)
        by_pc_kind[(event.pc, event.kind)].append(event)
    incoming = {edge.target_event for edge in program_order}
    outgoing = {edge.source_event for edge in program_order}
    edges: list[SynchronizationEdge] = []
    for create in threads.creates:
        create_events = by_pc_kind.get((create.call_site.pc, EventKind.THREAD_CREATE), ())
        child_events = by_role.get(create.child_role, ())
        if not create_events or not child_events:
            continue
        entries = [event for event in child_events if event.id not in incoming]
        for source in create_events:
            for target in entries:
                edges.append(
                    SynchronizationEdge(
                        source_event=source.id,
                        target_event=target.id,
                        kind="pthread_create",
                        evidence=("recovered pthread child role",),
                        complete=source.target_ordering != Ordering.UNKNOWN,
                        reason=(
                            None
                            if source.target_ordering != Ordering.UNKNOWN
                            else "pthread_create target ordering is not summarized from the concrete library"
                        ),
                    )
                )
    for join in threads.joins:
        join_events = by_pc_kind.get((join.call_site.pc, EventKind.THREAD_JOIN), ())
        for child_role in join.candidate_child_roles:
            child_events = by_role.get(child_role, ())
            if not join_events or not child_events:
                continue
            exits = [event for event in child_events if event.id not in outgoing]
            for source in exits:
                for target in join_events:
                    edges.append(
                        SynchronizationEdge(
                            source_event=source.id,
                            target_event=target.id,
                            kind="pthread_join",
                            evidence=(
                                "complete join relation"
                                if join.complete
                                else "candidate join relation; completion remains Unknown",
                            ),
                            complete=(
                                join.complete
                                and target.target_ordering != Ordering.UNKNOWN
                            ),
                            reason=(
                                None
                                if join.complete
                                and target.target_ordering != Ordering.UNKNOWN
                                else "join relation or concrete target ordering is incomplete"
                            ),
                        )
                    )
    return tuple(edges)


def build_shared_memory_slice(
    memory_events: MemoryEventReport,
    shared_state: SharedStateReport,
    threads: ThreadDiscoveryReport,
) -> SharedMemorySlice:
    kept = set(shared_state.kept_event_ids)
    events = tuple(event for event in memory_events.events if event.id in kept)
    program_order = tuple(
        edge
        for edge in memory_events.program_order
        if edge.source_event in kept and edge.target_event in kept
    )
    proof_counts = defaultdict(int)
    for proof in shared_state.proofs:
        proof_counts[proof.reason] += len(proof.event_ids)
    unknown_events = sum(
        event.kind in {EventKind.OPAQUE_CALL, EventKind.SYSCALL, EventKind.UNKNOWN_MEMORY_EFFECT}
        or (event.address is not None and event.address.kind == AddressKind.UNKNOWN)
        for event in events
    )
    coverage = PruningCoverage(
        total_events=len(memory_events.events),
        thread_local_removed=(
            proof_counts[ProofReason.TLS_STORAGE]
            + proof_counts[ProofReason.UNESCAPED_STACK]
            + proof_counts[ProofReason.SINGLE_MAIN_ROLE]
            + proof_counts[ProofReason.SEQUENTIAL_BEFORE_CREATE]
        ),
        readonly_removed=proof_counts[ProofReason.READ_ONLY_AFTER_CREATE],
        disjoint_removed=proof_counts[ProofReason.DISJOINT_AFFINE],
        atomic_covered_removed=0,
        remaining_shared_events=len(events),
        unknown_events=unknown_events,
    )
    return SharedMemorySlice(
        events=events,
        program_order=program_order,
        conflicts=_conflicts(events),
        synchronization=_lifecycle_edges(events, program_order, threads),
        proof_objects=shared_state.proofs,
        coverage=coverage,
        unknowns=memory_events.unknowns + shared_state.unknowns + threads.unknowns,
    )
