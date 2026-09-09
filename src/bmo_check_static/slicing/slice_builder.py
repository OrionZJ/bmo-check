from __future__ import annotations

from collections import defaultdict
from itertools import combinations

from bmo_check_static.model import (
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
    uncertain: list[MemoryEvent] = []
    concrete: dict[tuple[AddressKind, str], list[MemoryEvent]] = defaultdict(list)
    for event in memory:
        address = event.address
        if (
            address is None
            or address.kind in {AddressKind.UNKNOWN, AddressKind.AFFINE}
            or address.base is None
            or address.offset is None
            or event.size is None
        ):
            uncertain.append(event)
        else:
            # 已知对象之间只有同一 kind/base 才可能重叠；把不同对象
            # 分桶后，worker 数量增加不会把所有全局和 heap 访问做笛卡尔积。
            concrete[(address.kind, address.base)].append(event)

    def add_pair(first: MemoryEvent, second: MemoryEvent) -> None:
        concurrent, same_role_instances = _can_run_concurrently(first, second)
        if not concurrent:
            return
        if first.kind not in _WRITE_KINDS and second.kind not in _WRITE_KINDS:
            return
        alias = _alias(first, second)
        if alias == AliasRelation.NO_ALIAS:
            return
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

    # 同一 worker 访存可能由多个动态实例重复执行；保留原实现的
    # self-conflict，不能因为分桶只枚举不同事件就漏掉这类候选。
    for event in memory:
        add_pair(event, event)

    # Unknown/Affine 地址仍须和所有事件比较；这是精度代价，不能靠
    # 地址值猜测 NoAlias。这里只把确定对象的组合从这条慢路径移走。
    uncertain_ids = {event.id for event in uncertain}
    for first in uncertain:
        for second in memory:
            if first.id == second.id:
                continue
            if second.id in uncertain_ids and first.id >= second.id:
                continue
            add_pair(first, second)
    for bucket in concrete.values():
        for first, second in combinations(bucket, 2):
            add_pair(first, second)

    # `uncertain` 循环按字符串 id 去重依赖 id 的可比较性；同一报告内
    # id 唯一且稳定，下面按生成顺序重新消除任何意外重复。
    unique: dict[tuple[str, str], ConflictCandidate] = {}
    for candidate in candidates:
        key = (candidate.first_event, candidate.second_event)
        unique.setdefault(key, candidate)
    return tuple(unique.values())


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
                summary_reason = source.provenance.get("summary_reason")
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
                            else summary_reason
                            if isinstance(summary_reason, str)
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
                    summary_reason = target.provenance.get("summary_reason")
                    incomplete_reason = (
                        join.reason
                        if not join.complete
                        else summary_reason
                        if isinstance(summary_reason, str)
                        else "concrete target ordering is incomplete"
                    )
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
                                else incomplete_reason
                            ),
                        )
                    )

    # GOMP_parallel 本身不会写应用对象，但返回前会等待 callback 完成。
    # 把并行区入口和出口接到同一个 worker role，才能把主线程发布的
    # 初始化和 barrier 后的读取放进同一条 happens-before 链；若 callback
    # 或父角色不闭合，则不生成一条看似完整的边。
    for parallel in threads.parallel_regions:
        if not parallel.complete:
            continue
        barrier_events = by_pc_kind.get(
            (parallel.call_site.pc, EventKind.BARRIER), ()
        )
        worker_events = by_role.get(parallel.worker_role, ())
        if not barrier_events or not worker_events:
            continue
        entries = [event for event in worker_events if event.id not in incoming]
        exits = [event for event in worker_events if event.id not in outgoing]
        for barrier in barrier_events:
            for entry in entries:
                edges.append(
                    SynchronizationEdge(
                        source_event=barrier.id,
                        target_event=entry.id,
                        kind="openmp_parallel_start",
                        evidence=(
                            "GOMP_parallel callback target is closed",
                            "GOMP_parallel return is an implicit worker barrier",
                        ),
                        complete=barrier.target_ordering != Ordering.UNKNOWN,
                        reason=(
                            None
                            if barrier.target_ordering != Ordering.UNKNOWN
                            else "OpenMP barrier ordering is unknown"
                        ),
                    )
                )
            for exit_event in exits:
                edges.append(
                    SynchronizationEdge(
                        source_event=exit_event.id,
                        target_event=barrier.id,
                        kind="openmp_parallel_end",
                        evidence=(
                            "GOMP_parallel callback target is closed",
                            "worker exit precedes the implicit barrier return",
                        ),
                        complete=barrier.target_ordering != Ordering.UNKNOWN,
                        reason=(
                            None
                            if barrier.target_ordering != Ordering.UNKNOWN
                            else "OpenMP barrier ordering is unknown"
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
            + proof_counts[ProofReason.SEQUENTIAL_AFTER_JOIN]
            + proof_counts[ProofReason.SEQUENTIAL_MAIN_CALLEE]
            + proof_counts[ProofReason.NON_RETURNING_PATH]
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
