"""把旧 TraceEvent 流转换成不完整的生命周期输入视图。

TraceEvent 的 thread_id、sequence、ticket 和 aux 足以定位记录，但不能证明
pthread_t generation、CREATE→START callback 关系或 parent/join 关系。这个
适配器只为 RU4 characterization 服务；它返回 INCOMPLETE/UNSUPPORTED，绝不
把一次运行的观察提升为静态 ProofFact。
"""

from __future__ import annotations

from collections import defaultdict

from bmo_check_core import (
    CompletenessState,
    CompletenessStatus,
    InstructionId,
    LifecycleJoinRelation,
    LifecycleKind,
    LifecycleLedger,
    LifecycleOperationId,
    ModuleId,
    SyncOperationKind,
    SynchronizationIdentity,
    ThreadInstanceId,
    ThreadLifecycleRecord,
    ThreadOrigin,
    TraceId,
)
from bmo_check_dynamic.model import EventKind, TraceEvent


def _incomplete(scope: str, reason: str) -> CompletenessState:
    return CompletenessState(CompletenessStatus.INCOMPLETE, scope, reason=reason)


def _operation(
    trace_id: TraceId,
    event: TraceEvent,
    kind: LifecycleKind | SyncOperationKind,
) -> LifecycleOperationId:
    # 旧 trace 没有 module mapping；trace-local site 只用于定位，不能当 ELF proof。
    module = ModuleId.from_parts(trace_id.digest, "trace-event")
    site = InstructionId.from_parts(module, event.pc)
    return LifecycleOperationId.from_parts(
        trace_id,
        kind.value,
        site,
        None,
        f"trace-event:{event.event_id}",
    )


def characterize_trace_lifecycle(
    events: tuple[TraceEvent, ...],
    trace_id: TraceId,
    *,
    scope: str = "dynamic.trace.legacy-lifecycle",
) -> LifecycleLedger:
    """返回旧 TraceEvent schema 的保守生命周期视图。

    即使事件中出现 ``THREAD_CREATE``/``THREAD_JOIN``，也不读取它们的裸
    address/aux 作为 pthread_t。没有 generation 和 callback/parent correlation
    时，任何 join/HB 结论都必须停在不完整状态。
    """

    if not isinstance(trace_id, TraceId):
        raise ValueError("trace_id must be a TraceId")
    by_thread: dict[int, list[TraceEvent]] = defaultdict(list)
    for event in events:
        if not isinstance(event, TraceEvent):
            raise ValueError("events must contain TraceEvent values")
        by_thread[event.thread_id].append(event)

    records: list[ThreadLifecycleRecord] = []
    for thread_id, thread_events in sorted(by_thread.items()):
        instance = ThreadInstanceId.from_parts(trace_id, thread_id)
        starts = [event for event in thread_events if event.kind is EventKind.THREAD_START]
        ends = [event for event in thread_events if event.kind is EventKind.THREAD_END]
        records.append(
            ThreadLifecycleRecord(
                thread_id=instance,
                # 旧 schema 不携带 root/create 关系；把所有线程标成 external，
                # 并保持不完整，避免按最小 tid 猜主线程。
                origin=ThreadOrigin.EXTERNAL,
                start_operation=(
                    _operation(trace_id, starts[0], LifecycleKind.START)
                    if starts
                    else None
                ),
                end_operation=(
                    _operation(trace_id, ends[-1], LifecycleKind.END)
                    if ends
                    else None
                ),
                completeness=_incomplete(
                    scope,
                    "legacy trace lacks CREATE/START callback and pthread_t generation",
                ),
            )
        )

    joins: list[LifecycleJoinRelation] = []
    synchronizations: list[SynchronizationIdentity] = []
    for event in events:
        caller = ThreadInstanceId.from_parts(trace_id, event.thread_id)
        if event.kind is EventKind.THREAD_JOIN:
            joins.append(
                LifecycleJoinRelation(
                    operation_id=_operation(trace_id, event, LifecycleKind.JOIN),
                    caller_thread_id=caller,
                    # aux/address 可能是实现细节或复用值；没有 generation 就不能建 handle。
                    handle_id=None,
                    completeness=_incomplete(
                        scope,
                        "legacy trace join has no pthread_t generation or target instance",
                    ),
                )
            )
        elif event.kind is EventKind.FUTEX_WAIT:
            synchronizations.append(
                SynchronizationIdentity(
                    operation_id=_operation(trace_id, event, SyncOperationKind.FUTEX_WAIT),
                    kind=SyncOperationKind.FUTEX_WAIT,
                    sync_object=None,
                    completeness=CompletenessState(
                        CompletenessStatus.UNSUPPORTED,
                        scope,
                        reason="legacy trace has no contract-bound futex rule",
                    ),
                )
            )
        elif event.kind in {
            EventKind.SYNC_ACQUIRE,
            EventKind.SYNC_RELEASE,
            EventKind.SYNC_FULL,
            EventKind.SYNC_CALL,
        }:
            synchronizations.append(
                SynchronizationIdentity(
                    operation_id=_operation(
                        trace_id,
                        event,
                        SyncOperationKind.NATIVE_MARKER,
                    ),
                    kind=SyncOperationKind.NATIVE_MARKER,
                    sync_object=None,
                    completeness=CompletenessState(
                        CompletenessStatus.UNSUPPORTED,
                        scope,
                        reason="legacy trace marker has no contract-bound synchronization rule",
                    ),
                )
            )

    reason = "legacy trace lacks lifecycle correlation fields"
    if not events:
        reason = "legacy trace contains no events"
    return LifecycleLedger(
        subject=trace_id,
        thread_universe=tuple(
            ThreadInstanceId.from_parts(trace_id, thread_id)
            for thread_id in sorted(by_thread)
        ),
        records=tuple(records),
        joins=tuple(joins),
        synchronizations=tuple(synchronizations),
        completeness=_incomplete(scope, reason),
    )


__all__ = ["characterize_trace_lifecycle"]
