"""把 versioned lifecycle sidecar 严格转换为 core LifecycleLedger。"""

from __future__ import annotations

from collections import defaultdict

from bmo_check_core import (
    AbstractObjectId,
    CompletenessState,
    CompletenessStatus,
    FunctionId,
    LifecycleContextId,
    LifecycleJoinRelation,
    LifecycleKind,
    LifecycleLedger,
    LifecycleOperationId,
    SyncOperationKind,
    SynchronizationIdentity,
    ThreadHandleId,
    ThreadInstanceId,
    ThreadLifecycleRecord,
    ThreadOrigin,
    TraceId,
)
from bmo_check_dynamic.model import TraceLifecycleMetadata


class LifecycleMetadataError(ValueError):
    """sidecar 缺少 core 无法安全表达的身份或版本信息。"""


def _parse(name: str, value: str, parser):
    try:
        return parser.from_value(value)
    except (TypeError, ValueError) as error:
        raise LifecycleMetadataError(f"invalid {name}: {value!r}") from error


def _state(
    status: CompletenessStatus,
    scope: str,
    reason: str | None,
) -> CompletenessState:
    if status is CompletenessStatus.COMPLETE:
        if reason is not None:
            raise LifecycleMetadataError("complete lifecycle item carries a reason")
        return CompletenessState(status, scope)
    if not reason:
        raise LifecycleMetadataError("incomplete lifecycle item has no reason")
    return CompletenessState(status, scope, reason=reason)


def _handle(
    trace_id: TraceId,
    token: str | None,
    generation: int | None,
) -> ThreadHandleId | None:
    if token is None and generation is None:
        return None
    if token is None or generation is None:
        raise LifecycleMetadataError("handle token and generation are not paired")
    try:
        return ThreadHandleId.from_parts(trace_id, token, generation)
    except ValueError as error:
        raise LifecycleMetadataError("invalid thread handle identity") from error


def _record_group(
    trace_id: TraceId,
    thread_id: ThreadInstanceId,
    records,
    scope: str,
    force_incomplete_reason: str | None = None,
) -> ThreadLifecycleRecord:
    origins = {record.origin for record in records}
    if len(origins) != 1:
        raise LifecycleMetadataError(
            f"thread {thread_id.value} has conflicting lifecycle origins"
        )
    parents = {
        _parse("parent thread", record.parent_thread_instance_id, ThreadInstanceId)
        for record in records
        if record.parent_thread_instance_id is not None
    }
    if len(parents) > 1:
        raise LifecycleMetadataError(
            f"thread {thread_id.value} has conflicting parent identities"
        )
    handles = {
        _handle(trace_id, record.handle_token, record.handle_generation)
        for record in records
        if record.handle_token is not None
    }
    if len(handles) > 1:
        raise LifecycleMetadataError(
            f"thread {thread_id.value} has conflicting handle generations"
        )
    contexts = {
        _parse("callback context", record.callback_context_id, LifecycleContextId)
        for record in records
        if record.callback_context_id is not None
    }
    if len(contexts) > 1:
        raise LifecycleMetadataError(
            f"thread {thread_id.value} has conflicting callback contexts"
        )
    target_sets = {
        tuple(record.callback_target_ids)
        for record in records
        if record.callback_target_ids
    }
    callback_targets = ()
    callback_targets_complete = len(target_sets) <= 1
    if target_sets:
        callback_targets = tuple(
            _parse("callback target", value, FunctionId)
            for value in next(iter(target_sets))
        )
    if not callback_targets_complete:
        callback_targets = tuple(
            sorted(
                {
                    value
                    for target_set in target_sets
                    for value in target_set
                }
            )
        )
        callback_targets = tuple(
            _parse("callback target", value, FunctionId)
            for value in callback_targets
        )

    by_kind: dict[LifecycleKind, object] = {}
    for record in records:
        if record.kind in by_kind:
            raise LifecycleMetadataError(
                f"thread {thread_id.value} has duplicate {record.kind.value} operation"
            )
        by_kind[record.kind] = record
    operations: dict[LifecycleKind, LifecycleOperationId] = {
        kind: _parse(
            f"{kind.value} operation",
            record.operation_id,
            LifecycleOperationId,
        )
        for kind, record in by_kind.items()
    }
    statuses = [record.completeness for record in records]
    complete = force_incomplete_reason is None and callback_targets_complete and all(
        status is CompletenessStatus.COMPLETE for status in statuses
    )
    reason = None
    if not complete:
        reason = force_incomplete_reason or (
            "callback target candidates differ"
            if not callback_targets_complete
            else next(
                record.reason
                for record in records
                if record.completeness is not CompletenessStatus.COMPLETE
            )
        )
    return ThreadLifecycleRecord(
        thread_id=thread_id,
        origin=next(iter(origins)),
        parent_thread_id=next(iter(parents)) if parents else None,
        handle_id=next(iter(handles)) if handles else None,
        create_operation=operations.get(LifecycleKind.CREATE),
        start_operation=operations.get(LifecycleKind.START),
        end_operation=operations.get(LifecycleKind.END),
        callback_context=next(iter(contexts)) if contexts else None,
        callback_targets=callback_targets,
        completeness=_state(
            CompletenessStatus.COMPLETE if complete else CompletenessStatus.INCOMPLETE,
            scope,
            reason,
        ),
    )


def lifecycle_metadata_to_ledger(
    metadata: TraceLifecycleMetadata,
    *,
    scope: str = "dynamic.trace.lifecycle-import",
) -> LifecycleLedger:
    """严格读取 v2 sidecar；旧/未知 major 版本直接拒绝。"""

    if not isinstance(metadata, TraceLifecycleMetadata):
        raise LifecycleMetadataError("metadata must be TraceLifecycleMetadata")
    if metadata.schema_version.split(".", 1)[0] != "2":
        raise LifecycleMetadataError(
            f"unsupported lifecycle schema major: {metadata.schema_version}"
        )
    trace_id = _parse("trace id", metadata.trace_id, TraceId)
    thread_ids = tuple(
        _parse("thread universe entry", value, ThreadInstanceId)
        for value in metadata.thread_universe
    )
    grouped = defaultdict(list)
    for record in metadata.records:
        thread_id = _parse("record thread", record.thread_instance_id, ThreadInstanceId)
        grouped[thread_id].append(record)
    records = tuple(
        _record_group(
            trace_id,
            thread_id,
            grouped[thread_id],
            scope,
            force_incomplete_reason=(
                metadata.reason
                if metadata.completeness is not CompletenessStatus.COMPLETE
                else None
            ),
        )
        for thread_id in sorted(grouped, key=lambda item: item.value)
    )

    joins: list[LifecycleJoinRelation] = []
    for relation in metadata.joins:
        handle = _handle(trace_id, relation.handle_token, relation.handle_generation)
        joins.append(
            LifecycleJoinRelation(
                operation_id=_parse("join operation", relation.operation_id, LifecycleOperationId),
                caller_thread_id=_parse(
                    "join caller", relation.caller_thread_instance_id, ThreadInstanceId
                ),
                handle_id=handle,
                candidate_threads=tuple(
                    _parse("join candidate", value, ThreadInstanceId)
                    for value in relation.candidate_thread_instance_ids
                ),
                target_thread=(
                    _parse("join target", relation.target_thread_instance_id, ThreadInstanceId)
                    if relation.target_thread_instance_id is not None
                    else None
                ),
                completeness=_state(relation.completeness, scope, relation.reason),
            )
        )

    synchronizations: list[SynchronizationIdentity] = []
    for record in metadata.synchronizations:
        object_id = (
            _parse("synchronization object", record.sync_object_id, AbstractObjectId)
            if record.sync_object_id is not None
            else None
        )
        synchronizations.append(
            SynchronizationIdentity(
                operation_id=_parse("synchronization operation", record.operation_id, LifecycleOperationId),
                kind=record.kind,
                sync_object=object_id,
                contract_digest=record.contract_digest,
                contract_rule=record.contract_rule,
                completeness=_state(record.completeness, scope, record.reason),
            )
        )

    return LifecycleLedger(
        subject=trace_id,
        thread_universe=thread_ids,
        records=records,
        joins=tuple(joins),
        synchronizations=tuple(synchronizations),
        completeness=_state(metadata.completeness, scope, metadata.reason),
    )


__all__ = ["LifecycleMetadataError", "lifecycle_metadata_to_ledger"]
