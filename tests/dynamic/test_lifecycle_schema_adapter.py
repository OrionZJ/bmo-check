from __future__ import annotations

import pytest

from bmo_check_core import (
    AbstractObjectId,
    CompletenessStatus,
    FunctionId,
    InstructionId,
    LifecycleContextId,
    LifecycleOperationId,
    ModuleId,
    ObjectOrigin,
    SyncOperationKind,
    ThreadInstanceId,
    ThreadOrigin,
    TraceId,
)
from bmo_check_dynamic.analysis import (
    LifecycleMetadataError,
    lifecycle_metadata_to_ledger,
)
from bmo_check_dynamic.model import (
    TraceLifecycleJoin,
    TraceLifecycleMetadata,
    TraceLifecycleRecord,
    TraceSynchronizationRecord,
)


HASH = "a" * 64
CONTRACT = "b" * 64


def _complete_metadata() -> tuple[TraceLifecycleMetadata, ThreadInstanceId, ThreadInstanceId]:
    module = ModuleId.from_parts(HASH, "executable")
    trace = TraceId.from_parts("1.2", HASH, (module,), ("complete",), "c" * 64)
    main = ThreadInstanceId.from_parts(trace, 1)
    worker = ThreadInstanceId.from_parts(trace, 2)
    main_fn = FunctionId.from_parts(module, 0x100)
    worker_fn = FunctionId.from_parts(module, 0x200)
    context = LifecycleContextId.from_parts(
        main_fn,
        InstructionId.from_parts(module, 0x150),
        (worker_fn,),
    )

    def operation(kind: str, offset: int, occurrence: str) -> LifecycleOperationId:
        return LifecycleOperationId.from_parts(
            trace,
            kind,
            InstructionId.from_parts(module, offset),
            context if kind == "create" else None,
            occurrence,
        )

    complete = CompletenessStatus.COMPLETE
    records = (
        TraceLifecycleRecord(
            operation_id=operation("start", 0x100, "main-start").value,
            kind="start",
            origin=ThreadOrigin.ROOT,
            thread_instance_id=main.value,
            completeness=complete,
            reason=None,
        ),
        TraceLifecycleRecord(
            operation_id=operation("end", 0x101, "main-end").value,
            kind="end",
            origin=ThreadOrigin.ROOT,
            thread_instance_id=main.value,
            completeness=complete,
            reason=None,
        ),
    )
    worker_records = tuple(
        TraceLifecycleRecord(
            operation_id=operation(kind, offset, f"worker-{kind}").value,
            kind=kind,
            origin=ThreadOrigin.CREATED,
            thread_instance_id=worker.value,
            parent_thread_instance_id=main.value,
            handle_token="slot:0",
            handle_generation=1,
            callback_context_id=context.value,
            callback_target_ids=(worker_fn.value,),
            completeness=complete,
            reason=None,
        )
        for kind, offset in (("create", 0x300), ("start", 0x301), ("end", 0x302))
    )
    join = TraceLifecycleJoin(
        operation_id=operation("join", 0x400, "join-worker").value,
        caller_thread_instance_id=main.value,
        handle_token="slot:0",
        handle_generation=1,
        candidate_thread_instance_ids=(worker.value,),
        target_thread_instance_id=worker.value,
        completeness=complete,
        reason=None,
    )
    object_id = AbstractObjectId.from_parts(ObjectOrigin.ALLOCATION, "futex@0x5000")
    synchronization = TraceSynchronizationRecord(
        operation_id=operation("futex_wait", 0x500, "wait").value,
        kind=SyncOperationKind.FUTEX_WAIT,
        sync_object_id=object_id.value,
        contract_digest=CONTRACT,
        contract_rule="futex.wait.v1",
        completeness=complete,
        reason=None,
    )
    return (
        TraceLifecycleMetadata(
            trace_id=trace.value,
            thread_universe=(main.value, worker.value),
            records=records + worker_records,
            joins=(join,),
            synchronizations=(synchronization,),
            completeness=complete,
            reason=None,
        ),
        main,
        worker,
    )


def test_complete_sidecar_round_trips_to_core_handle_and_callback_identity() -> None:
    metadata, _main, worker = _complete_metadata()

    ledger = lifecycle_metadata_to_ledger(metadata)

    assert ledger.completeness.status is CompletenessStatus.COMPLETE
    handle = next(record.handle_id for record in ledger.records if record.thread_id == worker)
    assert handle is not None
    assert ledger.resolve_handle(handle).target_thread == worker
    worker_record = next(record for record in ledger.records if record.thread_id == worker)
    assert len(worker_record.callback_targets) == 1
    assert ledger.joins[0].target_thread == worker
    assert ledger.synchronizations[0].contract_rule == "futex.wait.v1"


def test_incomplete_sidecar_keeps_missing_thread_universe_visible() -> None:
    metadata, main, worker = _complete_metadata()
    partial = metadata.model_copy(
        update={
            "records": (metadata.records[2],),
            "joins": (),
            "synchronizations": (),
            "completeness": CompletenessStatus.INCOMPLETE,
            "reason": "main lifecycle records were not imported",
        }
    )

    ledger = lifecycle_metadata_to_ledger(partial)

    assert ledger.completeness.status is CompletenessStatus.INCOMPLETE
    assert ledger.missing_thread_ids == (main,)
    assert worker in {record.thread_id for record in ledger.records}


def test_unknown_schema_major_is_rejected_without_downgrade() -> None:
    metadata, _main, _worker = _complete_metadata()
    future = metadata.model_copy(update={"schema_version": "3.0"})

    with pytest.raises(LifecycleMetadataError, match="unsupported lifecycle schema"):
        lifecycle_metadata_to_ledger(future)
