from __future__ import annotations

import pytest
from pydantic import ValidationError

from bmo_check_core import (
    CompletenessStatus,
    FunctionId,
    InstructionId,
    LifecycleOperationId,
    ModuleId,
    ThreadInstanceId,
    ThreadOrigin,
    TraceId,
)
from bmo_check_dynamic.model import (
    TraceLifecycleJoin,
    TraceLifecycleMetadata,
    TraceLifecycleRecord,
    TraceSynchronizationRecord,
)
from bmo_check_core import SyncOperationKind


HASH = "a" * 64


def _ids() -> tuple[TraceId, ThreadInstanceId, ThreadInstanceId, LifecycleOperationId]:
    module = ModuleId.from_parts(HASH, "executable")
    trace = TraceId.from_parts("1.2", HASH, (module,), ("complete",), "b" * 64)
    main = ThreadInstanceId.from_parts(trace, 1)
    worker = ThreadInstanceId.from_parts(trace, 2)
    operation = LifecycleOperationId.from_parts(
        trace,
        "start",
        InstructionId.from_parts(module, 0x100),
        None,
        "trace-event:t2:e1",
    )
    return trace, main, worker, operation


def test_incomplete_sidecar_preserves_typed_lifecycle_gap() -> None:
    trace, main, worker, operation = _ids()
    payload = TraceLifecycleMetadata(
        trace_id=trace.value,
        thread_universe=(main.value, worker.value),
        records=(
            TraceLifecycleRecord(
                operation_id=operation.value,
                kind="start",
                origin=ThreadOrigin.CREATED,
                thread_instance_id=worker.value,
                completeness=CompletenessStatus.INCOMPLETE,
                reason="CREATE and handle generation are absent",
            ),
        ),
        completeness=CompletenessStatus.INCOMPLETE,
        reason="legacy trace has no lifecycle correlation fields",
    )

    assert payload.schema_version == "2.0"
    assert payload.records[0].handle_token is None
    assert payload.completeness is CompletenessStatus.INCOMPLETE


def test_lifecycle_universe_allows_multiple_operations_for_one_thread() -> None:
    trace, main, worker, start_operation = _ids()
    module = ModuleId.from_parts(HASH, "executable")
    end_operation = LifecycleOperationId.from_parts(
        trace,
        "end",
        InstructionId.from_parts(module, 0x101),
        None,
        "trace-event:t2:e2",
    )
    payload = TraceLifecycleMetadata(
        trace_id=trace.value,
        thread_universe=(main.value, worker.value),
        records=(
            TraceLifecycleRecord(
                operation_id=start_operation.value,
                kind="start",
                origin=ThreadOrigin.CREATED,
                thread_instance_id=worker.value,
                completeness=CompletenessStatus.INCOMPLETE,
                reason="create relation is not imported",
            ),
            TraceLifecycleRecord(
                operation_id=end_operation.value,
                kind="end",
                origin=ThreadOrigin.CREATED,
                thread_instance_id=worker.value,
                completeness=CompletenessStatus.INCOMPLETE,
                reason="end is not bound to the lifecycle record",
            ),
        ),
        completeness=CompletenessStatus.INCOMPLETE,
        reason="sidecar is a partial import",
    )

    assert tuple(record.thread_instance_id for record in payload.records) == (
        worker.value,
        worker.value,
    )


def test_old_or_partial_payload_cannot_be_treated_as_complete() -> None:
    trace, main, _worker, operation = _ids()
    with pytest.raises(ValidationError, match="complete lifecycle metadata"):
        TraceLifecycleMetadata(
            trace_id=trace.value,
            thread_universe=(main.value,),
            records=(),
            completeness=CompletenessStatus.COMPLETE,
            reason=None,
        )


def test_handle_token_requires_explicit_generation() -> None:
    _trace, _main, worker, operation = _ids()
    with pytest.raises(ValidationError, match="handle_token and handle_generation"):
        TraceLifecycleRecord(
            operation_id=operation.value,
            kind="start",
            origin=ThreadOrigin.CREATED,
            thread_instance_id=worker.value,
            handle_token="pthread:2",
            completeness=CompletenessStatus.INCOMPLETE,
            reason="generation was omitted",
        )


def test_join_and_futex_complete_paths_require_identity_and_contract() -> None:
    trace, main, worker, operation = _ids()
    with pytest.raises(ValidationError, match="complete join requires handle"):
        TraceLifecycleJoin(
            operation_id=operation.value,
            caller_thread_instance_id=main.value,
            candidate_thread_instance_ids=(worker.value,),
            target_thread_instance_id=worker.value,
            completeness=CompletenessStatus.COMPLETE,
            reason=None,
        )
    with pytest.raises(ValidationError, match="complete synchronization requires"):
        TraceSynchronizationRecord(
            operation_id=operation.value,
            kind=SyncOperationKind.FUTEX_WAIT,
            sync_object_id="object:unknown",
            completeness=CompletenessStatus.COMPLETE,
            reason=None,
        )


def test_unknown_wire_fields_are_rejected_instead_of_ignored() -> None:
    trace, main, _worker, _operation_id = _ids()
    with pytest.raises(ValidationError, match="extra_field"):
        TraceLifecycleMetadata(
            trace_id=trace.value,
            thread_universe=(main.value,),
            completeness=CompletenessStatus.INCOMPLETE,
            reason="not imported",
            extra_field=True,
        )
