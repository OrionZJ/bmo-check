from __future__ import annotations

import pytest

from bmo_check_core import (
    BinaryClosureId,
    CompletenessState,
    CompletenessStatus,
    FunctionId,
    InstructionId,
    LifecycleContextId,
    LifecycleJoinRelation,
    LifecycleKind,
    LifecycleLedger,
    LifecycleOperationId,
    LifecycleResolutionStatus,
    ModuleId,
    SyncOperationKind,
    SynchronizationIdentity,
    ThreadHandleId,
    ThreadLifecycleRecord,
    ThreadOrigin,
    ThreadRoleId,
)


HASH = "a" * 64
CONTRACT = "b" * 64


def _fixture() -> tuple[BinaryClosureId, ThreadRoleId, ThreadRoleId, ThreadRoleId]:
    closure = BinaryClosureId.from_parts(HASH, (("executable", HASH),), "x86_64")
    module = ModuleId.from_parts(HASH, "executable")
    main_fn = FunctionId.from_parts(module, 0x100)
    worker_a_fn = FunctionId.from_parts(module, 0x200)
    worker_b_fn = FunctionId.from_parts(module, 0x300)
    return (
        closure,
        ThreadRoleId.from_parts(None, None, (main_fn,)),
        ThreadRoleId.from_parts(None, None, (worker_a_fn,)),
        ThreadRoleId.from_parts(None, None, (worker_b_fn,)),
    )


def _operation(
    subject: BinaryClosureId,
    kind: LifecycleKind | SyncOperationKind,
    offset: int,
    occurrence: str,
    context: LifecycleContextId | None = None,
) -> LifecycleOperationId:
    module = ModuleId.from_parts(HASH, "executable")
    site = InstructionId.from_parts(module, offset)
    return LifecycleOperationId.from_parts(
        subject,
        kind.value,
        site,
        context,
        occurrence,
    )


def _complete_state(scope: str) -> CompletenessState:
    return CompletenessState(CompletenessStatus.COMPLETE, scope)


def test_context_identity_keeps_wrapper_callers_and_callbacks_separate() -> None:
    module = ModuleId.from_parts(HASH, "executable")
    caller_a = FunctionId.from_parts(module, 0x100)
    caller_b = FunctionId.from_parts(module, 0x110)
    call_site = InstructionId.from_parts(module, 0x120)
    callback = FunctionId.from_parts(module, 0x200)

    first = LifecycleContextId.from_parts(caller_a, call_site, (callback,))
    same = LifecycleContextId.from_parts(caller_a, call_site, (callback,))
    different_caller = LifecycleContextId.from_parts(caller_b, call_site, (callback,))

    assert first == same
    assert first != different_caller


def test_handle_generation_changes_identity_when_pthread_t_is_reused() -> None:
    closure, *_ = _fixture()
    first = ThreadHandleId.from_parts(closure, "slot:0", generation=1)
    reused = ThreadHandleId.from_parts(closure, "slot:0", generation=2)

    assert first != reused


def test_w3_join_resolution_uses_handle_not_worker_or_join_order() -> None:
    closure, main, worker_a, worker_b = _fixture()
    handle_a = ThreadHandleId.from_parts(closure, "slot:0", generation=1)
    handle_b = ThreadHandleId.from_parts(closure, "slot:1", generation=1)
    create_a = _operation(closure, LifecycleKind.CREATE, 0x400, "a")
    create_b = _operation(closure, LifecycleKind.CREATE, 0x401, "b")
    start_a = _operation(closure, LifecycleKind.START, 0x200, "a")
    start_b = _operation(closure, LifecycleKind.START, 0x300, "b")
    end_a = _operation(closure, LifecycleKind.END, 0x210, "a")
    end_b = _operation(closure, LifecycleKind.END, 0x310, "b")

    records = (
        ThreadLifecycleRecord(
            thread_id=main,
            origin=ThreadOrigin.ROOT,
            start_operation=_operation(closure, LifecycleKind.START, 0x100, "root"),
            end_operation=_operation(closure, LifecycleKind.END, 0x101, "root"),
            completeness=_complete_state("w3"),
        ),
        ThreadLifecycleRecord(
            thread_id=worker_a,
            origin=ThreadOrigin.CREATED,
            parent_thread_id=main,
            handle_id=handle_a,
            create_operation=create_a,
            start_operation=start_a,
            end_operation=end_a,
            completeness=_complete_state("w3"),
        ),
        ThreadLifecycleRecord(
            thread_id=worker_b,
            origin=ThreadOrigin.CREATED,
            parent_thread_id=main,
            handle_id=handle_b,
            create_operation=create_b,
            start_operation=start_b,
            end_operation=end_b,
            completeness=_complete_state("w3"),
        ),
    )
    joins = (
        LifecycleJoinRelation(
            operation_id=_operation(closure, LifecycleKind.JOIN, 0x500, "b"),
            caller_thread_id=main,
            handle_id=handle_b,
            candidate_threads=(worker_b,),
            target_thread=worker_b,
            completeness=_complete_state("w3"),
        ),
        LifecycleJoinRelation(
            operation_id=_operation(closure, LifecycleKind.JOIN, 0x501, "a"),
            caller_thread_id=main,
            handle_id=handle_a,
            candidate_threads=(worker_a,),
            target_thread=worker_a,
            completeness=_complete_state("w3"),
        ),
    )
    ledger = LifecycleLedger(
        subject=closure,
        thread_universe=(main, worker_a, worker_b),
        records=records,
        joins=joins,
        completeness=_complete_state("w3"),
    )

    assert ledger.resolve_handle(handle_a).status is LifecycleResolutionStatus.RESOLVED
    assert ledger.resolve_handle(handle_a).target_thread == worker_a
    assert ledger.resolve_handle(handle_b).target_thread == worker_b


def test_w14_missing_thread_record_is_visible_and_not_complete() -> None:
    closure, main, worker_a, worker_b = _fixture()
    record = ThreadLifecycleRecord(
        thread_id=main,
        origin=ThreadOrigin.ROOT,
        start_operation=_operation(closure, LifecycleKind.START, 0x100, "root"),
        end_operation=_operation(closure, LifecycleKind.END, 0x101, "root"),
        completeness=_complete_state("w14"),
    )
    ledger = LifecycleLedger(
        subject=closure,
        thread_universe=(main, worker_a, worker_b),
        records=(record,),
        completeness=CompletenessState(
            CompletenessStatus.INCOMPLETE,
            "w14",
            reason="worker lifecycle markers were not recovered",
        ),
    )

    assert ledger.missing_thread_ids == (worker_a, worker_b)
    assert ledger.resolve_handle(
        ThreadHandleId.from_parts(closure, "unknown", generation=1)
    ).status is LifecycleResolutionStatus.INCOMPLETE


def test_w4_futex_without_contract_rule_cannot_be_complete() -> None:
    closure, main, *_ = _fixture()
    operation = _operation(closure, SyncOperationKind.FUTEX_WAIT, 0x600, "wait")

    with pytest.raises(ValueError, match="contract rule"):
        SynchronizationIdentity(
            operation_id=operation,
            kind=SyncOperationKind.FUTEX_WAIT,
            sync_object=main,
            completeness=_complete_state("w4"),
        )

    unknown = SynchronizationIdentity(
        operation_id=operation,
        kind=SyncOperationKind.FUTEX_WAIT,
        sync_object=None,
        completeness=CompletenessState(
            CompletenessStatus.UNSUPPORTED,
            "w4",
            reason="bound contract does not declare futex ordering",
        ),
    )
    assert unknown.completeness.status is CompletenessStatus.UNSUPPORTED
