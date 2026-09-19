from __future__ import annotations

from bmo_check_core import (
    CompletenessStatus,
    ModuleId,
    ThreadInstanceId,
    TraceId,
)
from bmo_check_dynamic.analysis import characterize_trace_lifecycle
from bmo_check_dynamic.model import EventKind, TraceEvent


HASH = "a" * 64


def _trace() -> TraceId:
    return TraceId.from_parts(
        "1.2",
        HASH,
        (ModuleId.from_parts(HASH, "executable"),),
        ("complete",),
        "b" * 64,
    )


def test_legacy_trace_does_not_turn_raw_join_aux_into_a_handle() -> None:
    trace = _trace()
    events = (
        TraceEvent(1, 1, 1, 0x100, EventKind.THREAD_START),
        TraceEvent(1, 2, 2, 0x110, EventKind.THREAD_CREATE, address=2),
        TraceEvent(2, 1, 3, 0x200, EventKind.THREAD_START),
        TraceEvent(2, 2, 4, 0x210, EventKind.THREAD_END),
        TraceEvent(1, 3, 5, 0x120, EventKind.THREAD_JOIN, aux=2),
        TraceEvent(1, 4, 6, 0x130, EventKind.THREAD_END),
    )

    ledger = characterize_trace_lifecycle(events, trace)

    assert ledger.completeness.status is CompletenessStatus.INCOMPLETE
    assert len(ledger.joins) == 1
    assert ledger.joins[0].handle_id is None
    assert ledger.joins[0].target_thread is None
    assert ledger.joins[0].completeness.status is CompletenessStatus.INCOMPLETE
    assert all(
        record.thread_id in {
            ThreadInstanceId.from_parts(trace, 1),
            ThreadInstanceId.from_parts(trace, 2),
        }
        for record in ledger.records
    )


def test_w14_thread_without_start_or_end_stays_in_the_universe() -> None:
    trace = _trace()
    events = (
        TraceEvent(1, 1, 1, 0x100, EventKind.THREAD_START),
        TraceEvent(1, 2, 2, 0x110, EventKind.THREAD_END),
        TraceEvent(2, 1, 3, 0x220, EventKind.LOAD, address=0x4000, size=4),
    )

    ledger = characterize_trace_lifecycle(events, trace)
    worker = next(
        item
        for item in ledger.records
        if item.thread_id == ThreadInstanceId.from_parts(trace, 2)
    )

    assert ledger.missing_thread_ids == ()
    assert worker.start_operation is None
    assert worker.end_operation is None
    assert worker.completeness.status is CompletenessStatus.INCOMPLETE


def test_w4_futex_marker_requires_contract_binding() -> None:
    ledger = characterize_trace_lifecycle(
        (TraceEvent(1, 1, 1, 0x300, EventKind.FUTEX_WAIT, address=0x5000, size=4),),
        _trace(),
    )

    assert len(ledger.synchronizations) == 1
    sync = ledger.synchronizations[0]
    assert sync.contract_digest is None
    assert sync.contract_rule is None
    assert sync.completeness.status is CompletenessStatus.UNSUPPORTED
