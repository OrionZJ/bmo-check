from __future__ import annotations

from bmo_check_static.analysis.memory_events import _summary_ordering
from bmo_check_static.binary.capstone_backend import disassemble_bytes
from bmo_check_static.model import (
    Ordering,
    SynchronizationKind,
    SynchronizationReport,
    SynchronizationSummary,
)
from bmo_check_static.synchronization.pthread import _return_path_orderings


def _report(actual: Ordering, required: Ordering) -> SynchronizationReport:
    summary = SynchronizationSummary(
        api="pthread_join",
        kind=SynchronizationKind.THREAD_JOIN,
        required_ordering=required,
        module_path="/lib/libpthread.so.0",
        module_sha256="a" * 64,
        function_pc=0x1000,
        function_size=16,
        return_path_orderings=(actual,),
        target_ordering=actual,
        complete=True,
    )
    return SynchronizationReport(
        contract_version="test",
        library_path=summary.module_path,
        library_sha256=summary.module_sha256,
        summaries=(summary,),
    )


def test_complete_but_weak_summary_does_not_create_sync_boundary() -> None:
    ordering, reason = _summary_ordering(
        "pthread_join", (_report(Ordering.RELAXED, Ordering.ACQUIRE),)
    )

    assert ordering is None
    assert reason == "target Relaxed does not cover required Acquire"


def test_stronger_summary_satisfies_required_direction() -> None:
    assert _summary_ordering(
        "pthread_join", (_report(Ordering.ACQ_REL, Ordering.ACQUIRE),)
    ) == (Ordering.ACQ_REL, None)


def test_syscall_without_dbt_ordering_keeps_summary_incomplete() -> None:
    facts = disassemble_bytes(bytes.fromhex("0f05c3"), address=0x2000)

    orderings, complete, reason, _ = _return_path_orderings(
        facts, 0x2000, 0x2003
    )

    assert orderings == (Ordering.RELAXED,)
    assert not complete
    assert reason is not None
    assert "syscall target ordering is absent" in reason
