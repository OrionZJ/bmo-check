from pathlib import Path

from bmo_check_dynamic.analysis import analyze_application_partition
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.storage import TraceStore


def _events(second_output: int) -> tuple[TraceEvent, ...]:
    return (
        TraceEvent(1, 1, 1, 0, EventKind.THREAD_START),
        TraceEvent(1, 2, 2, 0x1010, EventKind.STORE, 0x4000, 4),
        TraceEvent(1, 3, 3, 0, EventKind.THREAD_CREATE),
        TraceEvent(2, 1, 4, 0, EventKind.THREAD_START),
        TraceEvent(2, 2, 4, 0x1020, EventKind.LOAD, 0x4000, 4),
        TraceEvent(2, 3, 4, 0x1024, EventKind.STORE, 0x5000, 4),
        TraceEvent(3, 1, 5, 0, EventKind.THREAD_START),
        TraceEvent(3, 2, 5, 0x1020, EventKind.LOAD, 0x4000, 4),
        TraceEvent(3, 3, 5, 0x1024, EventKind.STORE, second_output, 4),
        TraceEvent(2, 4, 8, 0, EventKind.THREAD_END),
        TraceEvent(3, 4, 9, 0, EventKind.THREAD_END),
        TraceEvent(1, 4, 10, 0x1030, EventKind.LOAD, 0x5000, 4),
        TraceEvent(1, 5, 11, 0, EventKind.THREAD_END),
    )


def _module_file(tmp_path: Path) -> Path:
    path = tmp_path / "modules.tsv"
    path.write_text("0x1000\t0x2000\t/app/program\n", encoding="utf-8")
    return path


def test_readonly_input_and_disjoint_worker_outputs_close_partition(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "safe.duckdb") as store:
        store.add_events(_events(0x5004), max_pages_per_access=16, batch_size=5)
        evidence = analyze_application_partition(
            store, _module_file(tmp_path), "/app/program"
        )
    assert evidence.status == "safe"
    assert evidence.worker_conflicting_ranges == 0
    assert evidence.concurrent_main_conflicts == 0
    assert evidence.readonly_shared_ranges == 1


def test_overlapping_worker_output_keeps_partition_unknown(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "overlap.duckdb") as store:
        store.add_events(_events(0x5000), max_pages_per_access=16, batch_size=5)
        evidence = analyze_application_partition(
            store, _module_file(tmp_path), "/app/program"
        )
    assert evidence.status == "unknown"
    assert evidence.worker_conflicting_ranges == 1


def test_single_complete_thread_has_no_application_communication(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "single.duckdb") as store:
        store.add_events(
            (
                TraceEvent(1, 1, 1, 0, EventKind.THREAD_START),
                TraceEvent(1, 2, 2, 0x1010, EventKind.STORE, 0x4000, 4),
                TraceEvent(1, 3, 3, 0, EventKind.THREAD_END),
            ),
            max_pages_per_access=16,
            batch_size=5,
        )
        evidence = analyze_application_partition(
            store, _module_file(tmp_path), "/app/program"
        )
    assert evidence.status == "safe"
    assert evidence.main_thread == 1
    assert evidence.worker_threads == ()
