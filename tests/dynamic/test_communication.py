from pathlib import Path

from bmo_check_dynamic.analysis import find_communication_edges
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.storage import TraceStore


def test_only_cross_thread_overlapping_write_forms_edge(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 8),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1004, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.LOAD, 0x2000, 4),
        TraceEvent(3, 1, 0, 0x30, EventKind.LOAD, 0x2000, 4),
    )
    with TraceStore(tmp_path / "trace.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=2)
        edges = tuple(find_communication_edges(store))
    assert len(edges) == 1
    assert edges[0].address == 0x1004
    assert edges[0].size == 4


def test_reused_heap_address_does_not_connect_generations(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 1, 0, EventKind.ALLOC, 0x1000, 16),
        TraceEvent(1, 2, 2, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(1, 3, 3, 0, EventKind.FREE, 0x1000),
        TraceEvent(1, 4, 4, 0, EventKind.ALLOC, 0x1000, 16),
        TraceEvent(2, 1, 5, 0x20, EventKind.LOAD, 0x1000, 4),
    )
    with TraceStore(tmp_path / "reuse.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=10)
        assert store.materialize_objects() == 2
        assert not tuple(find_communication_edges(store))


def test_single_thread_skips_communication_join(tmp_path: Path) -> None:
    events = tuple(
        TraceEvent(1, sequence, 0, 0x10, EventKind.STORE, 0x1000, 4)
        for sequence in range(1, 101)
    )
    with TraceStore(tmp_path / "single-thread.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=17)
        assert store.thread_count() == 1
        assert not tuple(find_communication_edges(store))
