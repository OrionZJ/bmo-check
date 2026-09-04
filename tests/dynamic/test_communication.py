from pathlib import Path

from bmo_check_dynamic.analysis import find_communication_edges
from bmo_check_dynamic.analysis.windows import _biconnected_components, build_windows
from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent
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


def test_window_omits_noncommunicating_memory_but_keeps_boundary(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.LOAD, 0x9000, 4),
        TraceEvent(1, 3, 0, 0x12, EventKind.MFENCE),
        TraceEvent(1, 4, 0, 0x13, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.LOAD, 0x2000, 4),
    )
    with TraceStore(tmp_path / "minimal-window.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=3)
        edges = tuple(find_communication_edges(store))
        windows, unknowns = build_windows(store, edges, max_events=10)

    assert not unknowns
    assert len(windows) == 1
    assert {event.event_id for event in windows[0].events} == {
        "t1:e1",
        "t1:e3",
        "t1:e4",
        "t2:e1",
        "t2:e2",
    }


def test_articulation_chain_is_split_into_independent_windows(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
        TraceEvent(3, 1, 0, 0x30, EventKind.LOAD, 0x2000, 4),
    )
    with TraceStore(tmp_path / "articulation.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=4)
        edges = tuple(find_communication_edges(store))
        windows, unknowns = build_windows(store, edges, max_events=3)

    assert not unknowns
    assert len(windows) == 2
    assert all(len(window.events) == 2 for window in windows)


def test_tls_addresses_are_private_to_each_thread(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x7000, 8, flags=EventFlags.TLS),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x7000, 8, flags=EventFlags.TLS),
    )
    with TraceStore(tmp_path / "tls.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=2)
        assert store.materialize_objects() == 2
        assert not tuple(find_communication_edges(store))


def test_communication_limit_is_applied_inside_query(tmp_path: Path) -> None:
    events = tuple(
        TraceEvent(thread, sequence, 0, 0x10, EventKind.STORE, 0x1000, 4)
        for thread in (1, 2)
        for sequence in range(1, 6)
    )
    with TraceStore(tmp_path / "edge-limit.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=4)
        assert len(tuple(find_communication_edges(store, limit=3))) == 3


def test_biconnected_split_handles_deep_graph_without_python_recursion() -> None:
    graph: dict[str, set[str]] = {}
    for index in range(2_500):
        node = str(index)
        graph.setdefault(node, set())
        if index:
            previous = str(index - 1)
            graph[node].add(previous)
            graph[previous].add(node)
    assert len(_biconnected_components(graph)) == 2_499
