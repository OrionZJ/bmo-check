from pathlib import Path

import pytest

from bmo_check_dynamic.analysis.communication import CommunicationLimitError

from bmo_check_dynamic.analysis import (
    CompactCommunicationEdges,
    CommunicationEndpoint,
    CommunicationScanStats,
    find_communication_edges,
    max_communication_page_events,
)
from bmo_check_dynamic.analysis.windows import (
    _biconnected_components,
    _group_edges_by_component,
    _minimal_boundaries,
    build_windows,
    WindowInclusionReason,
)
from bmo_check_dynamic.analysis.communication import CommunicationEdge
from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent
from bmo_check_dynamic.storage import TraceStore


def test_only_cross_thread_overlapping_write_forms_edge(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 8),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1004, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.LOAD, 0x2000, 4),
        TraceEvent(3, 1, 0, 0x30, EventKind.LOAD, 0x2000, 4),
    )
    stats = CommunicationScanStats()
    with TraceStore(tmp_path / "trace.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=2)
        edges = tuple(find_communication_edges(store, stats=stats))
    assert len(edges) == 1
    assert edges[0].address == 0x1004
    assert edges[0].size == 4
    assert edges[0].first_endpoint == CommunicationEndpoint(
        "t1:e1", 1, 1, EventKind.STORE
    )
    assert edges[0].second_endpoint == CommunicationEndpoint(
        "t2:e1", 2, 1, EventKind.LOAD
    )
    assert stats.candidate_page_count == 1
    assert stats.candidate_event_count == 2
    assert stats.scanned_event_count == 2
    assert stats.filtered_event_count == 2
    assert stats.filtered_event_reasons == {"not_candidate_page": 2}


def test_compact_edge_sink_preserves_edge_and_window_facts(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 1, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 1, 2, 0x20, EventKind.LOAD, 0x1000, 4),
    )
    with TraceStore(tmp_path / "compact-edge-sink.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=2)
        compact = CompactCommunicationEdges()
        assert not tuple(find_communication_edges(store, edge_sink=compact))
        assert compact.edge_count == 1
        assert compact.node_count == 2
        assert compact.edge(0) == CommunicationEdge(
            "t1:e1", "t2:e1", 0x1000, 4
        )

        windows, unknowns = build_windows(store, compact, max_events=4)

    assert not unknowns
    assert len(windows) == 1
    assert {event.event_id for event in windows[0].events} == {
        "t1:e1",
        "t2:e1",
    }


def test_edge_sweep_preserves_rmw_futex_and_page_boundary_edges(
    tmp_path: Path,
) -> None:
    events = (
        TraceEvent(1, 1, 1, 0x10, EventKind.LOAD, 0x1FFC, 8),
        TraceEvent(2, 1, 2, 0x20, EventKind.LOAD, 0x1FFC, 4),
        TraceEvent(2, 2, 3, 0x21, EventKind.STORE, 0x2000, 4),
        TraceEvent(3, 1, 4, 0x30, EventKind.ATOMIC_RMW, 0x1FFC, 8),
        TraceEvent(4, 1, 5, 0x40, EventKind.FUTEX_WAIT, 0x1FFC, 4),
    )

    with TraceStore(tmp_path / "indexed-edge-sweep.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=8)

        edges = set(find_communication_edges(store))

    assert edges == {
        CommunicationEdge("t1:e1", "t3:e1", 0x1FFC, 8),
        CommunicationEdge("t1:e1", "t2:e2", 0x2000, 4),
        CommunicationEdge("t2:e1", "t3:e1", 0x1FFC, 4),
        CommunicationEdge("t2:e2", "t3:e1", 0x2000, 4),
        CommunicationEdge("t3:e1", events[4].event_id, 0x1FFC, 4),
    }


def test_same_thread_read_hotspot_does_not_expand_irrelevant_pairs(
    tmp_path: Path,
) -> None:
    read_count = 10_000
    events = tuple(
        TraceEvent(1, sequence, sequence, 0x10, EventKind.LOAD, 0x1000, 4)
        for sequence in range(1, read_count + 1)
    ) + (
        TraceEvent(2, 1, read_count + 1, 0x20, EventKind.STORE, 0x1000, 4),
    )

    with TraceStore(tmp_path / "read-hotspot.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=1_000)

        edges = tuple(find_communication_edges(store, max_active_events=read_count + 2))

    assert len(edges) == read_count


def test_get_events_chunks_ids_and_preserves_global_order(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "bmo_check_dynamic.storage.duckdb_store._EVENT_ID_QUERY_BATCH_SIZE", 2
    )
    events = (
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1004, 4),
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
    )

    with TraceStore(tmp_path / "get-events-batches.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=3)

        selected = store.get_events({"t2:e1", "t1:e2", "t1:e1"})

    assert tuple(event.event_id for event in selected) == (
        "t1:e1",
        "t1:e2",
        "t2:e1",
    )


def test_get_events_uses_bulk_join_for_large_endpoint_sets(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "bmo_check_dynamic.storage.duckdb_store._EVENT_ID_BULK_LOOKUP_THRESHOLD", 2
    )
    monkeypatch.setattr(
        "bmo_check_dynamic.storage.duckdb_store._EVENT_ID_INSERT_BATCH_SIZE", 2
    )
    events = (
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1004, 4),
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
    )

    with TraceStore(tmp_path / "get-events-bulk-join.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=3)
        selected = store.get_events(
            iter(("t2:e1", "missing", "t1:e2", "t1:e1", "t1:e2"))
        )

    assert tuple(event.event_id for event in selected) == (
        "t1:e1",
        "t1:e2",
        "t2:e1",
    )


def test_application_edge_scope_keeps_mixed_edges_and_counts_runtime_only_edges(
    tmp_path: Path,
) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x1100, EventKind.STORE, 0x5000, 4),
        TraceEvent(1, 2, 0, 0x3000, EventKind.STORE, 0x5010, 4),
        TraceEvent(2, 1, 0, 0x3001, EventKind.LOAD, 0x5000, 4),
        TraceEvent(2, 2, 0, 0x3002, EventKind.LOAD, 0x5010, 4),
    )

    with TraceStore(tmp_path / "application-edge-scope.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=4)
        stats = CommunicationScanStats()
        edges = tuple(
            find_communication_edges(
                store,
                required_pc_range=(0x1000, 0x2000),
                edge_pc_range=(0x1000, 0x2000),
                stats=stats,
            )
        )

    assert edges == (CommunicationEdge("t1:e1", "t2:e1", 0x5000, 4),)
    assert stats.total_edges == 2
    assert stats.external_edges == 1
    assert stats.complete


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


def test_direct_munmap_ends_mapping_before_an_overlapping_remap(
    tmp_path: Path,
) -> None:
    arguments = (0x1000, 0x2000, 0, 0, 0, 0)
    events = [
        TraceEvent(1, 1, 1, 0, EventKind.MMAP, 0x1000, 0x2000),
        TraceEvent(1, 2, 4, 0x10, EventKind.STORE, 0x1900, 4),
        TraceEvent(1, 3, 5, 0, EventKind.SYSCALL, aux=11),
    ]
    events.extend(
        TraceEvent(
            1,
            index + 4,
            5,
            0,
            EventKind.SYSCALL_ARG,
            address=arguments[index],
            value=11,
            aux=index,
        )
        for index in range(6)
    )
    events.extend(
        (
            TraceEvent(1, 10, 11, 0, EventKind.SYSCALL_EXIT, value=0, aux=11),
            TraceEvent(1, 11, 20, 0, EventKind.MMAP, 0x1800, 0x2000),
            TraceEvent(2, 1, 21, 0x20, EventKind.LOAD, 0x1900, 4),
        )
    )

    with TraceStore(tmp_path / "overlapping-remap.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=8)
        store.materialize_objects()
        assigned = store.connection.execute(
            "SELECT thread_id, object_id FROM events "
            "WHERE kind IN (1, 2) ORDER BY thread_id"
        ).fetchall()
        edges = tuple(find_communication_edges(store))

    assert assigned[0][1] != assigned[1][1]
    assert not edges


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
    inclusion_reasons = {
        record.event_id: set(record.reasons)
        for record in windows[0].event_inclusions
    }
    assert inclusion_reasons["t1:e1"] == {
        WindowInclusionReason.COMMUNICATION_ENDPOINT
    }
    assert inclusion_reasons["t2:e2"] == {
        WindowInclusionReason.COMMUNICATION_ENDPOINT
    }
    assert inclusion_reasons["t1:e3"] == {
        WindowInclusionReason.ORDERING_BOUNDARY
    }


def test_window_uses_database_fallback_for_edges_without_endpoint_facts(
    tmp_path: Path,
) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
    )
    with TraceStore(tmp_path / "legacy-edge.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=2)
        # 手工构造的边没有扫描器附带的位置事实，窗口构建仍须读取真实事件。
        edge = CommunicationEdge("t1:e1", "t2:e1", 0x1000, 4)
        windows, unknowns = build_windows(store, (edge,), max_events=4)

    assert not unknowns
    assert len(windows) == 1
    assert {event.event_id for event in windows[0].events} == {"t1:e1", "t2:e1"}


def test_oversized_component_stays_unknown_without_loading_all_events(
    tmp_path: Path, monkeypatch
) -> None:
    events = tuple(
        TraceEvent(thread, 1, 0, 0x10 + thread, EventKind.STORE, 0x1000, 4)
        for thread in (1, 2, 3)
    )
    with TraceStore(tmp_path / "oversized-window.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=3)
        edges = tuple(find_communication_edges(store))
        assert len(edges) == 3
        assert all(edge.first_endpoint is not None for edge in edges)
        assert all(edge.second_endpoint is not None for edge in edges)

        def unexpected_event_lookup(_event_ids):
            pytest.fail("over-budget components must not load their full endpoints")

        monkeypatch.setattr(store, "get_events", unexpected_event_lookup)
        windows, unknowns = build_windows(store, edges, max_events=2)

    assert windows == ()
    assert unknowns == ("window-000000 contains at least 3 events, limit is 2",)


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


def test_boundary_chord_is_present_before_biconnected_split(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1000, 8),
        TraceEvent(1, 3, 0, 0x12, EventKind.MFENCE),
        TraceEvent(1, 4, 0, 0x13, EventKind.STORE, 0x1004, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.LOAD, 0x1000, 4),
        TraceEvent(3, 1, 0, 0x30, EventKind.LOAD, 0x1004, 4),
        TraceEvent(3, 2, 0, 0x31, EventKind.LOAD, 0x1004, 4),
    )
    with TraceStore(tmp_path / "boundary-chord.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=8)
        edges = tuple(find_communication_edges(store))
        windows, unknowns = build_windows(store, edges, max_events=20)

    assert not unknowns
    assert len(windows) == 1
    assert EventKind.MFENCE in {event.kind for event in windows[0].events}


def test_tls_label_does_not_hide_actual_address_overlap(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x7000, 8, flags=EventFlags.TLS),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x7000, 8, flags=EventFlags.TLS),
    )
    with TraceStore(tmp_path / "tls.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=2)
        assert store.materialize_objects() == 2
        assert len(tuple(find_communication_edges(store))) == 1


def test_communication_limit_is_applied_inside_query(tmp_path: Path) -> None:
    events = tuple(
        TraceEvent(thread, sequence, 0, 0x10, EventKind.STORE, 0x1000, 4)
        for thread in (1, 2)
        for sequence in range(1, 6)
    )
    with TraceStore(tmp_path / "edge-limit.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=4)
        assert len(tuple(find_communication_edges(store, limit=3))) == 3


def test_required_pc_range_skips_pages_without_application_access(
    tmp_path: Path,
) -> None:
    events = (
        TraceEvent(1, 1, 0, 0x3000, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x4000, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x1100, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 2, 0, 0x4000, EventKind.LOAD, 0x2000, 4),
    )
    with TraceStore(tmp_path / "pc-filter.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=4)
        edges = tuple(find_communication_edges(store, required_pc_range=(0x1000, 0x2000)))
    assert len(edges) == 1
    assert edges[0].address == 0x2000


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


def test_communication_edges_are_grouped_without_rescanning_each_component() -> None:
    count = 10_000
    components = tuple(
        frozenset((f"left-{index}", f"right-{index}"))
        for index in range(count)
    )
    edges = tuple(
        CommunicationEdge(f"left-{index}", f"right-{index}", index * 4, 4)
        for index in range(count)
    )

    grouped, unassigned = _group_edges_by_component(components, edges)

    assert unassigned == 0
    assert len(grouped) == count
    assert all(len(group) == 1 for group in grouped)
    assert tuple(group[0] for group in grouped) == edges


def test_equivalent_boundaries_at_same_endpoint_cut_are_collapsed() -> None:
    endpoints = [
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 100, 0, 0x20, EventKind.STORE, 0x2000, 4),
    ]
    boundaries = tuple(
        TraceEvent(1, sequence, 0, 0x30, EventKind.ATOMIC_RMW, 0x3000, 4)
        for sequence in range(2, 100)
    )
    selected = _minimal_boundaries(endpoints, boundaries)
    assert len(selected) == 1
    assert selected[0].sequence == 2


def test_active_set_limit_covers_readonly_hotspot(tmp_path: Path) -> None:
    events = tuple(
        TraceEvent(1, sequence, 0, 0x10, EventKind.LOAD, 0x1000, 4)
        for sequence in range(1, 10)
    ) + (TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 4),)
    with TraceStore(tmp_path / "active-limit.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=4)
        with pytest.raises(CommunicationLimitError, match="active set"):
            tuple(find_communication_edges(store, max_active_events=3))


def test_page_event_budget_is_computed_before_scan(tmp_path: Path) -> None:
    events = tuple(
        TraceEvent(1, sequence, 0, 0x10, EventKind.LOAD, 0x1000, 4)
        for sequence in range(1, 10)
    ) + (TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 4),)
    with TraceStore(tmp_path / "page-budget.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=4)
        assert max_communication_page_events(store) == 10


def test_thread_create_join_handoff_is_not_a_communication_window(
    tmp_path: Path,
) -> None:
    events = (
        TraceEvent(1, 1, 1, 0x10, EventKind.THREAD_START),
        TraceEvent(1, 2, 2, 0x20, EventKind.STORE, 0x4000, 8),
        TraceEvent(1, 3, 3, 0x25, EventKind.THREAD_CREATE),
        TraceEvent(2, 1, 4, 0x30, EventKind.THREAD_START),
        TraceEvent(2, 2, 5, 0x40, EventKind.LOAD, 0x4000, 8),
        TraceEvent(2, 3, 6, 0x50, EventKind.THREAD_END),
        TraceEvent(1, 4, 7, 0x55, EventKind.THREAD_JOIN),
        TraceEvent(1, 5, 8, 0x60, EventKind.THREAD_END),
    )
    with TraceStore(tmp_path / "initialization.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=16)
        assert tuple(find_communication_edges(store)) == ()


def test_missing_join_keeps_initialization_to_worker_write(tmp_path: Path) -> None:
    events = (
        TraceEvent(1, 1, 1, 0x10, EventKind.THREAD_START),
        TraceEvent(1, 2, 2, 0x20, EventKind.STORE, 0x4000, 8),
        TraceEvent(2, 1, 3, 0x30, EventKind.THREAD_START),
        TraceEvent(2, 2, 4, 0x40, EventKind.STORE, 0x4000, 8),
        TraceEvent(2, 3, 5, 0x50, EventKind.THREAD_END),
        TraceEvent(1, 3, 6, 0x60, EventKind.THREAD_END),
    )
    with TraceStore(tmp_path / "initialization-write.duckdb") as store:
        store.add_events(events, max_pages_per_access=16, batch_size=16)
        assert len(tuple(find_communication_edges(store))) == 1
