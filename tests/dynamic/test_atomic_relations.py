import pytest

from bmo_check_dynamic.analysis import AnalysisWindow, CommunicationEdge
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.proof import check_window
from bmo_check_dynamic.proof.checker import (
    _atomic_read_from_valid,
    _communication_relations,
)
from bmo_check_dynamic.proof.relations import (
    source_preserved_order,
    target_preserved_order,
)


def test_initial_read_has_from_read_edges_at_every_location():
    x = TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4)
    y = TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x2000, 4)
    read = TraceEvent(3, 1, 0, 0x30, EventKind.LOAD, 0x1000, 4)
    edges, _ = _communication_relations(
        ((read, None),), (), {(0x1000, 4): (x,), (0x2000, 4): (y,)}, (x, y)
    )
    assert (read.event_id, x.event_id) in edges


def test_internal_read_from_does_not_block_store_forwarding():
    store = TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4)
    local_read = TraceEvent(1, 2, 0, 0x20, EventKind.LOAD, 0x1000, 4)
    remote_read = TraceEvent(2, 1, 0, 0x30, EventKind.LOAD, 0x1000, 4)
    writes = {(0x1000, 4): (store,)}

    local_edges, _ = _communication_relations(
        ((local_read, store),), (), writes, (store,)
    )
    remote_edges, _ = _communication_relations(
        ((remote_read, store),), (), writes, (store,)
    )

    assert (store.event_id, local_read.event_id) not in local_edges
    assert (store.event_id, remote_read.event_id) in remote_edges


def test_same_address_store_to_load_is_preserved_in_both_models():
    store = TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4)
    load = TraceEvent(1, 2, 0, 0x20, EventKind.LOAD, 0x1000, 4)
    events = (store, load)
    assert (store.event_id, load.event_id) in source_preserved_order(events)
    assert (store.event_id, load.event_id) in target_preserved_order(events)


def test_rmw_is_not_its_own_from_read_successor():
    atomic = TraceEvent(1, 1, 0, 0x10, EventKind.ATOMIC_RMW, 0x1000, 4)
    edges, _ = _communication_relations(
        ((atomic, None),), (), {(0x1000, 4): (atomic,)}, (atomic,)
    )
    assert (atomic.event_id, atomic.event_id) not in edges


def test_rmw_must_read_immediate_coherence_predecessor():
    first = TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4)
    second = TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 4)
    atomic = TraceEvent(3, 1, 0, 0x30, EventKind.ATOMIC_RMW, 0x1000, 4)
    coherence = ((first, second), (second, atomic))
    assert not _atomic_read_from_valid(((atomic, first),), coherence)
    assert not _atomic_read_from_valid(((atomic, None),), coherence)
    assert _atomic_read_from_valid(((atomic, second),), coherence)


@pytest.mark.parametrize("budget", [1, 100])
def test_unrelated_atomic_cannot_hide_load_buffering_candidate(budget):
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x1000, 4),
        TraceEvent(3, 1, 0, 0x30, EventKind.ATOMIC_RMW, 0x3000, 4),
    )
    result = check_window(AnalysisWindow("atomic-lb", events, (
        CommunicationEdge("t1:e1", "t2:e2", 0x1000, 4),
        CommunicationEdge("t1:e2", "t2:e1", 0x2000, 4),
    )), max_executions=budget, control_flow_closed=False)
    assert result.status == "unknown"
    assert result.witness is not None
