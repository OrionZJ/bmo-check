from itertools import combinations

import pytest

from bmo_check_dynamic.analysis import AnalysisWindow, CommunicationEdge
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.proof import check_window
from bmo_check_dynamic.proof.relations import source_preserved_order, target_preserved_order


def _window(name, threads):
    events = tuple(
        TraceEvent(tid, seq, 0, tid * 0x100 + seq, kind, address,
                   4 if kind.is_memory else 0)
        for tid, instructions in enumerate(threads, 1)
        for seq, (kind, address) in enumerate(instructions, 1)
    )
    edges = tuple(
        CommunicationEdge(a.event_id, b.event_id, max(a.address, b.address), 4)
        for a, b in combinations(events, 2)
        if a.thread_id != b.thread_id and a.kind.is_memory and b.kind.is_memory
        and a.overlaps(b) and (a.kind.is_write or b.kind.is_write)
    )
    return AnalysisWindow(name, events, edges)


L, S = EventKind.LOAD, EventKind.STORE
LF, SF, MF = EventKind.LFENCE, EventKind.SFENCE, EventKind.MFENCE
X, Y = 0x1000, 0x2000


@pytest.mark.parametrize("budget", [1, 20_000], ids=["symbolic", "enumeration"])
@pytest.mark.parametrize("name,threads,expected", [
    ("MP", [[(S, X), (S, Y)], [(L, Y), (L, X)]], "unknown"),
    ("MP-fenced", [[(S, X), (SF, 0), (S, Y)],
                   [(L, Y), (LF, 0), (L, X)]], "safe"),
    ("SB", [[(S, X), (L, Y)], [(S, Y), (L, X)]], "safe"),
    ("SB-fenced", [[(S, X), (MF, 0), (L, Y)],
                   [(S, Y), (MF, 0), (L, X)]], "safe"),
    ("LB", [[(L, X), (S, Y)], [(L, Y), (S, X)]], "unknown"),
    ("LB-fenced", [[(L, X), (MF, 0), (S, Y)],
                   [(L, Y), (MF, 0), (S, X)]], "safe"),
    ("IRIW", [[(S, X)], [(S, Y)], [(L, X), (L, Y)],
               [(L, Y), (L, X)]], "unknown"),
    ("IRIW-fenced", [[(S, X)], [(S, Y)], [(L, X), (LF, 0), (L, Y)],
                      [(L, Y), (LF, 0), (L, X)]], "safe"),
])
def test_litmus_inclusion_matrix(name, threads, expected, budget):
    result = check_window(_window(name, threads), max_executions=budget,
                          control_flow_closed=False)
    assert result.status == expected, result.reason
    if expected == "unknown":
        # 候选可说明模型差异，但这些输入没有值/路径证明，不能宣布 COUNTEREXAMPLE。
        assert result.witness is not None
        assert not result.witness.validated


@pytest.mark.parametrize("left,right,preserved", [(L, L, True), (L, S, True),
                                                  (S, S, True), (S, L, False)])
def test_four_plain_program_order_pairs(left, right, preserved):
    events = _window("pair", [[(left, X), (right, Y)]]).events
    edge = (events[0].event_id, events[1].event_id)
    assert (edge in source_preserved_order(events)) == preserved
    assert edge not in target_preserved_order(events)


def _reachable(edges, source, target):
    pending = [source]
    visited = set()
    while pending:
        current = pending.pop()
        if current == target:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(right for left, right in edges if left == current)
    return False


def test_compact_source_order_preserves_non_adjacent_store_order():
    events = _window("store-load-store", [[(S, X), (L, Y), (S, Y)]]).events
    edges = source_preserved_order(events)
    assert _reachable(edges, events[0].event_id, events[2].event_id)
    assert not _reachable(edges, events[0].event_id, events[1].event_id)


def test_target_preserves_overlapping_address_order_before_store():
    events = _window("overlap", [[(L, X), (S, X), (S, X)]]).events
    edges = target_preserved_order(events)
    assert (events[0].event_id, events[1].event_id) in edges
    assert (events[1].event_id, events[2].event_id) in edges


@pytest.mark.parametrize("fence", [LF, SF, MF])
def test_fence_relation_uses_boundary_node_without_changing_reachability(fence):
    events = _window("fence", [[(L, X), (S, Y), (fence, 0), (L, Y), (S, X)]]).events
    source = source_preserved_order(events)
    target = target_preserved_order(events)
    fence_id = events[2].event_id
    assert any(right == fence_id for _left, right in target)
    assert any(left == fence_id for left, _right in target)
    assert all(left != fence_id and right != fence_id for left, right in source - target)
