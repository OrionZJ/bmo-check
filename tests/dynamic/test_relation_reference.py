from itertools import product

from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.proof.relations import (
    source_preserved_order,
    target_preserved_order,
)


KINDS = (
    EventKind.LOAD,
    EventKind.STORE,
    EventKind.LFENCE,
    EventKind.SFENCE,
    EventKind.MFENCE,
    EventKind.ATOMIC_RMW,
)


def _events(kinds):
    return tuple(
        TraceEvent(
            1,
            sequence,
            0,
            0x100 + sequence,
            kind,
            0x1000 + (sequence % 2) * 4 if kind.is_memory else 0,
            4 if kind.is_memory else 0,
        )
        for sequence, kind in enumerate(kinds, 1)
    )


def _boundary_pairs(events):
    pairs = set()
    for index, boundary in enumerate(events):
        if boundary.kind == EventKind.ATOMIC_RMW:
            pairs.update(
                (left.event_id, boundary.event_id)
                for left in events[:index]
                if left.kind.is_memory
            )
            pairs.update(
                (boundary.event_id, right.event_id)
                for right in events[index + 1 :]
                if right.kind.is_memory
            )
            continue
        if boundary.kind == EventKind.MFENCE:
            accepts = lambda event: event.kind.is_memory
        elif boundary.kind == EventKind.LFENCE:
            accepts = lambda event: event.kind.is_read
        elif boundary.kind == EventKind.SFENCE:
            accepts = lambda event: event.kind.is_write
        else:
            continue
        pairs.update(
            (left.event_id, right.event_id)
            for left in events[:index]
            if accepts(left)
            for right in events[index + 1 :]
            if accepts(right)
        )
    return pairs


def _dense_source(events):
    memory = [event for event in events if event.kind.is_memory]
    pairs = {
        (left.event_id, right.event_id)
        for index, left in enumerate(memory)
        for right in memory[index + 1 :]
        if not (left.kind.is_write and right.kind.is_read)
    }
    return pairs | _boundary_pairs(events)


def _dense_target(events):
    memory = [event for event in events if event.kind.is_memory]
    pairs = {
        (left.event_id, right.event_id)
        for index, left in enumerate(memory)
        for right in memory[index + 1 :]
        if right.kind.is_write and left.overlaps(right)
    }
    return pairs | _boundary_pairs(events)


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


def _assert_same_memory_reachability(events, compact, dense):
    memory = [event.event_id for event in events if event.kind.is_memory]
    for source in memory:
        for target in memory:
            if source == target:
                continue
            assert _reachable(compact, source, target) == _reachable(
                dense, source, target
            ), tuple(event.kind.name for event in events)


def test_compact_relations_match_independent_dense_reference():
    for length in range(1, 5):
        for kinds in product(KINDS, repeat=length):
            events = _events(kinds)
            _assert_same_memory_reachability(
                events, source_preserved_order(events), _dense_source(events)
            )
            _assert_same_memory_reachability(
                events, target_preserved_order(events), _dense_target(events)
            )
