from bmo_check_static.analysis.lockset import (
    lock_protection_candidates,
    prove_definite_locksets,
)
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    EventKind,
    MemoryEvent,
    Ordering,
    ProgramOrderEdge,
)


def _event(event_id: str, role: str, kind: EventKind, address=None) -> MemoryEvent:
    return MemoryEvent(
        id=event_id,
        module="app",
        module_sha256="a" * 64,
        pc=int(event_id.split("-")[-1], 16),
        kind=kind,
        address=address,
        source_ordering=Ordering.TSO,
        target_ordering=Ordering.RELAXED,
        thread_role=role,
    )


def test_common_concrete_lock_protects_accesses_in_two_roles() -> None:
    lock = AbstractAddress(kind=AddressKind.GLOBAL, base="lock", offset=0)
    data = AbstractAddress(kind=AddressKind.AFFINE, base="array", offset=0)
    events = (
        _event("main-acq-10", "main", EventKind.ACQUIRE, lock),
        _event("main-store-11", "main", EventKind.STORE, data),
        _event("main-rel-12", "main", EventKind.RELEASE, lock),
        _event("worker-acq-20", "worker", EventKind.ACQUIRE, lock),
        _event("worker-load-21", "worker", EventKind.LOAD, data),
        _event("worker-rel-22", "worker", EventKind.RELEASE, lock),
    )
    edges = tuple(
        ProgramOrderEdge(
            source_event=source,
            target_event=target,
            thread_role=role,
            evidence="test CFG",
        )
        for source, target, role in (
            ("main-acq-10", "main-store-11", "main"),
            ("main-store-11", "main-rel-12", "main"),
            ("worker-acq-20", "worker-load-21", "worker"),
            ("worker-load-21", "worker-rel-22", "worker"),
        )
    )
    locksets = prove_definite_locksets(events, edges)

    assert lock_protection_candidates(
        (events[1], events[4]), locksets
    ) == (("Global", "lock", 0),)


def test_unknown_release_does_not_extend_a_lock_proof() -> None:
    lock = AbstractAddress(kind=AddressKind.GLOBAL, base="lock", offset=0)
    data = AbstractAddress(kind=AddressKind.GLOBAL, base="data", offset=0)
    unknown_lock = AbstractAddress(kind=AddressKind.UNKNOWN)
    events = (
        _event("worker-acq-10", "worker", EventKind.ACQUIRE, lock),
        _event("worker-unknown-rel-11", "worker", EventKind.RELEASE, unknown_lock),
        _event("worker-store-12", "worker", EventKind.STORE, data),
    )
    edges = tuple(
        ProgramOrderEdge(
            source_event=source,
            target_event=target,
            thread_role="worker",
            evidence="test CFG",
        )
        for source, target in (
            ("worker-acq-10", "worker-unknown-rel-11"),
            ("worker-unknown-rel-11", "worker-store-12"),
        )
    )

    locksets = prove_definite_locksets(events, edges)
    assert lock_protection_candidates((events[-1],), locksets) == ()
