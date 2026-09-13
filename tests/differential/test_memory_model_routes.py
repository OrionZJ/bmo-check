from __future__ import annotations

from dataclasses import dataclass

import pytest

from bmo_check_dynamic.analysis import AnalysisWindow
from bmo_check_dynamic.model import EventKind as DynamicEventKind, TraceEvent
from bmo_check_dynamic.proof.characterization import (
    check_fixed_execution as check_dynamic,
)
from bmo_check_evaluation.litmus import (
    DifferentialClassification,
    DifferentialStatus,
    compare_fixed_execution,
)
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    EventKind as StaticEventKind,
    MemoryEvent,
    Ordering,
    ProgramOrderEdge,
    PruningCoverage,
    SharedMemorySlice,
)
from bmo_check_static.proof.characterization import (
    check_fixed_execution as check_static,
)
from bmo_check_static.proof.encoding import _object_id


HASH = "a" * 64


def _static_event(
    event_id: str,
    role: str,
    pc: int,
    kind: StaticEventKind,
    object_label: str | None = None,
    *,
    source_ordering: Ordering | None = None,
    target_ordering: Ordering | None = None,
) -> MemoryEvent:
    address = None
    size = None
    if object_label is not None:
        address = AbstractAddress(kind=AddressKind.GLOBAL, base=object_label, offset=0)
        size = 4
    return MemoryEvent(
        id=event_id,
        module="/bin/e2-5",
        module_sha256=HASH,
        pc=pc,
        kind=kind,
        address=address,
        size=size,
        source_ordering=(
            source_ordering
            if source_ordering is not None
            else (Ordering.FULL if kind == StaticEventKind.FENCE else Ordering.TSO)
        ),
        target_ordering=(
            target_ordering
            if target_ordering is not None
            else (Ordering.FULL if kind == StaticEventKind.FENCE else Ordering.RELAXED)
        ),
        thread_role=role,
    )


def _static_slice(threads: tuple[tuple[MemoryEvent, ...], ...]) -> SharedMemorySlice:
    events = tuple(event for thread in threads for event in thread)
    edges = tuple(
        ProgramOrderEdge(
            source_event=left.id,
            target_event=right.id,
            thread_role=left.thread_role or "unknown",
            evidence="E2.5 common relation fixture",
        )
        for thread in threads
        for left, right in zip(thread, thread[1:], strict=False)
    )
    return SharedMemorySlice(
        events=events,
        program_order=edges,
        coverage=PruningCoverage(total_events=len(events), remaining_shared_events=len(events)),
    )


def _dynamic_window(
    threads: tuple[tuple[tuple[DynamicEventKind, int], ...], ...],
) -> AnalysisWindow:
    events = tuple(
        TraceEvent(
            thread_id=thread_id,
            sequence=sequence,
            ticket=0,
            pc=thread_id * 0x100 + sequence,
            kind=kind,
            address=address,
            size=4 if kind.is_memory else 0,
        )
        for thread_id, thread in enumerate(threads, 1)
        for sequence, (kind, address) in enumerate(thread, 1)
    )
    return AnalysisWindow("e2-5-common", events, ())


@dataclass(frozen=True)
class _Model:
    model: str
    status: str


@dataclass(frozen=True)
class _Pair:
    source: object
    target: object


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (StaticEventKind.LOAD, StaticEventKind.LOAD),
        (StaticEventKind.LOAD, StaticEventKind.STORE),
        (StaticEventKind.STORE, StaticEventKind.STORE),
        (StaticEventKind.STORE, StaticEventKind.LOAD),
    ],
)
def test_common_plain_order_matrix_tracks_x86_tso_and_rvwmo(left, right) -> None:
    static = _static_slice(
        ((_static_event("left", "t0", 0x10, left, "x"), _static_event("right", "t0", 0x14, right, "y")),)
    )
    static_result = check_static(static, read_from={event.id: None for event in static.events if event.kind == StaticEventKind.LOAD})

    dynamic_kind = {
        StaticEventKind.LOAD: DynamicEventKind.LOAD,
        StaticEventKind.STORE: DynamicEventKind.STORE,
    }
    dynamic = _dynamic_window((((dynamic_kind[left], 0x1000), (dynamic_kind[right], 0x2000)),))
    dynamic_result = check_dynamic(
        dynamic,
        read_from={event.event_id: None for event in dynamic.events if event.kind.is_read},
    )

    comparison = compare_fixed_execution(static_result, dynamic_result)
    assert comparison.classification is DifferentialClassification.EQUIVALENT
    assert comparison.status is DifferentialStatus.MATCH


def test_message_passing_target_only_execution_matches_both_routes() -> None:
    static = _static_slice(
        (
            (_static_event("w-data", "t0", 0x10, StaticEventKind.STORE, "data"), _static_event("w-flag", "t0", 0x14, StaticEventKind.STORE, "flag")),
            (_static_event("r-flag", "t1", 0x20, StaticEventKind.LOAD, "flag"), _static_event("r-data", "t1", 0x24, StaticEventKind.LOAD, "data")),
        )
    )
    static_result = check_static(static, read_from={"r-flag": "w-flag", "r-data": None})
    dynamic = _dynamic_window(
        (
            ((DynamicEventKind.STORE, 0x1000), (DynamicEventKind.STORE, 0x2000)),
            ((DynamicEventKind.LOAD, 0x2000), (DynamicEventKind.LOAD, 0x1000)),
        )
    )
    dynamic_result = check_dynamic(
        dynamic,
        read_from={"t2:e1": "t1:e2", "t2:e2": None},
        object_locations={"data": (0x1000, 4), "flag": (0x2000, 4)},
    )

    comparison = compare_fixed_execution(static_result, dynamic_result)
    assert comparison.status is DifferentialStatus.MATCH
    assert comparison.classification is DifferentialClassification.EQUIVALENT
    assert (comparison.source_static, comparison.target_static) == ("forbidden", "allowed")


@pytest.mark.parametrize(
    ("dynamic_fence", "ordering"),
    [
        (DynamicEventKind.LFENCE, Ordering.FENCE_RR),
        (DynamicEventKind.SFENCE, Ordering.FENCE_WW),
        (DynamicEventKind.MFENCE, Ordering.FULL),
    ],
)
def test_explicit_fences_have_matching_route_legality(
    dynamic_fence: DynamicEventKind, ordering: Ordering
) -> None:
    static = _static_slice(
        (
            (
                _static_event(
                    "fence",
                    "t0",
                    0x10,
                    StaticEventKind.FENCE,
                    source_ordering=ordering,
                    target_ordering=ordering,
                ),
            ),
        )
    )
    static_result = check_static(static, read_from={})
    dynamic = _dynamic_window((((dynamic_fence, 0),),))
    dynamic_result = check_dynamic(dynamic, read_from={})

    comparison = compare_fixed_execution(static_result, dynamic_result)

    assert comparison.status is DifferentialStatus.MATCH
    assert (comparison.source_static, comparison.target_static) == (
        "allowed",
        "allowed",
    )


def test_acq_rel_atomic_boundary_has_matching_route_legality() -> None:
    static = _static_slice(
        (
            (
                _static_event(
                    "rmw-0",
                    "t0",
                    0x10,
                    StaticEventKind.ATOMIC_RMW,
                    "x",
                    target_ordering=Ordering.ACQ_REL,
                ),
            ),
            (
                _static_event(
                    "rmw-1",
                    "t1",
                    0x20,
                    StaticEventKind.ATOMIC_RMW,
                    "x",
                    target_ordering=Ordering.ACQ_REL,
                ),
            ),
        )
    )
    static_object = _object_id(static.events[0])
    static_result = check_static(
        static,
        read_from={"rmw-0": None, "rmw-1": "rmw-0"},
        coherence=((static_object, "rmw-0", "rmw-1"),),
    )
    dynamic = _dynamic_window(
        (
            ((DynamicEventKind.ATOMIC_RMW, 0x1000),),
            ((DynamicEventKind.ATOMIC_RMW, 0x1000),),
        )
    )
    dynamic_result = check_dynamic(
        dynamic,
        read_from={"t1:e1": None, "t2:e1": "t1:e1"},
        coherence=(("x", "t1:e1", "t2:e1"),),
        object_locations={"x": (0x1000, 4)},
    )

    comparison = compare_fixed_execution(static_result, dynamic_result)

    assert comparison.status is DifferentialStatus.MATCH
    assert (comparison.source_static, comparison.target_static) == (
        "allowed",
        "allowed",
    )


def test_same_address_store_load_difference_is_explicitly_route_specific() -> None:
    static = _static_slice(
        (
            (
                _static_event("store", "t0", 0x10, StaticEventKind.STORE, "x"),
                _static_event("load", "t0", 0x14, StaticEventKind.LOAD, "x"),
            ),
        )
    )
    static_result = check_static(static, read_from={"load": None})
    dynamic = _dynamic_window(
        (
            ((DynamicEventKind.STORE, 0x1000), (DynamicEventKind.LOAD, 0x1000)),
        )
    )
    dynamic_result = check_dynamic(
        dynamic,
        read_from={"t1:e2": None},
        object_locations={"x": (0x1000, 4)},
    )

    comparison = compare_fixed_execution(
        static_result,
        dynamic_result,
        expected=DifferentialClassification.INTENDED_ROUTE_DIFFERENCE,
        expected_reason=(
            "static and dynamic facades intentionally model same-address "
            "Store-to-Load forwarding at different abstraction levels"
        ),
    )

    assert comparison.status is DifferentialStatus.MISMATCH
    assert (comparison.source_static, comparison.source_dynamic) == (
        "allowed",
        "forbidden",
    )


def test_dynamic_facade_accepts_explicit_from_read_for_the_same_execution() -> None:
    window = _dynamic_window(
        (
            ((DynamicEventKind.STORE, 0x1000), (DynamicEventKind.STORE, 0x2000)),
            ((DynamicEventKind.LOAD, 0x2000), (DynamicEventKind.LOAD, 0x1000)),
        )
    )
    result = check_dynamic(
        window,
        read_from={"t2:e1": "t1:e2", "t2:e2": None},
        from_read=(("data", "t2:e2", "t1:e1"),),
        object_locations={"data": (0x1000, 4), "flag": (0x2000, 4)},
    )
    assert (result.source.status, result.target.status) == ("forbidden", "allowed")

    invalid = check_dynamic(
        window,
        read_from={"t2:e1": "t1:e2", "t2:e2": None},
        from_read=(("data", "t2:e2", "t1:e2"),),
        object_locations={"data": (0x1000, 4), "flag": (0x2000, 4)},
    )
    assert invalid.source.status == invalid.target.status == "unknown"


def test_unknown_route_is_incomplete_and_not_equivalent() -> None:
    static = _static_slice(((_static_event("load", "t0", 0x10, StaticEventKind.LOAD, "x"),),))
    dynamic = _dynamic_window((((DynamicEventKind.LOAD, 0x1000),),))
    comparison = compare_fixed_execution(
        check_static(static, read_from={}),
        check_dynamic(dynamic, read_from={}),
    )
    assert comparison.status is DifferentialStatus.INCOMPLETE
    assert comparison.classification is DifferentialClassification.UNRESOLVED_MODEL_DRIFT


def test_known_route_difference_must_be_explicitly_exempted() -> None:
    static = _Pair(_Model("x86-tso", "forbidden"), _Model("rvwmo", "allowed"))
    dynamic = _Pair(_Model("x86-tso", "allowed"), _Model("rvwmo", "allowed"))
    comparison = compare_fixed_execution(static, dynamic)
    assert comparison.classification is DifferentialClassification.UNRESOLVED_MODEL_DRIFT

    exempted = compare_fixed_execution(
        static,
        dynamic,
        expected=DifferentialClassification.INTENDED_ROUTE_DIFFERENCE,
        expected_reason="overlapping same-address S-L rule is intentionally route-specific",
    )
    assert exempted.status is DifferentialStatus.MISMATCH
    assert exempted.classification is DifferentialClassification.INTENDED_ROUTE_DIFFERENCE
