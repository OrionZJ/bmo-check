from __future__ import annotations

from bmo_check_dynamic.analysis import AnalysisWindow
from bmo_check_dynamic.model import EventKind as DynamicEventKind, TraceEvent
from bmo_check_dynamic.proof.characterization import (
    check_fixed_execution as check_dynamic,
)
from bmo_check_evaluation.litmus import (
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


HASH = "a" * 64


def _static_event(
    event_id: str,
    role: str,
    pc: int,
    kind: StaticEventKind,
    object_label: str | None = None,
) -> MemoryEvent:
    address = None
    size = None
    if object_label is not None:
        address = AbstractAddress(kind=AddressKind.GLOBAL, base=object_label, offset=0)
        size = 4
    ordering = Ordering.FULL if kind == StaticEventKind.FENCE else Ordering.RELAXED
    return MemoryEvent(
        id=event_id,
        module="/bin/litmus",
        module_sha256=HASH,
        pc=pc,
        kind=kind,
        address=address,
        size=size,
        source_ordering=Ordering.FULL if kind == StaticEventKind.FENCE else Ordering.TSO,
        target_ordering=ordering,
        thread_role=role,
    )


def _static_slice(
    threads: tuple[tuple[MemoryEvent, ...], ...],
) -> SharedMemorySlice:
    events = tuple(event for thread in threads for event in thread)
    edges = tuple(
        ProgramOrderEdge(
            source_event=left.id,
            target_event=right.id,
            thread_role=left.thread_role or "unknown",
            evidence="fixed characterization",
        )
        for thread in threads
        for left, right in zip(thread, thread[1:], strict=False)
    )
    return SharedMemorySlice(
        events=events,
        program_order=edges,
        coverage=PruningCoverage(
            total_events=len(events),
            remaining_shared_events=len(events),
        ),
    )


def _dynamic_window(threads: tuple[tuple[tuple[DynamicEventKind, int], ...], ...]):
    events = tuple(
        TraceEvent(
            thread_id=thread_id,
            sequence=index,
            ticket=0,
            pc=thread_id * 0x100 + index,
            kind=kind,
            address=address,
            size=4 if kind.is_memory else 0,
        )
        for thread_id, thread in enumerate(threads, 1)
        for index, (kind, address) in enumerate(thread, 1)
    )
    return AnalysisWindow("fixed", events, ())


def test_fixed_message_passing_is_target_only_in_both_routes() -> None:
    static = _static_slice(
        (
            (
                _static_event("w-data", "t0", 0x10, StaticEventKind.STORE, "data"),
                _static_event("w-flag", "t0", 0x14, StaticEventKind.STORE, "flag"),
            ),
            (
                _static_event("r-flag", "t1", 0x20, StaticEventKind.LOAD, "flag"),
                _static_event("r-data", "t1", 0x24, StaticEventKind.LOAD, "data"),
            ),
        )
    )
    static_result = check_static(
        static,
        read_from={"r-flag": "w-flag", "r-data": None},
    )
    dynamic_window = _dynamic_window(
        (
            ((DynamicEventKind.STORE, 0x1000), (DynamicEventKind.STORE, 0x2000)),
            ((DynamicEventKind.LOAD, 0x2000), (DynamicEventKind.LOAD, 0x1000)),
        )
    )
    dynamic_events = {event.event_id: event for event in dynamic_window.events}
    dynamic_result = check_dynamic(
        dynamic_window,
        read_from={
            dynamic_events["t2:e1"].event_id: dynamic_events["t1:e2"].event_id,
            dynamic_events["t2:e2"].event_id: None,
        },
        object_locations={"data": (0x1000, 4), "flag": (0x2000, 4)},
    )

    assert (static_result.source.status, static_result.target.status) == (
        "forbidden",
        "allowed",
    )
    assert (dynamic_result.source.status, dynamic_result.target.status) == (
        "forbidden",
        "allowed",
    )
    comparison = compare_fixed_execution(static_result, dynamic_result)
    assert comparison.status is DifferentialStatus.MATCH


def test_fixed_full_fence_blocks_message_passing_in_both_routes() -> None:
    static = _static_slice(
        (
            (
                _static_event("w-data", "t0", 0x10, StaticEventKind.STORE, "data"),
                _static_event("f0", "t0", 0x14, StaticEventKind.FENCE),
                _static_event("w-flag", "t0", 0x18, StaticEventKind.STORE, "flag"),
            ),
            (
                _static_event("r-flag", "t1", 0x20, StaticEventKind.LOAD, "flag"),
                _static_event("f1", "t1", 0x24, StaticEventKind.FENCE),
                _static_event("r-data", "t1", 0x28, StaticEventKind.LOAD, "data"),
            ),
        )
    )
    static_result = check_static(
        static,
        read_from={"r-flag": "w-flag", "r-data": None},
    )
    dynamic_window = _dynamic_window(
        (
            (
                (DynamicEventKind.STORE, 0x1000),
                (DynamicEventKind.MFENCE, 0),
                (DynamicEventKind.STORE, 0x2000),
            ),
            (
                (DynamicEventKind.LOAD, 0x2000),
                (DynamicEventKind.MFENCE, 0),
                (DynamicEventKind.LOAD, 0x1000),
            ),
        )
    )
    dynamic_events = {event.event_id: event for event in dynamic_window.events}
    dynamic_result = check_dynamic(
        dynamic_window,
        read_from={"t2:e1": "t1:e3", "t2:e3": None},
        object_locations={"data": (0x1000, 4), "flag": (0x2000, 4)},
    )

    assert static_result.source.status == static_result.target.status == "forbidden"
    assert dynamic_result.source.status == dynamic_result.target.status == "forbidden"
    comparison = compare_fixed_execution(static_result, dynamic_result)
    assert comparison.status is DifferentialStatus.MATCH


def test_incomplete_fixed_relations_are_unknown_not_an_allowed_execution() -> None:
    static = _static_slice(
        ((_static_event("r", "t0", 0x10, StaticEventKind.LOAD, "x"),),)
    )
    static_result = check_static(static, read_from={})
    dynamic = _dynamic_window((((DynamicEventKind.LOAD, 0x1000),),))
    dynamic_result = check_dynamic(dynamic, read_from={})

    assert static_result.source.status == static_result.target.status == "unknown"
    assert dynamic_result.source.status == dynamic_result.target.status == "unknown"
