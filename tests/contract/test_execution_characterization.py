from __future__ import annotations

from bmo_check_core import (
    AccessRange,
    ExecutionRelations,
    InstructionId,
    MemoryAccessKind,
    MemoryEventId,
    MemoryOperation,
    MemoryRelation,
    MemoryOperandId,
    ModuleId,
    RelationKind,
    ThreadRoleId,
)
from bmo_check_dynamic.analysis import AnalysisWindow
from bmo_check_dynamic.model import EventKind as DynamicEventKind, TraceEvent
from bmo_check_dynamic.proof.characterization import (
    canonicalize_fixed_relations as canonicalize_dynamic_relations,
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
    build_execution_obligation_inventory,
    canonicalize_fixed_relations,
    check_fixed_execution as check_static,
)
from bmo_check_static.proof.encoding import _object_id


HASH = "a" * 64


def _static_event_ids(static: SharedMemorySlice) -> dict[str, MemoryEventId]:
    module = ModuleId.from_parts(HASH, "executable")
    result: dict[str, MemoryEventId] = {}
    for event in static.events:
        if event.address is None:
            continue
        instruction = InstructionId.from_parts(module, event.pc)
        operand_index = event.operand_index if event.operand_index is not None else 0
        discriminator = (
            event.kind.value
            if event.operand_index is not None
            else f"{event.kind.value}:implicit"
        )
        operand = MemoryOperandId.from_parts(instruction, operand_index, discriminator)
        role = ThreadRoleId.from_legacy(event.thread_role or "legacy-unknown-thread-role")
        result[event.id] = MemoryEventId.from_parts(
            operand,
            role,
            event.kind.value,
            event.id,
        )
    return result


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


def test_static_typed_relations_match_legacy_fixed_execution() -> None:
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
    legacy = check_static(
        static,
        read_from={"r-flag": "w-flag", "r-data": None},
    )
    relations = canonicalize_fixed_relations(
        static,
        read_from={"r-flag": "w-flag", "r-data": None},
    )
    obligations = build_execution_obligation_inventory(
        static,
        relations,
        event_ids=_static_event_ids(static),
    )
    typed = check_static(
        static,
        relations=relations,
        obligation_inventory=obligations,
    )

    assert typed == legacy


def test_static_typed_adapter_rejects_incomplete_execution_inventory() -> None:
    static = _static_slice(
        (
            (_static_event("w", "t0", 0x10, StaticEventKind.STORE, "x"),),
            (_static_event("r", "t1", 0x20, StaticEventKind.LOAD, "x"),),
        )
    )
    relations = canonicalize_fixed_relations(static, read_from={})
    inventory = build_execution_obligation_inventory(
        static,
        relations,
        event_ids=_static_event_ids(static),
    )

    result = check_static(
        static,
        relations=relations,
        obligation_inventory=inventory,
    )

    assert not inventory.is_enumerated
    assert result.source.status == result.target.status == "unknown"


def test_dynamic_typed_relations_match_legacy_fixed_execution() -> None:
    dynamic = _dynamic_window(
        (
            ((DynamicEventKind.STORE, 0x1000),),
            ((DynamicEventKind.STORE, 0x1000),),
            ((DynamicEventKind.LOAD, 0x1000),),
        )
    )
    dynamic_ids = {event.thread_id: event.event_id for event in dynamic.events}
    locations = {"x": (0x1000, 4)}
    legacy = check_dynamic(
        dynamic,
        read_from={dynamic_ids[3]: dynamic_ids[1]},
        coherence=(("x", dynamic_ids[1], dynamic_ids[2]),),
        from_read=(("x", dynamic_ids[3], dynamic_ids[2]),),
        object_locations=locations,
    )
    relations = canonicalize_dynamic_relations(
        dynamic,
        read_from={dynamic_ids[3]: dynamic_ids[1]},
        coherence=(("x", dynamic_ids[1], dynamic_ids[2]),),
        from_read=(("x", dynamic_ids[3], dynamic_ids[2]),),
        object_locations=locations,
    )
    typed = check_dynamic(dynamic, relations=relations, object_locations=locations)

    assert typed == legacy


def test_static_typed_partial_relation_is_unknown_not_a_new_execution() -> None:
    write = _static_event("w", "t0", 0x10, StaticEventKind.STORE, "x").model_copy(
        update={"size": 8}
    )
    read = _static_event("r", "t1", 0x20, StaticEventKind.LOAD, "x").model_copy(
        update={
            "address": AbstractAddress(
                kind=AddressKind.GLOBAL,
                base="x",
                offset=4,
            )
        }
    )
    static = _static_slice(
        (
            (write,),
            (read,),
        )
    )
    object_id = f"{HASH}:Global:x"
    relations = ExecutionRelations(
        read_from=(
            MemoryRelation(
                RelationKind.READ_FROM,
                MemoryOperation(
                    event_id="w",
                    thread_id="t0",
                    sequence=0,
                    access=AccessRange(object_id=object_id, offset=0, size=8),
                    kind=MemoryAccessKind.STORE,
                ),
                MemoryOperation(
                    event_id="r",
                    thread_id="t1",
                    sequence=0,
                    access=AccessRange(object_id=object_id, offset=4, size=4),
                    kind=MemoryAccessKind.LOAD,
                ),
            ),
        )
    )
    inventory = build_execution_obligation_inventory(
        static,
        relations,
        event_ids=_static_event_ids(static),
    )
    result = check_static(
        static,
        relations=relations,
        obligation_inventory=inventory,
    )

    assert result.source.status == result.target.status == "unknown"
    assert not inventory.is_enumerated
    assert "exact-width" in inventory.completeness.reason


def test_incomplete_fixed_relations_are_unknown_not_an_allowed_execution() -> None:
    static = _static_slice(
        ((_static_event("r", "t0", 0x10, StaticEventKind.LOAD, "x"),),)
    )
    static_result = check_static(static, read_from={})
    dynamic = _dynamic_window((((DynamicEventKind.LOAD, 0x1000),),))
    dynamic_result = check_dynamic(dynamic, read_from={})

    assert static_result.source.status == static_result.target.status == "unknown"
    assert dynamic_result.source.status == dynamic_result.target.status == "unknown"


def test_explicit_from_read_is_checked_against_the_fixed_rf_co_assignment() -> None:
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
    data_object = _object_id(static.events[0])
    source = check_static(
        static,
        read_from={"r-flag": "w-flag", "r-data": None},
        from_read=((data_object, "r-data", "w-data"),),
    )
    assert (source.source.status, source.target.status) == ("forbidden", "allowed")

    invalid = check_static(
        static,
        read_from={"r-flag": "w-flag", "r-data": None},
        from_read=((data_object, "r-data", "w-flag"),),
    )
    assert invalid.source.status == invalid.target.status == "unknown"
