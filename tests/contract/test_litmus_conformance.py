from __future__ import annotations

from bmo_check_evaluation.litmus.conformance import (
    ConformanceStatus,
    align_critical_events,
)
from bmo_check_evaluation.litmus.projection import project_critical_slice
from bmo_check_evaluation.litmus.model import (
    BinaryBinding,
    CriticalEvent,
    ExecutionAssignment,
    FixtureEventKind,
    HerdOracleRecord,
    LitmusCase,
)
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    CodeLocation,
    EventKind,
    ExecutionScope,
    IndirectTargetSet,
    MemoryEvent,
    MemoryEventReport,
    Ordering,
    ProgramOrderEdge,
    PruningCoverage,
    ProgramManifest,
    ProgramRecoveryReport,
    ProgramSliceReport,
    SharedMemorySlice,
    ThreadDiscoveryReport,
    ThreadRole,
)


HASH = "a" * 64


def _case(*events: CriticalEvent) -> LitmusCase:
    return LitmusCase(
        case_id="fixture-case",
        binding=BinaryBinding(
            source_litmus="tests/fixture.litmus",
            source_sha256=HASH,
            elf_relative_path="elf-tests/fixture.exe",
            elf_sha256=HASH,
            corpus_revision="rev-1",
            build_recipe="make fixture",
        ),
        critical_events=events,
        program_order=(),
        executions=(ExecutionAssignment(assignment_id="fixed"),),
        oracle=HerdOracleRecord(
            herd_version="herd7",
            source_model="x86.cat",
            target_model="riscv.cat",
            source_outcome="Allowed",
            target_outcome="Allowed",
            source_input_sha256=HASH,
            target_input_sha256="b" * 64,
            elf_sha256=HASH,
            contract_version="dbt6-mo-off-v2",
            contract_sha256=HASH,
            raw_output_sha256=HASH,
        ),
    )


def _event(
    event_id: str,
    role: str,
    pc: int,
    kind: EventKind,
    base: str | None = None,
    ordering: Ordering = Ordering.RELAXED,
) -> MemoryEvent:
    address = (
        AbstractAddress(kind=AddressKind.GLOBAL, base=base, offset=0)
        if base is not None
        else None
    )
    return MemoryEvent(
        id=event_id,
        module="/bin/fixture",
        module_sha256=HASH,
        pc=pc,
        kind=kind,
        address=address,
        size=4 if address is not None else None,
        source_ordering=ordering if kind == EventKind.FENCE else Ordering.TSO,
        target_ordering=ordering,
        thread_role=role,
    )


def _report(
    events: tuple[MemoryEvent, ...],
    unknowns=(),
    roles: tuple[ThreadRole, ...] | None = None,
    program_order: tuple[ProgramOrderEdge, ...] = (),
) -> ProgramSliceReport:
    roles = roles or tuple(
        ThreadRole(
            id=role,
            start_targets=IndirectTargetSet(complete=True),
            complete=True,
        )
        for role in ("main", "worker")
    )
    recovery = ProgramRecoveryReport(
        manifest=ProgramManifest(
            dbt_contract_version="dbt6-mo-off-v2",
            closure_complete=True,
            execution=ExecutionScope(thread_count_min=2, thread_count_max=2),
        ),
        thread_roles=ThreadDiscoveryReport(roles=roles),
    )
    return ProgramSliceReport(
        recovery=recovery,
        memory_events=MemoryEventReport(
            module_path="/bin/fixture",
            module_sha256=HASH,
            events=events,
        ),
        shared_slice=SharedMemorySlice(
            events=events,
            program_order=program_order,
            coverage=PruningCoverage(
                total_events=len(events), remaining_shared_events=len(events)
            ),
        ),
        unknowns=tuple(unknowns),
    )


def test_conformance_aligns_roles_objects_and_counts_harness_events() -> None:
    case = _case(
        CriticalEvent(
            label="write-x",
            thread=1,
            ordinal=0,
            kind=FixtureEventKind.STORE,
            object_label="x",
            width=4,
            instruction_pc=0x20,
        ),
        CriticalEvent(
            label="read-x",
            thread=0,
            ordinal=0,
            kind=FixtureEventKind.LOAD,
            object_label="x",
            width=4,
            instruction_pc=0x10,
        ),
    )
    report = _report(
        (
            _event("worker-store", "worker", 0x20, EventKind.STORE, "x"),
            _event("main-load", "main", 0x10, EventKind.LOAD, "x"),
            _event("harness", "main", 0x30, EventKind.STORE, "stats"),
        )
    )

    result = align_critical_events(case, report)

    assert result.status is ConformanceStatus.MATCHED
    assert {match.label for match in result.matches} == {"write-x", "read-x"}
    assert result.extra_event_count == 1
    assert result.extra_event_ids == ("harness",)


def test_conformance_does_not_guess_ambiguous_or_wrong_fence_events() -> None:
    ambiguous_case = _case(
        CriticalEvent(
            label="read-x",
            thread=0,
            ordinal=0,
            kind=FixtureEventKind.LOAD,
            object_label="x",
            width=4,
        )
    )
    ambiguous_report = _report(
        (
            _event("load-1", "main", 0x10, EventKind.LOAD, "x"),
            _event("load-2", "main", 0x20, EventKind.LOAD, "x"),
        )
    )
    ambiguous = align_critical_events(ambiguous_case, ambiguous_report)

    fence_case = _case(
        CriticalEvent(
            label="lfence",
            thread=0,
            ordinal=0,
            kind=FixtureEventKind.LFENCE,
            instruction_pc=0x30,
        )
    )
    fence_report = _report(
        (_event("sfence", "main", 0x30, EventKind.FENCE, ordering=Ordering.FENCE_WW),)
    )
    fence = align_critical_events(fence_case, fence_report)

    assert ambiguous.status is ConformanceStatus.UNKNOWN
    assert ambiguous.ambiguous_labels == ("read-x",)
    assert fence.status is ConformanceStatus.UNKNOWN
    assert fence.missing_labels == ("lfence",)


def test_conformance_binds_roles_by_binary_entry_pc() -> None:
    case = _case(
        CriticalEvent(
            label="p0-store",
            thread=0,
            ordinal=0,
            kind=FixtureEventKind.STORE,
            object_label="x",
            width=4,
            instruction_pc=0x40,
            thread_entry_pc=0x1000,
        ),
        CriticalEvent(
            label="p1-load",
            thread=1,
            ordinal=0,
            kind=FixtureEventKind.LOAD,
            object_label="x",
            width=4,
            instruction_pc=0x50,
            thread_entry_pc=0x2000,
        ),
    )
    roles = (
        ThreadRole(
            id="main",
            start_targets=IndirectTargetSet(complete=True),
            complete=True,
        ),
        ThreadRole(
            id="p1",
            start_targets=IndirectTargetSet(
                known_targets=(
                    # The role order intentionally does not match fixture thread numbers.
                    # The PC is the binary identity used by the conformance adapter.
                    CodeLocation(
                        module_path="/bin/fixture",
                        module_sha256=HASH,
                        pc=0x2000,
                    ),
                ),
                complete=True,
            ),
            complete=True,
        ),
        ThreadRole(
            id="p0",
            start_targets=IndirectTargetSet(
                known_targets=(
                    CodeLocation(
                        module_path="/bin/fixture",
                        module_sha256=HASH,
                        pc=0x1000,
                    ),
                ),
                complete=True,
            ),
            complete=True,
        ),
    )
    report = _report(
        (
            _event("p0-store", "p0", 0x40, EventKind.STORE, "x"),
            _event("p1-load", "p1", 0x50, EventKind.LOAD, "x"),
        ),
        roles=roles,
    )

    result = align_critical_events(case, report)

    assert result.status is ConformanceStatus.MATCHED
    assert {match.label for match in result.matches} == {"p0-store", "p1-load"}


def test_critical_projection_is_small_and_does_not_mutate_recovery_slice() -> None:
    case = _case(
        CriticalEvent(
            label="store-x",
            thread=0,
            ordinal=0,
            kind=FixtureEventKind.STORE,
            object_label="x",
            width=4,
            instruction_pc=0x60,
        ),
        CriticalEvent(
            label="load-x",
            thread=0,
            ordinal=1,
            kind=FixtureEventKind.LOAD,
            object_label="x",
            width=4,
            instruction_pc=0x70,
        ),
    )
    critical_store = _event(
        "critical-store", "main", 0x60, EventKind.STORE, "x"
    ).model_copy(
        update={
            "address": AbstractAddress(
                kind=AddressKind.AFFINE,
                expression="rdi+rcx",
            )
        }
    )
    critical_load = _event(
        "critical-load", "main", 0x70, EventKind.LOAD, "x"
    ).model_copy(
        update={
            "address": AbstractAddress(
                kind=AddressKind.AFFINE,
                expression="rdi+rcx",
            )
        }
    )
    harness = _event("harness", "main", 0x80, EventKind.OPAQUE_CALL)
    report = _report(
        (critical_store, critical_load, harness),
        program_order=(
            ProgramOrderEdge(
                source_event="critical-store",
                target_event="critical-load",
                thread_role="main",
                evidence="test CFG",
            ),
        ),
    )
    conformance = align_critical_events(case, report)

    projected = project_critical_slice(case, conformance, report)

    assert conformance.status is ConformanceStatus.MATCHED
    assert tuple(event.id for event in projected.events) == (
        "critical-store",
        "critical-load",
    )
    assert all(
        event.address is not None
        and event.address.kind is AddressKind.GLOBAL
        and event.address.base == "e2.5-object:x"
        for event in projected.events
    )
    assert report.shared_slice is not None
    assert len(report.shared_slice.events) == 3
    assert len(projected.program_order) == 1
    assert "evaluation only" in projected.program_order[0].evidence
