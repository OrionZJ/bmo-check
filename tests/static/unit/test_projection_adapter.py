from __future__ import annotations

from bmo_check_core import CompletenessStatus, MemoryEventId
from bmo_check_static.analysis.evidence import memory_event_identity
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    AliasRelation,
    ConflictCandidate,
    ElfMetadata,
    EventKind,
    MemoryEvent,
    ModuleFingerprint,
    ModuleRole,
    PruningCoverage,
    ProgramOrderEdge,
    SynchronizationEdge,
    SharedMemorySlice,
)
from bmo_check_static.slicing import (
    SliceEvidenceError,
    restrict_to_application_scope,
    build_projection_ledger,
)


HASH = "a" * 64


def _event(label: str, *, runtime: bool = False) -> MemoryEvent:
    return MemoryEvent(
        id=label,
        module="/bin/app" if not runtime else "/lib/runtime.so",
        module_sha256=HASH if not runtime else "c" * 64,
        pc=0x1000 + len(label),
        kind=EventKind.OPAQUE_CALL if runtime else EventKind.LOAD,
        address=AbstractAddress(
            kind=AddressKind.GLOBAL,
            base="runtime:private" if runtime else f"app:{label}",
            provenance={"runtime_internal": runtime},
        ),
        size=4,
        thread_role="main" if not runtime else "worker",
        provenance={"runtime_internal": runtime},
    )


def _identity(event: MemoryEvent) -> MemoryEventId:
    module = ModuleFingerprint(
        path=event.module,
        role=ModuleRole.EXECUTABLE,
        size=4096,
        sha256=event.module_sha256,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    return memory_event_identity(module, event)


def _source_and_projected() -> tuple[SharedMemorySlice, SharedMemorySlice, dict[str, MemoryEventId]]:
    runtime = _event("runtime", runtime=True)
    app1 = _event("app1")
    app2 = _event("app2")
    source = SharedMemorySlice(
        events=(runtime, app1, app2),
        program_order=(
            ProgramOrderEdge(
                source_event=runtime.id,
                target_event=app1.id,
                thread_role="worker",
                evidence="cross-block",
            ),
            ProgramOrderEdge(
                source_event=app1.id,
                target_event=app2.id,
                thread_role="main",
                evidence="same-block",
            ),
        ),
        conflicts=(
            ConflictCandidate(
                first_event=runtime.id,
                second_event=app2.id,
                first_role="worker",
                second_role="main",
                alias=AliasRelation.MUST_ALIAS,
            ),
        ),
        synchronization=(
            SynchronizationEdge(
                source_event=runtime.id,
                target_event=app2.id,
                kind="runtime-boundary",
                complete=True,
            ),
        ),
        coverage=PruningCoverage(total_events=3, remaining_shared_events=3),
    )
    projected = restrict_to_application_scope(source, executable_sha256=HASH)
    identities = {event.id: _identity(event) for event in source.events}
    return source, projected, identities


def test_projection_adapter_exposes_unproved_removed_relations() -> None:
    source, projected, identities = _source_and_projected()

    ledger = build_projection_ledger(
        source,
        projected,
        event_identities=identities,
        scope="static.application",
    )

    assert ledger.completeness.status is CompletenessStatus.INCOMPLETE
    assert len(ledger.input_relation_ids) == 4
    assert len(ledger.retained_relation_ids) == 1
    assert ledger.removed_relation_ids == ()
    assert len(ledger.missing_relation_ids) == 3
    assert "relation-level proof" in (ledger.completeness.reason or "")


def test_projection_adapter_closes_an_unchanged_relation_universe() -> None:
    source, _, identities = _source_and_projected()

    ledger = build_projection_ledger(
        source,
        source,
        event_identities=identities,
        scope="static.full",
    )

    assert ledger.completeness.status is CompletenessStatus.COMPLETE
    assert ledger.missing_relation_ids == ()
    assert len(ledger.retained_relation_ids) == 4


def test_projection_adapter_rejects_an_unmapped_relation_endpoint() -> None:
    source, projected, identities = _source_and_projected()
    identities.pop("runtime")

    try:
        build_projection_ledger(
            source,
            projected,
            event_identities=identities,
            scope="static.application",
        )
    except SliceEvidenceError as error:
        assert "unmapped event" in str(error)
    else:
        raise AssertionError("an unmapped relation endpoint must not be guessed")
