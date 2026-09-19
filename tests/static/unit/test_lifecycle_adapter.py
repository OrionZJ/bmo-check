from __future__ import annotations

from bmo_check_core import CompletenessStatus, ThreadRoleId
from bmo_check_static.model import (
    CodeLocation,
    ElfMetadata,
    IndirectTargetSet,
    ModuleFingerprint,
    ModuleRole,
    ThreadCreateFact,
    ThreadDiscoveryReport,
    ThreadJoinFact,
    ThreadRole,
)
from bmo_check_static.threading import characterize_thread_discovery


HASH = "a" * 64


def _module() -> ModuleFingerprint:
    return ModuleFingerprint(
        path="/tmp/app",
        role=ModuleRole.EXECUTABLE,
        size=4096,
        sha256=HASH,
        elf=ElfMetadata(
            elf_class=2,
            little_endian=True,
            machine="x86_64",
            elf_type="ET_EXEC",
        ),
    )


def _location(pc: int) -> CodeLocation:
    return CodeLocation(module_path="/tmp/app", module_sha256=HASH, pc=pc)


def _targets(pc: int) -> IndirectTargetSet:
    return IndirectTargetSet(known_targets=(_location(pc),), complete=True)


def test_legacy_static_report_cannot_be_upgraded_to_complete_lifecycle() -> None:
    report = ThreadDiscoveryReport(
        roles=(
            ThreadRole(
                id="main",
                start_targets=_targets(0x100),
                complete=True,
            ),
            ThreadRole(
                id="worker@400",
                parent_role="main",
                create_site=_location(0x400),
                start_targets=_targets(0x200),
                handle_locations=("stack-slot:0",),
                complete=True,
            ),
        ),
        creates=(
            ThreadCreateFact(
                call_site=_location(0x400),
                parent_role="main",
                child_role="worker@400",
                start_targets=_targets(0x200),
                handle_locations=("stack-slot:0",),
            ),
        ),
    )

    ledger = characterize_thread_discovery(report, _module())

    assert ledger.completeness.status is CompletenessStatus.INCOMPLETE
    assert ledger.missing_thread_ids == ()
    assert all(
        record.completeness.status is CompletenessStatus.INCOMPLETE
        for record in ledger.records
    )
    worker = next(
        record
        for record in ledger.records
        if record.thread_id == ThreadRoleId.from_legacy("worker@400")
    )
    assert worker.create_operation is not None
    assert worker.start_operation is None
    assert worker.end_operation is None
    assert worker.handle_id is None


def test_legacy_join_candidate_is_preserved_but_not_resolved_by_slot_name() -> None:
    report = ThreadDiscoveryReport(
        roles=(
            ThreadRole(id="main", start_targets=_targets(0x100), complete=True),
            ThreadRole(
                id="worker@400",
                parent_role="main",
                create_site=_location(0x400),
                start_targets=_targets(0x200),
                handle_locations=("slot:0",),
                complete=True,
            ),
        ),
        joins=(
            ThreadJoinFact(
                call_site=_location(0x500),
                parent_role="main",
                candidate_child_roles=("worker@400",),
                handle_locations=("slot:0",),
                complete=True,
            ),
        ),
    )

    ledger = characterize_thread_discovery(report, _module())

    assert len(ledger.joins) == 1
    relation = ledger.joins[0]
    assert relation.candidate_threads == (ThreadRoleId.from_legacy("worker@400"),)
    assert relation.handle_id is None
    assert relation.target_thread is None
    assert relation.completeness.status is CompletenessStatus.INCOMPLETE
