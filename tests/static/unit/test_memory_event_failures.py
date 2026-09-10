from __future__ import annotations

from bmo_check_core import UnknownFact as CanonicalUnknownFact
from bmo_check_core.evidence import UnknownKind as CanonicalUnknownKind
from bmo_check_static.analysis import (
    extract_memory_events,
    extract_memory_events_with_evidence,
)
from bmo_check_static.model import (
    CFGCoverage,
    ControlFlowReport,
    ElfMetadata,
    EventKind,
    ModuleFingerprint,
    ModuleRole,
    ThreadDiscoveryReport,
    UnknownKind,
)


def test_extraction_failure_produces_unknown_sentinel(monkeypatch) -> None:
    module = ModuleFingerprint(
        path="/missing/app",
        role=ModuleRole.EXECUTABLE,
        size=0,
        sha256="a" * 64,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    cfg = ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0x1000,
        coverage=CFGCoverage(
            angr_version="test",
            functions=0,
            basic_blocks=0,
            call_sites=0,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )
    monkeypatch.setattr(
        "bmo_check_static.analysis.memory_events.collect_instruction_facts",
        lambda _: (_ for _ in ()).throw(RuntimeError("backend failed")),
    )

    report = extract_memory_events(module, cfg, ThreadDiscoveryReport())

    assert len(report.events) == 1
    assert report.events[0].kind == EventKind.UNKNOWN_MEMORY_EFFECT
    assert report.unknowns[0].kind == UnknownKind.MEMORY_EVENT_RECOVERY_FAILURE


def test_extraction_evidence_sidecar_preserves_failure_and_event_identity(monkeypatch) -> None:
    module = ModuleFingerprint(
        path="/missing/app",
        role=ModuleRole.EXECUTABLE,
        size=0,
        sha256="a" * 64,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    cfg = ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0x1000,
        coverage=CFGCoverage(
            angr_version="test",
            functions=0,
            basic_blocks=0,
            call_sites=0,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )
    monkeypatch.setattr(
        "bmo_check_static.analysis.memory_events.collect_instruction_facts",
        lambda _: (_ for _ in ()).throw(RuntimeError("backend failed")),
    )

    legacy = extract_memory_events(module, cfg, ThreadDiscoveryReport())
    snapshot = extract_memory_events_with_evidence(
        module,
        cfg,
        ThreadDiscoveryReport(),
    )

    assert snapshot.report == legacy
    assert len(snapshot.event_links) == 1
    assert snapshot.event_links[0].legacy_id == "unknown:memory-event-recovery"
    assert len(snapshot.event_ids) == 1
    node = snapshot.ledger.get(snapshot.unknown_ids[0])
    assert isinstance(node, CanonicalUnknownFact)
    assert node.kind == CanonicalUnknownKind.MEMORY_EVENT_RECOVERY_FAILURE
