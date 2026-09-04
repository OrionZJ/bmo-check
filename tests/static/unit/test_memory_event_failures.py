from __future__ import annotations

from bmo_check_static.analysis import extract_memory_events
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
