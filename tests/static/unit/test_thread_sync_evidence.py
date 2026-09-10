from __future__ import annotations

from pathlib import Path

from bmo_check_core import UnknownFact as CanonicalUnknownFact
from bmo_check_core.evidence import UnknownKind as CanonicalUnknownKind
from bmo_check_static.binary.elf import inspect_elf
from bmo_check_static.model import (
    CallKind,
    CallSite,
    CFGCoverage,
    CodeLocation,
    ControlFlowReport,
    IndirectTargetSet,
    InstructionModuleFacts,
    ModuleRole,
    UnknownFact,
    UnknownKind,
)
from bmo_check_static.synchronization import (
    analyze_pthread_synchronization,
    analyze_pthread_synchronization_with_evidence,
)
from bmo_check_static.threading import (
    discover_pthread_threads,
    discover_pthread_threads_with_evidence,
)
from bmo_check_static.binary.angr_backend import AngrBackendError


def _module(path: Path):
    return inspect_elf(path, ModuleRole.EXECUTABLE)


def test_thread_evidence_sidecar_preserves_cfg_failure(
    elf_fixture,
    monkeypatch,
) -> None:
    module = _module(elf_fixture.executable)
    manifest = object()
    control_flow = object()

    def fail(_module):
        raise AngrBackendError("synthetic thread CFG failure")

    monkeypatch.setattr("bmo_check_static.threading.pthread.load_cfg", fail)
    legacy = discover_pthread_threads(module, manifest, control_flow)
    snapshot = discover_pthread_threads_with_evidence(module, manifest, control_flow)

    assert snapshot.report == legacy
    assert len(snapshot.unknown_ids) == 1
    unknown = snapshot.ledger.get(snapshot.unknown_ids[0])
    assert isinstance(unknown, CanonicalUnknownFact)
    assert unknown.kind == CanonicalUnknownKind.CFG_BACKEND_FAILURE


def test_thread_evidence_records_unknown_callback(
    elf_fixture,
    monkeypatch,
) -> None:
    module = _module(elf_fixture.executable)
    control_flow = ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0x1000,
        functions=(),
        call_sites=(
            CallSite(
                location=CodeLocation(
                    module_path=module.path,
                    module_sha256=module.sha256,
                    pc=0x1010,
                ),
                containing_function_pc=0x1000,
                block_pc=0x1010,
                kind=CallKind.PLT,
                target_symbol="pthread_create",
                targets=IndirectTargetSet(complete=True),
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=0,
            basic_blocks=0,
            call_sites=1,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )
    monkeypatch.setattr(
        "bmo_check_static.threading.pthread.load_cfg",
        lambda _module: object(),
    )
    monkeypatch.setattr(
        "bmo_check_static.threading.pthread._symbol_by_pc",
        lambda _module: {},
    )
    monkeypatch.setattr(
        "bmo_check_static.threading.pthread._main_reachability",
        lambda _report, _pc: ({0x1000}, True),
    )
    monkeypatch.setattr(
        "bmo_check_static.threading.pthread._definition_before_call",
        lambda _context, _block_pc, _call_pc, register: (
            (None, None, False)
            if register == "rdx"
            else (None, "argument", False)
        ),
    )

    legacy = discover_pthread_threads(module, object(), control_flow)
    snapshot = discover_pthread_threads_with_evidence(
        module,
        object(),
        control_flow,
    )

    assert snapshot.report == legacy
    assert any(item.kind == UnknownKind.UNKNOWN_THREAD_ENTRY for item in legacy.unknowns)
    canonical = [snapshot.ledger.get(item) for item in snapshot.unknown_ids]
    assert any(
        isinstance(item, CanonicalUnknownFact)
        and item.kind == CanonicalUnknownKind.UNKNOWN_THREAD_ENTRY
        for item in canonical
    )


def test_synchronization_evidence_mirrors_instruction_and_api_unknowns(
    elf_fixture,
    monkeypatch,
) -> None:
    module = _module(elf_fixture.executable)
    instruction_unknown = UnknownFact(
        kind=UnknownKind.DISASSEMBLY_FAILURE,
        reason="synthetic instruction failure",
        impact="instruction facts are unavailable",
        module=module.path,
    )
    facts = InstructionModuleFacts(
        module_path=module.path,
        module_sha256=module.sha256,
        instruction_count=0,
        memory_instruction_count=0,
        facts=(),
        unknowns=(instruction_unknown,),
    )
    monkeypatch.setattr(
        "bmo_check_static.synchronization.pthread.collect_instruction_facts",
        lambda _module: facts,
    )
    monkeypatch.setattr(
        "bmo_check_static.synchronization.pthread.function_symbols",
        lambda _module: (),
    )
    root = Path(__file__).parents[3]
    spec = root / "specs" / "static" / "pthread-api.yaml"
    contract = root / "specs" / "static" / "dbt6-mo-off.yaml"

    legacy = analyze_pthread_synchronization(
        module,
        spec,
        contract,
        {"pthread_create"},
    )
    snapshot = analyze_pthread_synchronization_with_evidence(
        module,
        spec,
        contract,
        {"pthread_create"},
    )

    assert snapshot.report == legacy
    kinds = {
        node.kind
        for node in snapshot.ledger.nodes()
        if isinstance(node, CanonicalUnknownFact)
    }
    assert kinds == {
        CanonicalUnknownKind.DISASSEMBLY_FAILURE,
        CanonicalUnknownKind.MISSING_SYMBOL_IMPLEMENTATION,
    }
    assert all(
        isinstance(node, CanonicalUnknownFact) for node in snapshot.ledger.nodes()
    )
