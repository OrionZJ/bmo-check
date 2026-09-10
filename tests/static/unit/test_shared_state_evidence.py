from __future__ import annotations

from bmo_check_core import UnknownFact as CanonicalUnknownFact
from bmo_check_core.evidence import UnknownKind as CanonicalUnknownKind
from bmo_check_static.analysis import (
    analyze_shared_state,
    analyze_shared_state_with_evidence,
)
from bmo_check_static.binary.elf import inspect_elf
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    BasicBlockFact,
    CFGCoverage,
    CodeLocation,
    ControlFlowReport,
    EventKind,
    FunctionFact,
    MemoryEvent,
    MemoryEventReport,
    ModuleRole,
    ThreadDiscoveryReport,
    ThreadRole,
    IndirectTargetSet,
)
from bmo_check_static.binary.angr_backend import AngrBackendError


def test_shared_state_evidence_records_affine_unknown_without_changing_report(
    elf_fixture,
    monkeypatch,
) -> None:
    module = inspect_elf(elf_fixture.executable, ModuleRole.EXECUTABLE)
    location = CodeLocation(
        module_path=module.path,
        module_sha256=module.sha256,
        pc=0x1000,
        symbol="main",
    )
    block = BasicBlockFact(
        location=location,
        size=16,
        instruction_pcs=(0x1100, 0x1200),
    )
    control_flow = ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0x1000,
        functions=(FunctionFact(location=location, size=16, block_pcs=(0x1000,)),),
        basic_blocks=(block,),
        coverage=CFGCoverage(
            angr_version="test",
            functions=1,
            basic_blocks=1,
            call_sites=0,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )
    address = AbstractAddress(
        kind=AddressKind.AFFINE,
        base="heap:array",
        offset=0,
        expression="tid+i",
        thread_coefficient=1,
        index_coefficient=1,
    )
    events = MemoryEventReport(
        module_path=module.path,
        module_sha256=module.sha256,
        events=(
            MemoryEvent(
                id="main-load",
                module=module.path,
                module_sha256=module.sha256,
                pc=0x1100,
                block_pc=0x1000,
                function="main",
                function_pc=0x1000,
                kind=EventKind.LOAD,
                address=address,
                thread_role="main",
            ),
            MemoryEvent(
                id="worker-store",
                module=module.path,
                module_sha256=module.sha256,
                pc=0x1200,
                block_pc=0x1000,
                function="main",
                function_pc=0x1000,
                kind=EventKind.STORE,
                address=address,
                thread_role="worker",
            ),
        ),
    )
    threads = ThreadDiscoveryReport(
        roles=(
            ThreadRole(
                id="main",
                start_targets=IndirectTargetSet(complete=True),
                complete=True,
            ),
            ThreadRole(
                id="worker",
                start_targets=IndirectTargetSet(complete=True),
                complete=True,
            ),
        )
    )
    monkeypatch.setattr(
        "bmo_check_static.analysis.shared_state._stack_escape_by_function",
        lambda *_args: ({}, {}, ()),
    )
    monkeypatch.setattr(
        "bmo_check_static.analysis.shared_state.load_cfg",
        lambda _module: (_ for _ in ()).throw(AngrBackendError("unused")),
    )

    legacy = analyze_shared_state(module, control_flow, threads, events)
    snapshot = analyze_shared_state_with_evidence(
        module,
        control_flow,
        threads,
        events,
    )

    assert snapshot.report == legacy
    assert any(
        item.kind.value == "UnknownAffineBounds" for item in legacy.unknowns
    )
    canonical = [snapshot.ledger.get(item) for item in snapshot.unknown_ids]
    assert any(
        isinstance(item, CanonicalUnknownFact)
        and item.kind == CanonicalUnknownKind.UNKNOWN_AFFINE_BOUNDS
        for item in canonical
    )
    assert all(isinstance(item, CanonicalUnknownFact) for item in canonical)
