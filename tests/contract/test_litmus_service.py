from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from bmo_check_evaluation.litmus.model import (
    BinaryBinding,
    CriticalEvent,
    ExecutionAssignment,
    FixtureEventKind,
    HerdOracleRecord,
    LitmusCase,
    LitmusManifest,
)
from bmo_check_evaluation.litmus.service import (
    LitmusConformanceRequest,
    run_litmus_conformance,
)
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    EventKind,
    ElfMetadata,
    ExecutionScope,
    IndirectTargetSet,
    MemoryEvent,
    MemoryEventReport,
    ModuleFingerprint,
    ModuleRole,
    Ordering,
    PruningCoverage,
    ProgramManifest,
    ProgramRecoveryReport,
    ProgramSliceReport,
    SharedMemorySlice,
    ThreadDiscoveryReport,
    ThreadRole,
)


HASH = "a" * 64


def _case(source_hash: str, elf_hash: str, contract_hash: str = HASH) -> LitmusCase:
    return LitmusCase(
        case_id="fixture-case",
        binding=BinaryBinding(
            source_litmus="tests/fixture.litmus",
            source_sha256=source_hash,
            elf_relative_path="elf-tests/fixture.exe",
            elf_sha256=elf_hash,
            corpus_revision="rev-1",
            build_recipe="make fixture",
        ),
        critical_events=(
            CriticalEvent(
                label="read-x",
                thread=0,
                ordinal=0,
                kind=FixtureEventKind.LOAD,
                object_label="x",
                width=4,
                instruction_pc=0x10,
            ),
        ),
        program_order=(),
        executions=(
            ExecutionAssignment(
                assignment_id="initial",
                read_from=(
                    {"load": "read-x"},
                ),
            ),
        ),
        oracle=HerdOracleRecord(
            herd_version="herd7",
            source_model="x86.cat",
            target_model="riscv.cat",
            source_outcome="Allowed",
            target_outcome="Allowed",
            source_input_sha256=source_hash,
            target_input_sha256="b" * 64,
            elf_sha256=elf_hash,
            contract_version="dbt6-mo-off-v2",
            contract_sha256=contract_hash,
            raw_output_sha256=HASH,
        ),
    )


def _report(elf_hash: str = HASH) -> ProgramSliceReport:
    event = MemoryEvent(
        id="read",
        module="/bin/fixture",
        module_sha256=HASH,
        pc=0x10,
        kind=EventKind.LOAD,
        address=AbstractAddress(kind=AddressKind.GLOBAL, base="x", offset=0),
        size=4,
        source_ordering=Ordering.TSO,
        target_ordering=Ordering.RELAXED,
        thread_role="main",
    )
    recovery = ProgramRecoveryReport(
        manifest=ProgramManifest(
            executable=ModuleFingerprint(
                path="/bin/fixture",
                role=ModuleRole.EXECUTABLE,
                size=1,
                sha256=elf_hash,
                elf=ElfMetadata(
                    elf_class=64,
                    little_endian=True,
                    machine="EM_X86_64",
                    elf_type="ET_EXEC",
                ),
            ),
            dbt_contract_version="dbt6-mo-off-v2",
            closure_complete=True,
            execution=ExecutionScope(thread_count_min=1, thread_count_max=1),
        ),
        thread_roles=ThreadDiscoveryReport(
            roles=(
                ThreadRole(
                    id="main",
                    start_targets=IndirectTargetSet(complete=True),
                    complete=True,
                ),
            )
        ),
    )
    return ProgramSliceReport(
        recovery=recovery,
        memory_events=MemoryEventReport(
            module_path="/bin/fixture",
            module_sha256=HASH,
            events=(event,),
        ),
        shared_slice=SharedMemorySlice(
            events=(event,),
            coverage=PruningCoverage(total_events=1, remaining_shared_events=1),
        ),
    )


def _write_manifest(root: Path, source: bytes, elf: bytes) -> Path:
    source_path = root / "tests" / "fixture.litmus"
    elf_path = root / "elf-tests" / "fixture.exe"
    source_path.parent.mkdir(parents=True)
    elf_path.parent.mkdir(parents=True)
    source_path.write_bytes(source)
    elf_path.write_bytes(elf)
    source_hash = hashlib.sha256(source).hexdigest()
    elf_hash = hashlib.sha256(elf).hexdigest()
    contract_path = Path(__file__).resolve().parents[2] / "specs" / "static" / "dbt6-mo-off.yaml"
    contract_hash = hashlib.sha256(contract_path.read_bytes()).hexdigest()
    manifest = LitmusManifest(
        schema=1,
        corpus_name="fixture",
        corpus_revision="rev-1",
        cases=(_case(source_hash, elf_hash, contract_hash),),
    )
    path = root / "manifest.yaml"
    path.write_text(
        yaml.safe_dump(manifest.model_dump(mode="json", by_alias=True)),
        encoding="utf-8",
    )
    return path


def _request(root: Path, manifest: Path) -> LitmusConformanceRequest:
    contract = Path(__file__).resolve().parents[2] / "specs" / "static" / "dbt6-mo-off.yaml"
    pthread = root / "pthread.yaml"
    effects = root / "effects.yaml"
    pthread.write_text("schema: 1\napis: {}\n", encoding="utf-8")
    effects.write_text("schema: 1\ncontract_version: test\nfunctions: {}\n", encoding="utf-8")
    return LitmusConformanceRequest(
        manifest=manifest,
        corpus_root=root,
        dbt_contract=contract,
        pthread_spec=pthread,
        function_effects=effects,
    )


def test_service_verifies_binary_bindings_before_recovery(tmp_path: Path, monkeypatch) -> None:
    manifest = _write_manifest(tmp_path, b"source", b"elf")
    calls = []
    recovered = _report(hashlib.sha256(b"elf").hexdigest())
    monkeypatch.setattr(
        "bmo_check_evaluation.litmus.service.slice_report",
        lambda request: (calls.append(request), recovered)[1],
    )

    result = run_litmus_conformance(_request(tmp_path, manifest))

    assert result.status.value == "MATCHED"
    assert result.cases[0].status.value == "MATCHED"
    assert len(calls) == 1
    assert calls[0].executable.name == "fixture.exe"


def test_service_returns_unknown_for_missing_or_changed_elf(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path, b"source", b"elf")
    (tmp_path / "elf-tests" / "fixture.exe").write_bytes(b"changed")

    result = run_litmus_conformance(_request(tmp_path, manifest))

    assert result.status.value == "UNKNOWN"
    assert "SHA-256 mismatch" in result.cases[0].errors[0]


def test_service_runs_regular_static_pipeline_and_fixed_legality(
    tmp_path: Path, monkeypatch
) -> None:
    manifest = _write_manifest(tmp_path, b"source", b"elf")
    monkeypatch.setattr(
        "bmo_check_evaluation.litmus.service.slice_report",
        lambda request: _report(hashlib.sha256(b"elf").hexdigest()),
    )

    result = run_litmus_conformance(_request(tmp_path, manifest))

    case = result.cases[0]
    assert case.status.value == "MATCHED"
    assert case.conformance is not None
    assert case.executions[0].source_status == "allowed"
    assert case.executions[0].target_status == "allowed"
