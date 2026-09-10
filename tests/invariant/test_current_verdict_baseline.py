from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import (
    BinaryFingerprint,
    TraceManifest,
    TraceVerdict,
)
from bmo_check_dynamic.pipeline import analyze_trace
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.trace import TraceWriter
from bmo_check_static.model import (
    ElfMetadata,
    ExecutionScope,
    MemoryEventReport,
    ModuleFingerprint,
    ModuleRole,
    PruningCoverage,
    ProgramManifest,
    ProgramRecoveryReport,
    ProgramSliceReport,
    SharedMemorySlice,
    SharedStateReport,
    UnknownFact,
    UnknownKind,
)
from bmo_check_static.proof import verify_portability


HASH = "a" * 64


def _write_trace_manifest(
    trace_dir: Path, *, complete: bool
) -> TraceManifest:
    trace_dir.mkdir(parents=True, exist_ok=True)
    executable = trace_dir.parent / "program"
    executable.write_bytes(b"BMoCheck C1 trace fixture")
    manifest = TraceManifest(
        trace_id="c1-trace",
        platform="Linux-test",
        command=(str(executable),),
        working_directory=str(trace_dir.parent),
        executable=BinaryFingerprint(
            path=str(executable),
            sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        ),
        complete=complete,
    )
    manifest.save(trace_dir / "manifest.json")
    return manifest


def _static_report(unknowns: tuple[UnknownFact, ...] = ()) -> ProgramSliceReport:
    module = ModuleFingerprint(
        path="/bin/bmo-baseline",
        role=ModuleRole.EXECUTABLE,
        size=1,
        sha256=HASH,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    manifest = ProgramManifest(
        executable=module,
        execution=ExecutionScope(argv=("bmo-baseline",), thread_count_min=1),
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision="b" * 40,
        closure_complete=True,
        unknowns=unknowns,
    )
    return ProgramSliceReport(
        recovery=ProgramRecoveryReport(manifest=manifest),
        memory_events=MemoryEventReport(
            module_path=module.path,
            module_sha256=module.sha256,
            unknowns=unknowns,
        ),
        shared_state=SharedStateReport(unknowns=unknowns),
        shared_slice=SharedMemorySlice(
            coverage=PruningCoverage(total_events=0, remaining_shared_events=0),
            unknowns=unknowns,
        ),
    )


def test_static_verdict_and_certificate_shape_are_characterized() -> None:
    certificate = verify_portability(_static_report())
    payload = json.loads(certificate.model_dump_json())

    assert certificate.verdict.value == "SAFE"
    assert certificate.checker.conclusion.value == "StructuralSafe"
    assert certificate.checker.bounded is False
    assert certificate.coverage.memory_events == 0
    assert certificate.coverage.shared_events == 0
    assert payload["verdict"] == "SAFE"
    assert payload["relevant_unknowns"] == []
    assert type(certificate).model_validate_json(certificate.model_dump_json()) == certificate


def test_static_unknown_is_visible_in_certificate_baseline() -> None:
    unknown = UnknownFact(
        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
        reason="baseline helper has no memory-effect summary",
        impact="the helper may communicate through shared memory",
        module="/bin/bmo-baseline",
        pc=0x401000,
    )
    certificate = verify_portability(_static_report((unknown,)))

    assert certificate.verdict.value == "UNKNOWN"
    assert len(certificate.relevant_unknowns) == 1
    assert certificate.relevant_unknowns[0].kind == UnknownKind.UNKNOWN_MEMORY_EFFECT
    assert certificate.coverage.memory_events == 0


def test_dynamic_single_thread_verdict_and_counts_are_characterized(
    tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = _write_trace_manifest(trace_dir, complete=True)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x1000, EventKind.LOAD, 0x2000, 4))
    contract = tmp_path / "contract.yaml"
    shutil.copyfile(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml",
        contract,
    )

    certificate = analyze_trace(
        trace_dir,
        dbt_contract=contract,
        config=DynamicConfig(),
    )
    payload = json.loads(certificate.model_dump_json())

    assert certificate.verdict == TraceVerdict.TRACE_SAFE
    assert certificate.trace_complete is True
    assert certificate.event_count == 1
    assert certificate.thread_count == 1
    assert certificate.communication_edge_count == 0
    assert payload["verdict"] == "TRACE_SAFE"
    assert type(certificate).model_validate_json(certificate.model_dump_json()) == certificate
    assert manifest.trace_id == certificate.scope.trace_ids[0]


def test_dynamic_incomplete_trace_remains_unknown(tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    _write_trace_manifest(trace_dir, complete=False)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x1000, EventKind.LOAD, 0x2000, 4))
    contract = tmp_path / "contract.yaml"
    shutil.copyfile(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml",
        contract,
    )

    certificate = analyze_trace(trace_dir, dbt_contract=contract)

    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert certificate.trace_complete is False
    assert certificate.unknown_reasons
    assert any("clean process exit" in reason for reason in certificate.unknown_reasons)
