from __future__ import annotations

from pathlib import Path

import pytest

from bmo_check_evaluation import EvaluationApplicationError, ParsecEvaluationRequest
from bmo_check_dynamic.application import (
    AnalyzeRequest,
    CaptureRequest,
    analyze as analyze_dynamic,
    capture as capture_dynamic,
)
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_static.application import StaticApplicationError, StaticRequest
from bmo_check_static.application import analyze as analyze_static
from bmo_check_static.application import analyze_with_evidence
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
)


def test_static_request_rejects_unscoped_analysis() -> None:
    try:
        StaticRequest(
            executable=Path("/bin/program"),
            dbt_contract=Path("/tmp/dbt.yaml"),
            pthread_spec=Path("/tmp/pthread.yaml"),
            function_effects=Path("/tmp/effects.yaml"),
            scope="unknown",
        )
    except StaticApplicationError as error:
        assert "scope" in str(error)
    else:
        raise AssertionError("invalid static scope was accepted")


def test_dynamic_capture_service_passes_typed_request(monkeypatch, tmp_path: Path) -> None:
    manifest = object()
    captured: dict[str, object] = {}

    def fake_capture(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return manifest

    monkeypatch.setattr("bmo_check_dynamic.application.capture_program", fake_capture)
    request = CaptureRequest(
        command=("/bin/program", "--input"),
        output_dir=tmp_path / "trace",
        dynamorio_home=tmp_path / "dr",
        client_path=tmp_path / "client.so",
        environment=(("MODE", "test"),),
    )

    assert capture_dynamic(request) is manifest
    assert captured["args"] == (request.command, request.output_dir)
    assert captured["kwargs"] == {
        "dynamorio_home": request.dynamorio_home,
        "client_path": request.client_path,
        "environment": {"MODE": "test"},
        "working_directory": None,
        "max_thread_events": None,
    }


def test_dynamic_analyze_service_passes_typed_request(monkeypatch, tmp_path: Path) -> None:
    expected = object()
    captured: dict[str, object] = {}

    def fake_analyze(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return expected

    monkeypatch.setattr("bmo_check_dynamic.application.analyze_trace", fake_analyze)
    request = AnalyzeRequest(
        trace_dir=tmp_path / "trace",
        dbt_contract=tmp_path / "contract.yaml",
        config=DynamicConfig(),
    )

    assert analyze_dynamic(request) is expected
    assert captured["args"] == (request.trace_dir,)
    assert captured["kwargs"] == {
        "dbt_contract": request.dbt_contract,
        "config": request.config,
    }


def test_parsec_evaluation_request_round_trips_explicit_worker_payload(
    tmp_path: Path,
) -> None:
    request = ParsecEvaluationRequest(
        suite=tmp_path / "suite.yaml",
        parsec_root=tmp_path / "parsec",
        dbt_contract=tmp_path / "dbt.yaml",
        pthread_spec=tmp_path / "pthread.yaml",
        function_effects=tmp_path / "effects.yaml",
        output_dir=tmp_path / "out",
        benchmark_ids=("fixture",),
        library_roots=(tmp_path / "lib",),
        threads_override=2,
        environment=(("MODE", "test"),),
        dbt_revision="a" * 40,
        scope="application",
        run_native=True,
        analysis_memory_limit_mb=128,
        in_process=True,
    )

    assert ParsecEvaluationRequest.from_payload(request.to_payload()) == request


def test_parsec_evaluation_request_rejects_invalid_resource_limit(
    tmp_path: Path,
) -> None:
    with pytest.raises(EvaluationApplicationError, match="max_events"):
        ParsecEvaluationRequest(
            suite=tmp_path / "suite.yaml",
            parsec_root=tmp_path / "parsec",
            dbt_contract=tmp_path / "dbt.yaml",
            pthread_spec=tmp_path / "pthread.yaml",
            function_effects=tmp_path / "effects.yaml",
            output_dir=tmp_path / "out",
            max_events=0,
        )


def _static_service_report(*, dbt_revision: str | None = "b" * 40) -> ProgramSliceReport:
    module = ModuleFingerprint(
        path="/bin/static-service-fixture",
        role=ModuleRole.EXECUTABLE,
        size=1,
        sha256="a" * 64,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    manifest = ProgramManifest(
        executable=module,
        execution=ExecutionScope(argv=(module.path,), thread_count_min=1),
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision=dbt_revision,
        closure_complete=True,
    )
    return ProgramSliceReport(
        recovery=ProgramRecoveryReport(manifest=manifest),
        memory_events=MemoryEventReport(
            module_path=module.path,
            module_sha256=module.sha256,
        ),
        shared_state=SharedStateReport(),
        shared_slice=SharedMemorySlice(
            coverage=PruningCoverage(total_events=0),
        ),
    )


def _static_service_request(tmp_path: Path) -> StaticRequest:
    contract = tmp_path / "contract.yaml"
    contract.write_text("schema: 1\ncontract_version: test-v1\n", encoding="utf-8")
    pthread = tmp_path / "pthread.yaml"
    pthread.write_text("schema: 1\napis: {}\n", encoding="utf-8")
    effects = tmp_path / "effects.yaml"
    effects.write_text("schema: 1\nfunctions: {}\n", encoding="utf-8")
    return StaticRequest(
        executable=tmp_path / "fixture",
        dbt_contract=contract,
        pthread_spec=pthread,
        function_effects=effects,
        dbt_revision="b" * 40,
    )


def test_static_analyze_service_downgrades_unreplayable_legacy_certificate(
    monkeypatch, tmp_path: Path
) -> None:
    request = _static_service_request(tmp_path)
    report = _static_service_report()
    monkeypatch.setattr("bmo_check_static.application.slice_report", lambda *args, **kwargs: report)

    result = analyze_with_evidence(request)

    assert result.legacy_certificate.verdict.value == "UNKNOWN"
    assert result.canonical_certificate is None
    assert result.canonical_error is not None
    assert "explain-only" in result.canonical_error
    assert analyze_static(request).verdict.value == "UNKNOWN"


def test_static_analyze_service_records_unbound_revision_without_fabricating_binding(
    monkeypatch, tmp_path: Path
) -> None:
    request = _static_service_request(tmp_path)
    report = _static_service_report(dbt_revision=None)
    monkeypatch.setattr("bmo_check_static.application.slice_report", lambda *args, **kwargs: report)

    result = analyze_with_evidence(request)

    assert result.legacy_certificate.verdict.value == "UNKNOWN"
    assert result.canonical_certificate is None
    assert result.canonical_error == "static certificate requires a DBT revision"
