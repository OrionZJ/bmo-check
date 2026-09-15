from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from bmo_check_core import (
    BinaryClosureId,
    CertificateVerdict,
    DynamicDiagnosticSnapshot,
    EvidenceSnapshot,
    InstructionId,
    MemoryOperandId,
    ModuleId,
    ObservedFact,
    ProducerId,
    StaticDiagnosticSnapshot,
    ThreadInstanceId,
    TraceId,
    UnknownFact,
    UnknownKind,
)
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.adapters.trace_binding import BoundDynamicEvidence
from bmo_check_dynamic.model import (
    BinaryFingerprint,
    DynamicCertificate,
    TraceManifest,
    TraceScope,
    TraceVerdict,
)
from bmo_check_static.application import StaticAnalysisResult, StaticRequest
from bmo_check_workflow.application import (
    HybridWorkflowError,
    HybridWorkflowRequest,
    WorkflowStage,
    analyze_workload,
)
from bmo_check_diagnostics import CorrelationStatus


HASH = "a" * 64
TRACE_HASH = "d" * 64


def _request(tmp_path: Path, *, application_only: bool = False) -> HybridWorkflowRequest:
    contract = tmp_path / "dbt6-mo-off.yaml"
    contract.write_text("schema: 1\ncontract_version: dbt6-mo-off-v1\n", encoding="utf-8")
    static = StaticRequest(
        executable=tmp_path / "program",
        dbt_contract=contract,
        pthread_spec=tmp_path / "pthread.yaml",
        function_effects=tmp_path / "effects.yaml",
        argv=("--input", "case.dat"),
        environment=(("WORKERS", "3"),),
        dbt_revision="b" * 40,
        scope="full",
    )
    return HybridWorkflowRequest(
        static_request=static,
        dynamorio_home=tmp_path / "dynamorio",
        client_path=tmp_path / "libbmo_trace.so",
        trace_dir=tmp_path / "trace",
        working_directory=tmp_path,
        max_thread_events=50_000,
        dynamic_config=DynamicConfig(application_only=application_only),
        max_snapshot_sites=1234,
    )


def _snapshot_pair(
    request: HybridWorkflowRequest,
    *,
    dynamic_scope: str = "full",
    dynamic_closure: BinaryClosureId | None = None,
) -> tuple[
    StaticDiagnosticSnapshot,
    TraceManifest,
    DynamicCertificate,
    BoundDynamicEvidence,
]:
    executable_hash = HASH
    closure = BinaryClosureId.from_parts(
        executable_hash,
        (("executable", executable_hash),),
        "EM_X86_64:elf64:le",
    )
    module = ModuleId.from_parts(executable_hash, "executable")
    subject = MemoryOperandId.from_parts(
        InstructionId.from_parts(module, 0x120), 0, "store"
    )
    unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "workflow"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="a static loop bound is unresolved",
        subject=subject,
        scope="full",
    )
    static = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v2",
        scope="full",
        verdict=CertificateVerdict.UNKNOWN,
        evidence=EvidenceSnapshot((unknown,)),
        binary_closure=closure,
        subject_ids=(subject,),
        blocking_unknown_ids=(unknown.id,),
    )

    executable = BinaryFingerprint(
        path=str(request.static_request.executable),
        sha256=executable_hash,
        build_id=None,
    )
    command = (str(request.static_request.executable), *request.static_request.argv)
    manifest = TraceManifest(
        trace_id="launcher-trace-001",
        platform="Linux-test",
        architecture="x86_64",
        command=command,
        working_directory=str(request.working_directory),
        environment=dict(request.static_request.environment),
        executable=executable,
        libraries=(),
        complete=True,
    )
    contract_hash = hashlib.sha256(
        request.static_request.dbt_contract.read_bytes()
    ).hexdigest()
    dynamic_certificate = DynamicCertificate(
        verdict=TraceVerdict.TRACE_SAFE,
        scope=TraceScope(
            trace_ids=(manifest.trace_id,),
            trace_sha256=(TRACE_HASH,),
            executable=executable,
            libraries=manifest.libraries,
            commands=(manifest.command,),
            working_directories=(manifest.working_directory,),
            analysis_scope=dynamic_scope,
        ),
        dbt_contract_sha256=contract_hash,
        analyzer_version="test",
        trace_complete=True,
        event_count=1,
        thread_count=1,
        object_count=1,
        unique_pc_count=1,
        communication_edge_count=0,
        indirect_target_count=0,
    )
    trace_id = TraceId.from_parts(
        "trace-v1",
        TRACE_HASH,
        (module,),
        (manifest.trace_id, "complete"),
        TRACE_HASH,
    )
    observed = ObservedFact.create(
        schema_version="observed-v1",
        producer=ProducerId("dynamic-test", "workflow"),
        trace_id=trace_id,
        execution_id=ThreadInstanceId.from_parts(trace_id, 1),
        subject=subject,
        observation_kind="memory-site",
    )
    dynamic_snapshot = DynamicDiagnosticSnapshot(
        schema_version="dynamic-diagnostic-v1",
        trace_id=trace_id,
        scope=f"dynamic.{dynamic_scope}",
        complete=True,
        evidence=EvidenceSnapshot((observed,)),
        binary_closure=dynamic_closure or closure,
    )
    bound = BoundDynamicEvidence(
        certificate=dynamic_certificate,
        manifest=manifest,
        snapshot=dynamic_snapshot,
        manifest_trace_id=manifest.trace_id,
        content_trace_id=trace_id,
        trace_sha256=TRACE_HASH,
        dbt_contract_sha256=contract_hash,
    )
    return static, manifest, dynamic_certificate, bound


def _install_route_stubs(
    monkeypatch: pytest.MonkeyPatch,
    request: HybridWorkflowRequest,
    *,
    dynamic_scope: str = "full",
    dynamic_closure: BinaryClosureId | None = None,
    static_has_certificate: bool = True,
    static_hook=None,
) -> tuple[
    list[str],
    StaticDiagnosticSnapshot,
    TraceManifest,
    DynamicCertificate,
    BoundDynamicEvidence,
]:
    static_snapshot, manifest, dynamic_certificate, bound = _snapshot_pair(
        request,
        dynamic_scope=dynamic_scope,
        dynamic_closure=dynamic_closure,
    )
    calls: list[str] = []

    def fake_static(actual_request, limits):
        assert actual_request is request.static_request
        calls.append("static")
        if static_hook is not None:
            static_hook()
        return StaticAnalysisResult(
            report=object(),
            legacy_certificate=object(),
            canonical_certificate=(
                SimpleNamespace(
                    certificate=SimpleNamespace(
                        schema_version="static-certificate-test"
                    )
                )
                if static_has_certificate
                else None
            ),
            canonical_error=(None if static_has_certificate else "DBT revision is unbound"),
        )

    def fake_static_snapshot(certificate):
        assert certificate is not None
        calls.append("static_snapshot")
        return static_snapshot

    def fake_capture(capture_request):
        calls.append("capture")
        assert capture_request.command == (
            str(request.static_request.executable.resolve()),
            *request.static_request.argv,
        )
        assert capture_request.output_dir == request.trace_dir
        assert capture_request.environment == request.static_request.environment
        assert capture_request.working_directory == request.working_directory
        assert capture_request.max_thread_events == request.max_thread_events
        return manifest

    def fake_dynamic(analyze_request):
        calls.append("dynamic")
        assert analyze_request.trace_dir == request.trace_dir
        assert analyze_request.dbt_contract == request.static_request.dbt_contract
        assert analyze_request.config is request.dynamic_config
        return dynamic_certificate

    def fake_bind(certificate, trace_dir, contract, *, max_sites):
        calls.append("bind")
        assert certificate is dynamic_certificate
        assert trace_dir == request.trace_dir
        assert contract == request.static_request.dbt_contract
        assert max_sites == request.max_snapshot_sites
        return bound

    monkeypatch.setattr(
        "bmo_check_workflow.application.analyze_with_evidence", fake_static
    )
    monkeypatch.setattr(
        "bmo_check_workflow.application.static_snapshot_from_certificate",
        fake_static_snapshot,
    )
    monkeypatch.setattr("bmo_check_workflow.application.capture_dynamic", fake_capture)
    monkeypatch.setattr("bmo_check_workflow.application.analyze_dynamic", fake_dynamic)
    monkeypatch.setattr(
        "bmo_check_workflow.application.bind_dynamic_certificate_to_trace", fake_bind
    )
    return calls, static_snapshot, manifest, dynamic_certificate, bound


def test_workflow_runs_existing_services_and_keeps_verdict_domains_separate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request = _request(tmp_path)
    calls, static_snapshot, _manifest, _certificate, _bound = _install_route_stubs(
        monkeypatch, request
    )

    result = analyze_workload(request)

    assert calls == ["static", "static_snapshot", "capture", "dynamic", "bind"]
    assert result.static_analysis.legacy_certificate is not None
    assert result.dynamic_evidence.certificate.verdict == TraceVerdict.TRACE_SAFE
    assert result.diagnostics is not None
    assert result.diagnostics.report.static_verdict == CertificateVerdict.UNKNOWN
    assert result.diagnostics.report.static_proof_unchanged is True
    assert result.diagnostics.report.records[0].status == CorrelationStatus.EXACT
    assert result.diagnostics.affine_report.static_verdict == static_snapshot.verdict
    assert result.static_policy_sha256_before == result.dynamic_evidence.dbt_contract_sha256
    assert result.static_policy_sha256_after == result.dynamic_evidence.dbt_contract_sha256
    assert result.dynamic_config is request.dynamic_config
    assert result.max_thread_events == request.max_thread_events
    assert result.max_snapshot_sites == request.max_snapshot_sites


def test_scope_mismatch_keeps_both_route_results_but_blocks_correlation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request = _request(tmp_path, application_only=True)
    _install_route_stubs(monkeypatch, request, dynamic_scope="application")

    result = analyze_workload(request)

    assert result.diagnostics is not None
    assert result.static_analysis.legacy_certificate is not None
    assert result.dynamic_evidence.certificate.verdict == TraceVerdict.TRACE_SAFE
    assert result.diagnostics.correlation_binding.status.value == "mismatch"
    record = result.diagnostics.report.records[0]
    assert record.status == CorrelationStatus.UNMATCHED
    assert record.observed_ids == ()
    assert "analysis_scope" in record.reason


def test_contract_change_during_static_analysis_prevents_exact_correlation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request = _request(tmp_path)

    def change_contract() -> None:
        request.static_request.dbt_contract.write_text(
            "schema: 1\ncontract_version: changed-v2\n", encoding="utf-8"
        )

    _install_route_stubs(monkeypatch, request, static_hook=change_contract)

    result = analyze_workload(request)

    assert result.diagnostics is not None
    assert result.diagnostics.correlation_binding.status.value == "unverified"
    assert result.static_policy_sha256_before != result.static_policy_sha256_after
    record = result.diagnostics.report.records[0]
    assert record.status == CorrelationStatus.AMBIGUOUS
    assert record.observed_ids
    assert "changed during static analysis" in record.reason


def test_static_without_canonical_certificate_retains_dynamic_result_explicitly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request = _request(tmp_path)
    calls, _snapshot, _manifest, _certificate, _bound = _install_route_stubs(
        monkeypatch,
        request,
        static_has_certificate=False,
    )

    result = analyze_workload(request)

    assert calls == ["static", "capture", "dynamic", "bind"]
    assert result.diagnostics is None
    assert result.diagnostics_unavailable_reason == "DBT revision is unbound"
    assert result.dynamic_evidence.certificate.verdict == TraceVerdict.TRACE_SAFE


def test_capture_failure_is_a_workflow_error_not_a_synthetic_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request = _request(tmp_path)
    _install_route_stubs(monkeypatch, request)

    def fail_capture(_capture_request):
        raise OSError("DynamoRIO launcher is unavailable")

    monkeypatch.setattr("bmo_check_workflow.application.capture_dynamic", fail_capture)

    with pytest.raises(HybridWorkflowError) as error:
        analyze_workload(request)

    assert error.value.stage == WorkflowStage.TRACE_CAPTURE
    assert "DynamoRIO launcher is unavailable" in str(error.value)
