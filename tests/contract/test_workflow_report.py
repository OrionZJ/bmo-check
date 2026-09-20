from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from bmo_check_core import (
    BindingCheck,
    BindingDimension,
    BindingStatus,
    BinaryClosureId,
    CertificateBinding,
    CertificateVerdict,
    CorrelationBinding,
    DynamicDiagnosticSnapshot,
    EvidenceAttribute,
    EvidenceLedger,
    EvidenceSnapshot,
    InstructionId,
    MemoryOperandId,
    ModuleId,
    ObservedFact,
    ProducerId,
    StaticCertificate,
    StaticDiagnosticSnapshot,
    ThreadInstanceId,
    TraceId,
    UnknownFact,
    UnknownKind,
    verify_static_certificate,
)
from bmo_check_diagnostics import (
    build_affine_validation_report,
    build_diagnostic_report,
)
from bmo_check_diagnostics.affine import affine_report_to_dict
from bmo_check_diagnostics.correlation import CorrelationStatus
from bmo_check_diagnostics.serialization import report_to_dict
from bmo_check_dynamic.adapters.trace_binding import BoundDynamicEvidence
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import (
    BinaryFingerprint,
    DynamicCertificate,
    TraceManifest,
    TraceScope,
    TraceVerdict,
)
from bmo_check_static.application import StaticAnalysisResult
from bmo_check_static.model import (
    CertificateCoverage,
    CertificateScope,
    CheckerConclusion,
    CheckerLimits,
    CheckerReport,
    PortabilityCertificate,
    UnknownFact as LegacyUnknownFact,
    UnknownKind as LegacyUnknownKind,
    Verdict,
)
from bmo_check_static.proof.certificate_bridge import StaticCertificateEvidence
from bmo_check_workflow import (
    DiagnosticProducts,
    HybridReportError,
    HybridWorkflowReport,
    HybridWorkflowResult,
    build_hybrid_workflow_report,
    hybrid_report_from_dict,
    hybrid_report_from_json,
    load_hybrid_workflow_report,
    save_hybrid_workflow_report,
)
from bmo_check_workflow.report import CanonicalStaticCertificateSummary


HASH = "a" * 64
TRACE_HASH = "d" * 64
CONTRACT_HASH = "c" * 64
DBT_REVISION = "b" * 40


def test_workflow_static_v2_summary_preserves_completeness_digests() -> None:
    kwargs = dict(
        schema_version="static-certificate-v2",
        verdict=CertificateVerdict.SAFE,
        binary_closure_id="closure",
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision=DBT_REVISION,
        scope="full",
        proof_root_ids=(),
        proof_closure_ids=(),
        removal_decisions=(),
        relevant_unknown_ids=(),
        discharged_unknown_ids=(),
        bounded=False,
    )
    with pytest.raises(ValueError, match="completeness digests"):
        CanonicalStaticCertificateSummary(**kwargs)

    summary = CanonicalStaticCertificateSummary(
        **kwargs,
        event_universe_sha256=HASH,
        obligation_sha256=HASH,
        unknown_sha256=HASH,
        projection_sha256=HASH,
    )
    assert summary.projection_sha256 == HASH


def _result(
    tmp_path: Path,
    *,
    dynamic_scope: str = "full",
    canonical_static: bool = True,
    capture_complete: bool = True,
    certificate_trace_complete: bool = True,
    diagnostic_snapshot_complete: bool = True,
) -> HybridWorkflowResult:
    closure = BinaryClosureId.from_parts(
        HASH,
        (("executable", HASH),),
        "EM_X86_64:elf64:le",
    )
    module = ModuleId.from_parts(HASH, "executable")
    instruction = InstructionId.from_parts(module, 0x120)
    subject = MemoryOperandId.from_parts(instruction, 0, "load")
    unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "workflow-report"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="loop upper bound is not statically closed",
        subject=subject,
        scope="full",
        supporting_context=("loop upper bound is missing",),
    )
    static_snapshot = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v2",
        scope="full",
        verdict=CertificateVerdict.UNKNOWN,
        evidence=EvidenceSnapshot((unknown,)),
        binary_closure=closure,
        subject_ids=(subject,),
        blocking_unknown_ids=(unknown.id,),
    )

    executable = BinaryFingerprint(
        path=str(tmp_path / "program"),
        sha256=HASH,
        build_id="build-test",
    )
    command = (str(tmp_path / "program"), "--case", "1")
    working_directory = str(tmp_path)
    manifest = TraceManifest(
        trace_id="launcher-trace-001",
        platform="Linux-test",
        architecture="x86_64",
        command=command,
        working_directory=working_directory,
        environment={"WORKERS": "3", "TOKEN": "secret-value-for-test"},
        executable=executable,
        libraries=(),
        dynamorio_version="11.3.0",
        client_version="test-client",
        complete=capture_complete,
        exit_code=0,
        dropped_events=0,
        dropped_by_reason={},
        control_flow_closed=True,
    )
    contract_digest = hashlib.sha256(b"dbt6-mo-off-v1 test contract").hexdigest()
    certificate = DynamicCertificate(
        verdict=(
            TraceVerdict.TRACE_SAFE
            if certificate_trace_complete
            else TraceVerdict.UNKNOWN
        ),
        scope=TraceScope(
            trace_ids=(manifest.trace_id,),
            trace_sha256=(TRACE_HASH,),
            executable=executable,
            libraries=(),
            commands=(command,),
            working_directories=(working_directory,),
            analysis_scope=dynamic_scope,
        ),
        dbt_contract_sha256=contract_digest,
        analyzer_version="test-analyzer",
        trace_complete=certificate_trace_complete,
        event_count=2,
        thread_count=1,
        object_count=1,
        unique_pc_count=1,
        communication_edge_count=0,
        indirect_target_count=0,
        unknown_reasons=(
            ()
            if certificate_trace_complete
            else ("trace structure could not be validated",)
        ),
    )
    content_trace_id = TraceId.from_parts(
        "trace-v1",
        TRACE_HASH,
        (module,),
        (manifest.trace_id, "complete"),
        TRACE_HASH,
    )
    observed = ObservedFact.create(
        schema_version="dynamic-observed-v1",
        producer=ProducerId("dynamic-test", "workflow-report"),
        trace_id=content_trace_id,
        execution_id=ThreadInstanceId.from_parts(content_trace_id, 1),
        subject=subject,
        observation_kind="memory-site",
        attributes=(
            EvidenceAttribute("sample_count", "2"),
            EvidenceAttribute("address_samples", "0x1000,0x1040"),
            EvidenceAttribute("sample_complete", "true"),
        ),
    )
    diagnostic_nodes = (observed,)
    if not diagnostic_snapshot_complete:
        diagnostic_nodes += (
            UnknownFact.create(
                schema_version="unknown-v1",
                producer=ProducerId("dynamic-test", "workflow-report"),
                kind=UnknownKind.UNSUPPORTED_INPUT,
                reason="module has no bound fingerprint: [vdso]",
                subject=None,
                scope=f"dynamic.{dynamic_scope}",
            ),
        )
    dynamic_snapshot = DynamicDiagnosticSnapshot(
        schema_version="dynamic-diagnostic-v1",
        trace_id=content_trace_id,
        scope=f"dynamic.{dynamic_scope}",
        complete=diagnostic_snapshot_complete,
        evidence=EvidenceSnapshot(diagnostic_nodes),
        binary_closure=closure,
    )
    bound = BoundDynamicEvidence(
        certificate=certificate,
        manifest=manifest,
        snapshot=dynamic_snapshot,
        manifest_trace_id=manifest.trace_id,
        content_trace_id=content_trace_id,
        trace_sha256=TRACE_HASH,
        dbt_contract_sha256=contract_digest,
    )

    legacy_unknown = LegacyUnknownFact(
        kind=LegacyUnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason=unknown.reason,
        impact="shared address range is not proven",
        module="program",
        pc=0x120,
        function="worker",
    )
    legacy_scope = CertificateScope(
        executable_sha256=HASH,
        library_sha256=(),
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision=DBT_REVISION if canonical_static else "",
        argv=command[1:],
        analysis_scope="full",
    )
    legacy_certificate = PortabilityCertificate(
        verdict=Verdict.UNKNOWN,
        scope=legacy_scope,
        coverage=CertificateCoverage(
            modules=1,
            functions=1,
            thread_roles=1,
            memory_events=2,
            shared_events=2,
            shared_objects=1,
        ),
        checker=CheckerReport(
            backend="finite-enumerator",
            backend_version="test",
            bounded=True,
            limits=CheckerLimits(),
            conclusion=CheckerConclusion.INCOMPLETE,
            reason="one static address bound remains open",
        ),
        relevant_unknowns=(legacy_unknown,),
    )

    canonical_evidence = None
    canonical_error = "DBT revision is unbound"
    products = None
    if canonical_static:
        static_certificate = StaticCertificate(
            schema_version="static-certificate-1",
            verdict=CertificateVerdict.UNKNOWN,
            binding=CertificateBinding(
                binary_closure=closure,
                dbt_contract_version="dbt6-mo-off-v1",
                dbt_revision=DBT_REVISION,
                scope="full",
            ),
            relevant_unknowns=(unknown.id,),
            bounded=True,
        )
        ledger = EvidenceLedger()
        ledger.add(unknown)
        verification = verify_static_certificate(static_certificate, ledger)
        canonical_evidence = StaticCertificateEvidence(
            certificate=static_certificate,
            ledger=ledger,
            verification=verification,
        )
        canonical_error = None
        binding = CorrelationBinding(
            checks=(
                BindingCheck(
                    BindingDimension.BINARY_CLOSURE,
                    BindingStatus.MATCH,
                    "static and trace snapshots bind the same module closure",
                ),
                BindingCheck(
                    BindingDimension.TRANSLATION_POLICY,
                    BindingStatus.MATCH,
                    "both routes bind the same DBT contract bytes",
                ),
                BindingCheck(
                    BindingDimension.ANALYSIS_SCOPE,
                    BindingStatus.MATCH if dynamic_scope == "full" else BindingStatus.MISMATCH,
                    "scope comparison from the workflow fixture",
                ),
            )
        )
        d4 = build_diagnostic_report(
            static_snapshot,
            dynamic_snapshot,
            static_certificate_schema_version=static_certificate.schema_version,
            trace_certificate_schema_version=certificate.schema_version,
            trace_certificate_sha256=TRACE_HASH,
            correlation_binding=binding,
        )
        affine = build_affine_validation_report(
            static_snapshot,
            dynamic_snapshot,
            correlations=(d4.correlations,),
        )
        products = DiagnosticProducts(
            static_snapshot=static_snapshot,
            correlation_binding=binding,
            report=d4,
            affine_report=affine,
        )

    static_analysis = StaticAnalysisResult(
        report=SimpleNamespace(
            recovery=SimpleNamespace(
                manifest=SimpleNamespace(
                    execution=SimpleNamespace(
                        environment=dict(manifest.environment)
                    )
                )
            )
        ),
        legacy_certificate=legacy_certificate,
        canonical_certificate=canonical_evidence,
        canonical_error=canonical_error,
    )
    return HybridWorkflowResult(
        static_analysis=static_analysis,
        dynamic_evidence=bound,
        diagnostics=products,
        diagnostics_unavailable_reason=(
            None if products is not None else "DBT revision is unbound"
        ),
        trace_dir=tmp_path / "trace",
        static_policy_sha256_before=contract_digest,
        static_policy_sha256_after=contract_digest,
        dynamic_config=DynamicConfig(database_path=tmp_path / "trace.duckdb"),
        max_thread_events=50_000,
        max_snapshot_sites=5_000,
    )


def test_hybrid_report_keeps_route_results_and_d4_e1_children_round_trip(
    tmp_path: Path,
) -> None:
    result = _result(tmp_path)
    report = build_hybrid_workflow_report(result)
    payload = report.to_dict()

    assert report.schema_version == "hybrid-workflow-report-v2"
    assert report.static.verdict == CertificateVerdict.UNKNOWN
    assert report.dynamic.certificate.verdict == TraceVerdict.TRACE_SAFE
    assert report.static.blocking_unknowns[0].identity_source.value == "canonical_evidence"
    assert report.static.blocking_unknowns[0].evidence_id
    assert report.diagnostics is not None
    assert payload["diagnostics"]["d4_report"]["schema_version"] == "diagnostic-report-v3"
    assert payload["diagnostics"]["affine_report"]["schema_version"] == "affine-validation-report-v1"
    assert payload["diagnostics"]["d4_report"] == report_to_dict(
        result.diagnostics.report
    )
    assert payload["diagnostics"]["affine_report"] == affine_report_to_dict(
        result.diagnostics.affine_report
    )
    assert payload["diagnostics"]["d4_report"]["correlations"]["records"][0]["status"] == "Exact"
    assert payload["diagnostics"]["root_cause_assessments"][0]["causal_status"] == (
        "causal_relation_unresolved"
    )
    assert "secret-value-for-test" not in report.to_json()
    assert report.static.scope.environment == report.dynamic.manifest.environment
    assert report.dynamic.analysis_limits.database_path == str(tmp_path / "trace.duckdb")
    assert report.dynamic.capture_max_thread_events == 50_000
    assert report.dynamic.diagnostic_max_snapshot_sites == 5_000
    assert "verdict" not in HybridWorkflowReport.model_fields

    restored = hybrid_report_from_json(report.to_json())
    assert restored == report
    out_path = tmp_path / "report" / "hybrid.json"
    save_hybrid_workflow_report(report, out_path)
    assert load_hybrid_workflow_report(out_path) == report


def test_diagnostic_snapshot_may_be_incomplete_for_a_structurally_complete_trace(
    tmp_path: Path,
) -> None:
    report = build_hybrid_workflow_report(
        _result(tmp_path, diagnostic_snapshot_complete=False)
    )

    assert report.dynamic.manifest.complete
    assert report.dynamic.certificate.trace_complete
    assert report.diagnostics is not None
    d4 = report.diagnostics.d4_report
    assert not d4.trace_complete
    assert [item.reason for item in d4.dynamic_unknowns] == [
        "module has no bound fingerprint: [vdso]"
    ]


def test_hybrid_report_rejects_completeness_claims_that_exceed_their_input(
    tmp_path: Path,
) -> None:
    with pytest.raises(HybridReportError, match="capture manifest is incomplete"):
        build_hybrid_workflow_report(
            _result(tmp_path, capture_complete=False)
        )

    with pytest.raises(HybridReportError, match="structurally incomplete trace"):
        build_hybrid_workflow_report(
            _result(
                tmp_path,
                certificate_trace_complete=False,
                diagnostic_snapshot_complete=True,
            )
        )


def test_hybrid_report_rejects_unknown_schema_and_implicit_combined_verdict(
    tmp_path: Path,
) -> None:
    report = build_hybrid_workflow_report(_result(tmp_path))
    payload = report.to_dict()
    unsupported = copy.deepcopy(payload)
    unsupported["schema_version"] = "hybrid-workflow-report-v9"
    with pytest.raises(ValueError, match="invalid hybrid workflow report"):
        hybrid_report_from_dict(unsupported)

    combined = copy.deepcopy(payload)
    combined["combined_verdict"] = "SAFE"
    with pytest.raises(ValueError, match="invalid hybrid workflow report"):
        hybrid_report_from_dict(combined)

    changed_child_schema = copy.deepcopy(payload)
    changed_child_schema["diagnostics"]["d4_report"]["schema_version"] = (
        "diagnostic-report-v99"
    )
    with pytest.raises(ValueError, match="invalid hybrid workflow report"):
        hybrid_report_from_dict(changed_child_schema)

    changed_statement = copy.deepcopy(payload)
    changed_statement["diagnostics"]["affine_report"]["statement"] = "SAFE"
    with pytest.raises(ValueError, match="invalid hybrid workflow report"):
        hybrid_report_from_dict(changed_statement)

    changed_argv = copy.deepcopy(payload)
    changed_argv["static"]["scope"]["argv"][0] = "different-input"
    with pytest.raises(ValueError, match="different argv"):
        hybrid_report_from_dict(changed_argv)

    changed_environment = copy.deepcopy(payload)
    changed_environment["dynamic"]["manifest"]["environment"][0][
        "value_sha256"
    ] = "e" * 64
    with pytest.raises(ValueError, match="different environments"):
        hybrid_report_from_dict(changed_environment)


def test_hybrid_report_rejects_cross_trace_and_observation_in_proof_closure(
    tmp_path: Path,
) -> None:
    payload = build_hybrid_workflow_report(_result(tmp_path)).to_dict()
    wrong_trace = copy.deepcopy(payload)
    wrong_trace["dynamic"]["content_trace_id"] = "trace:another-execution"
    with pytest.raises(ValueError, match="D4 report is bound to another trace"):
        hybrid_report_from_dict(wrong_trace)

    observed_as_proof = copy.deepcopy(payload)
    observed_id = observed_as_proof["diagnostics"]["d4_report"]["observed_facts"][0]["id"]
    observed_as_proof["static"]["canonical_certificate"]["proof_closure_ids"] = [
        observed_id
    ]
    with pytest.raises(ValueError, match="dynamic evidence and hints"):
        hybrid_report_from_dict(observed_as_proof)

    hint_as_proof = copy.deepcopy(payload)
    hint_id = hint_as_proof["diagnostics"]["d4_report"]["hints"][0]["id"]
    hint_as_proof["static"]["canonical_certificate"]["proof_closure_ids"] = [
        hint_id
    ]
    with pytest.raises(ValueError, match="dynamic evidence and hints"):
        hybrid_report_from_dict(hint_as_proof)


def test_hybrid_report_requires_verified_route_binding_and_consistent_coverage(
    tmp_path: Path,
) -> None:
    payload = build_hybrid_workflow_report(
        _result(tmp_path, dynamic_scope="application")
    ).to_dict()

    missing_binding = copy.deepcopy(payload)
    missing_binding["diagnostics"]["d4_report"]["correlations"]["binding"] = None
    with pytest.raises(ValueError, match="explicit cross-route binding"):
        hybrid_report_from_dict(missing_binding)

    unverified_scope = copy.deepcopy(payload)
    checks = unverified_scope["diagnostics"]["d4_report"]["correlations"]["binding"]["checks"]
    for check in checks:
        if check["dimension"] == "analysis_scope":
            check["status"] = "unverified"
    unverified_scope["diagnostics"]["d4_report"]["correlations"]["binding"]["status"] = (
        "unverified"
    )
    with pytest.raises(ValueError, match="scope binding status differs"):
        hybrid_report_from_dict(unverified_scope)

    wrong_policy_binding = copy.deepcopy(
        build_hybrid_workflow_report(_result(tmp_path)).to_dict()
    )
    wrong_policy_binding["static"]["scope"]["dbt_contract_sha256_after"] = "e" * 64
    with pytest.raises(ValueError, match="translation-policy binding differs"):
        hybrid_report_from_dict(wrong_policy_binding)

    inconsistent_coverage = build_hybrid_workflow_report(_result(tmp_path)).to_dict()
    assert inconsistent_coverage["diagnostics"]["affine_report"]["coverage"][
        "exercised_count"
    ] == 1
    inconsistent_coverage["diagnostics"]["affine_report"]["coverage"][
        "exercised_count"
    ] = 0
    inconsistent_coverage["diagnostics"]["affine_report"]["coverage"][
        "unmatched_count"
    ] = 1
    with pytest.raises(ValueError, match="E1 coverage counts differ"):
        hybrid_report_from_dict(inconsistent_coverage)


def test_scope_mismatch_is_reported_without_claiming_exact_correlation(
    tmp_path: Path,
) -> None:
    report = build_hybrid_workflow_report(
        _result(tmp_path, dynamic_scope="application")
    )

    assert report.diagnostics is not None
    binding = report.diagnostics.d4_report.correlations.binding
    assert binding is not None
    analysis_scope = next(item for item in binding.checks if item.dimension == "analysis_scope")
    assert analysis_scope.status == "mismatch"
    assert report.diagnostics.d4_report.correlations.records[0].status == (
        CorrelationStatus.UNMATCHED
    )
    assert report.diagnostics.root_cause_assessments[0].causal_status.value == (
        "causal_relation_unresolved"
    )


def test_report_without_canonical_static_certificate_exposes_legacy_unknowns(
    tmp_path: Path,
) -> None:
    report = build_hybrid_workflow_report(
        _result(tmp_path, canonical_static=False)
    )

    assert report.diagnostics is None
    assert report.diagnostics_unavailable_reason == "DBT revision is unbound"
    blocker = report.static.blocking_unknowns[0]
    assert blocker.identity_source.value == "legacy_report"
    assert blocker.evidence_id is None
    assert blocker.kind == "UnknownAffineBounds"
