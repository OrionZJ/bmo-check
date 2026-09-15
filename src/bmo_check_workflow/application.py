"""把既有 static、dynamic 和 diagnostics application services 串成一次运行。

这个包不分析 MemoryEvent，也不创建 proof 或 observation。它只把同一 workload
请求送入两条独立路线，再把各自产生的不可变结果交给诊断服务。
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TypeVar

from bmo_check_core import (
    BindingCheck,
    BindingDimension,
    BindingStatus,
    CorrelationBinding,
)
from bmo_check_core.diagnostics import DynamicDiagnosticSnapshot, StaticDiagnosticSnapshot
from bmo_check_diagnostics import (
    AffineValidationReport,
    DiagnosticReport,
    build_affine_validation_report,
    build_diagnostic_report,
)
from bmo_check_dynamic.adapters.trace_binding import (
    BoundDynamicEvidence,
    bind_dynamic_certificate_to_trace,
)
from bmo_check_dynamic.application import (
    AnalyzeRequest,
    CaptureRequest,
    analyze as analyze_dynamic,
    capture as capture_dynamic,
)
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import DynamicCertificate, TraceManifest
from bmo_check_static.adapters.diagnostic_snapshot import static_snapshot_from_certificate
from bmo_check_static.application import (
    StaticAnalysisResult,
    StaticRequest,
    analyze_with_evidence,
)
from bmo_check_static.model import CheckerLimits


class WorkflowStage(StrEnum):
    """指出一次 workflow 在哪条既有 route 或连接边界失败。"""

    INPUT = "input"
    STATIC_ANALYSIS = "static_analysis"
    TRACE_CAPTURE = "trace_capture"
    TRACE_ANALYSIS = "trace_analysis"
    EVIDENCE_BINDING = "evidence_binding"
    DIAGNOSTICS = "diagnostics"


class HybridWorkflowError(RuntimeError):
    """编排失败；route 返回的 UNKNOWN 仍是正常分析结果，不会变成该错误。"""

    def __init__(self, stage: WorkflowStage, reason: str) -> None:
        if not isinstance(stage, WorkflowStage):
            raise TypeError("workflow error stage must be a WorkflowStage")
        if not isinstance(reason, str) or not reason or "\x00" in reason:
            raise ValueError("workflow error reason must be non-empty")
        self.stage = stage
        self.reason = reason
        super().__init__(f"{stage.value}: {reason}")


@dataclass(frozen=True, slots=True)
class HybridWorkflowRequest:
    """一份 workload 的静态设置和动态采集资源。"""

    # static_request 是两条 route 共用的 executable、argv、environment 和契约来源。
    static_request: StaticRequest
    # dynamorio_home 指定捕获器使用的 DynamoRIO 安装目录。
    dynamorio_home: Path
    # client_path 指定已构建的 BMoCheck DynamoRIO client。
    client_path: Path
    # trace_dir 是唯一一条动态执行的落盘目录，必须由 capture 首次创建。
    trace_dir: Path
    # working_directory 只影响实际动态启动，不会伪装成静态证明范围。
    working_directory: Path | None
    # max_thread_events 是采集上限；触顶后的结果由动态 route 标成 UNKNOWN。
    max_thread_events: int | None
    # dynamic_config 沿用既有动态 solver 和存储预算。
    dynamic_config: DynamicConfig
    # checker_limits 沿用静态 checker 的搜索预算。
    checker_limits: CheckerLimits | None = None
    # max_snapshot_sites 限制诊断 adapter 保留的线程/站点聚合项数量。
    max_snapshot_sites: int = 100_000

    def __post_init__(self) -> None:
        if not isinstance(self.static_request, StaticRequest):
            raise HybridWorkflowError(WorkflowStage.INPUT, "static_request has an invalid type")
        for name in ("dynamorio_home", "client_path", "trace_dir"):
            if not isinstance(getattr(self, name), Path):
                raise HybridWorkflowError(WorkflowStage.INPUT, f"{name} must be a Path")
        if self.working_directory is not None and not isinstance(
            self.working_directory, Path
        ):
            raise HybridWorkflowError(WorkflowStage.INPUT, "working_directory must be a Path")
        if self.max_thread_events is not None and (
            isinstance(self.max_thread_events, bool)
            or not isinstance(self.max_thread_events, int)
            or self.max_thread_events < 1
        ):
            raise HybridWorkflowError(
                WorkflowStage.INPUT, "max_thread_events must be positive"
            )
        if not isinstance(self.dynamic_config, DynamicConfig):
            raise HybridWorkflowError(WorkflowStage.INPUT, "dynamic_config has an invalid type")
        try:
            self.dynamic_config.validate()
        except (TypeError, ValueError) as error:
            raise HybridWorkflowError(WorkflowStage.INPUT, str(error)) from error
        if self.checker_limits is not None and not isinstance(
            self.checker_limits, CheckerLimits
        ):
            raise HybridWorkflowError(WorkflowStage.INPUT, "checker_limits has an invalid type")
        if (
            isinstance(self.max_snapshot_sites, bool)
            or not isinstance(self.max_snapshot_sites, int)
            or self.max_snapshot_sites < 1
        ):
            raise HybridWorkflowError(
                WorkflowStage.INPUT, "max_snapshot_sites must be positive"
            )


@dataclass(frozen=True, slots=True)
class DiagnosticProducts:
    """复用 D4/E1 的结果，不把它们折叠进任一 verdict。"""

    # static_snapshot 来自 replay 后的 canonical static certificate。
    static_snapshot: StaticDiagnosticSnapshot
    # correlation_binding 是 workflow 根据两条 route 的实际绑定计算的结果。
    correlation_binding: CorrelationBinding
    # report 保留 static verdict，并逐项关联 trace-bound observations。
    report: DiagnosticReport
    # affine_report 只汇总动态观察，不是静态 affine proof。
    affine_report: AffineValidationReport

    def __post_init__(self) -> None:
        if not isinstance(self.static_snapshot, StaticDiagnosticSnapshot):
            raise HybridWorkflowError(
                WorkflowStage.DIAGNOSTICS, "static_snapshot has an invalid type"
            )
        if not isinstance(self.correlation_binding, CorrelationBinding):
            raise HybridWorkflowError(
                WorkflowStage.DIAGNOSTICS, "correlation_binding has an invalid type"
            )
        if not isinstance(self.report, DiagnosticReport):
            raise HybridWorkflowError(WorkflowStage.DIAGNOSTICS, "report has an invalid type")
        if not isinstance(self.affine_report, AffineValidationReport):
            raise HybridWorkflowError(
                WorkflowStage.DIAGNOSTICS, "affine_report has an invalid type"
            )
        if self.report.static_verdict != self.static_snapshot.verdict:
            raise HybridWorkflowError(
                WorkflowStage.DIAGNOSTICS, "diagnostics changed the static verdict"
            )
        if self.report.correlations.binding != self.correlation_binding:
            raise HybridWorkflowError(
                WorkflowStage.DIAGNOSTICS, "report dropped the workflow binding assessment"
            )
        if self.affine_report.static_verdict != self.static_snapshot.verdict:
            raise HybridWorkflowError(
                WorkflowStage.DIAGNOSTICS, "affine observations changed the static verdict"
            )


@dataclass(frozen=True, slots=True)
class HybridWorkflowResult:
    """保留两份独立分析结果，以及可选的只读诊断产品。"""

    # static_analysis 是静态 application service 原样返回的结果。
    static_analysis: StaticAnalysisResult
    # dynamic_evidence 同时保留动态证书和从同一 trace 得到的诊断 snapshot。
    dynamic_evidence: BoundDynamicEvidence
    # diagnostics 缺失只允许由 static canonical certificate 不可用解释。
    diagnostics: DiagnosticProducts | None
    # diagnostics_unavailable_reason 让调用方知道为什么本次不能做跨路由诊断。
    diagnostics_unavailable_reason: str | None
    # trace_dir 指向用户选择的动态采集产物，不复制或清理它。
    trace_dir: Path

    def __post_init__(self) -> None:
        if not isinstance(self.static_analysis, StaticAnalysisResult):
            raise HybridWorkflowError(
                WorkflowStage.INPUT, "static_analysis has an invalid type"
            )
        if not isinstance(self.dynamic_evidence, BoundDynamicEvidence):
            raise HybridWorkflowError(
                WorkflowStage.INPUT, "dynamic_evidence has an invalid type"
            )
        if not isinstance(self.trace_dir, Path):
            raise HybridWorkflowError(WorkflowStage.INPUT, "trace_dir must be a Path")
        if self.diagnostics is None:
            if self.static_analysis.canonical_certificate is not None:
                raise HybridWorkflowError(
                    WorkflowStage.DIAGNOSTICS,
                    "diagnostics are missing despite a canonical static certificate",
                )
            if not self.diagnostics_unavailable_reason:
                raise HybridWorkflowError(
                    WorkflowStage.DIAGNOSTICS,
                    "missing diagnostics require an explicit reason",
                )
        else:
            if self.static_analysis.canonical_certificate is None:
                raise HybridWorkflowError(
                    WorkflowStage.DIAGNOSTICS,
                    "diagnostics cannot exist without a canonical static certificate",
                )
            if self.diagnostics_unavailable_reason is not None:
                raise HybridWorkflowError(
                    WorkflowStage.DIAGNOSTICS,
                    "available diagnostics cannot carry an unavailable reason",
                )


_T = TypeVar("_T")


def _at_stage(stage: WorkflowStage, operation: Callable[[], _T]) -> _T:
    try:
        return operation()
    except HybridWorkflowError:
        raise
    except Exception as error:
        raise HybridWorkflowError(stage, str(error)) from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _binding_check(
    dimension: BindingDimension,
    status: BindingStatus,
    reason: str,
) -> BindingCheck:
    return BindingCheck(dimension=dimension, status=status, reason=reason)


def _correlation_binding(
    static: StaticDiagnosticSnapshot,
    dynamic: BoundDynamicEvidence,
    *,
    static_policy_sha256_before: str,
    static_policy_sha256_after: str,
) -> CorrelationBinding:
    if static.binary_closure is None or dynamic.snapshot.binary_closure is None:
        binary_status = BindingStatus.UNVERIFIED
        binary_reason = "one or both routes lack a binary-closure identity"
    elif static.binary_closure == dynamic.snapshot.binary_closure:
        binary_status = BindingStatus.MATCH
        binary_reason = (
            "static and dynamic snapshots have the same executable/library closure"
        )
    else:
        binary_status = BindingStatus.MISMATCH
        binary_reason = "static and dynamic executable/library closure identities differ"

    if static_policy_sha256_before != static_policy_sha256_after:
        policy_status = BindingStatus.UNVERIFIED
        policy_reason = (
            "the DBT contract changed during static analysis; its consumed bytes "
            "cannot be bound to the dynamic route"
        )
    elif static_policy_sha256_before == dynamic.dbt_contract_sha256:
        policy_status = BindingStatus.MATCH
        policy_reason = (
            "the static route used an unchanged DBT contract file and the dynamic "
            "certificate binds the same SHA-256"
        )
    else:
        policy_status = BindingStatus.MISMATCH
        policy_reason = (
            "the dynamic certificate binds different DBT contract bytes from the "
            "unchanged file used by static analysis"
        )

    static_scope = static.scope
    dynamic_scope = dynamic.certificate.scope.analysis_scope
    if static_scope == dynamic_scope:
        scope_status = BindingStatus.MATCH
        scope_reason = f"both routes analyze the {static_scope!r} scope"
    else:
        scope_status = BindingStatus.MISMATCH
        scope_reason = (
            f"static scope {static_scope!r} differs from dynamic scope "
            f"{dynamic_scope!r}"
        )

    return CorrelationBinding(
        checks=(
            _binding_check(
                BindingDimension.BINARY_CLOSURE,
                binary_status,
                binary_reason,
            ),
            _binding_check(
                BindingDimension.TRANSLATION_POLICY,
                policy_status,
                policy_reason,
            ),
            _binding_check(
                BindingDimension.ANALYSIS_SCOPE,
                scope_status,
                scope_reason,
            ),
        )
    )


def analyze_workload(request: HybridWorkflowRequest) -> HybridWorkflowResult:
    """运行同一 workload 的静态分析、动态采集/分析和只读诊断。"""

    if not isinstance(request, HybridWorkflowRequest):
        raise HybridWorkflowError(WorkflowStage.INPUT, "request has an invalid type")

    contract_path = request.static_request.dbt_contract
    policy_sha256_before = _at_stage(
        WorkflowStage.INPUT,
        lambda: _sha256_file(contract_path),
    )
    static_analysis = _at_stage(
        WorkflowStage.STATIC_ANALYSIS,
        lambda: analyze_with_evidence(
            request.static_request,
            request.checker_limits,
        ),
    )
    if not isinstance(static_analysis, StaticAnalysisResult):
        raise HybridWorkflowError(
            WorkflowStage.STATIC_ANALYSIS,
            "static application service returned an invalid result",
        )
    policy_sha256_after_static = _at_stage(
        WorkflowStage.STATIC_ANALYSIS,
        lambda: _sha256_file(contract_path),
    )

    static_snapshot: StaticDiagnosticSnapshot | None = None
    if static_analysis.canonical_certificate is not None:
        static_snapshot = _at_stage(
            WorkflowStage.EVIDENCE_BINDING,
            lambda: static_snapshot_from_certificate(
                static_analysis.canonical_certificate
            ),
        )

    capture_request = _at_stage(
        WorkflowStage.TRACE_CAPTURE,
        lambda: CaptureRequest(
            command=(
                str(request.static_request.executable.resolve()),
                *request.static_request.argv,
            ),
            output_dir=request.trace_dir,
            dynamorio_home=request.dynamorio_home,
            client_path=request.client_path,
            environment=request.static_request.environment,
            working_directory=request.working_directory,
            max_thread_events=request.max_thread_events,
        ),
    )
    captured_manifest = _at_stage(
        WorkflowStage.TRACE_CAPTURE,
        lambda: capture_dynamic(capture_request),
    )
    if not isinstance(captured_manifest, TraceManifest):
        raise HybridWorkflowError(
            WorkflowStage.TRACE_CAPTURE,
            "capture service returned an invalid manifest",
        )

    dynamic_certificate = _at_stage(
        WorkflowStage.TRACE_ANALYSIS,
        lambda: analyze_dynamic(
            AnalyzeRequest(
                trace_dir=request.trace_dir,
                dbt_contract=contract_path,
                config=request.dynamic_config,
            )
        ),
    )
    if not isinstance(dynamic_certificate, DynamicCertificate):
        raise HybridWorkflowError(
            WorkflowStage.TRACE_ANALYSIS,
            "dynamic application service returned an invalid certificate",
        )
    dynamic_evidence = _at_stage(
        WorkflowStage.EVIDENCE_BINDING,
        lambda: bind_dynamic_certificate_to_trace(
            dynamic_certificate,
            request.trace_dir,
            contract_path,
            max_sites=request.max_snapshot_sites,
        ),
    )
    if not isinstance(dynamic_evidence, BoundDynamicEvidence):
        raise HybridWorkflowError(
            WorkflowStage.EVIDENCE_BINDING,
            "trace binding adapter returned an invalid result",
        )
    if dynamic_evidence.manifest != captured_manifest:
        raise HybridWorkflowError(
            WorkflowStage.EVIDENCE_BINDING,
            "trace manifest changed between capture and evidence binding",
        )

    if static_snapshot is None:
        reason = static_analysis.canonical_error or (
            "static service did not produce a replayed canonical certificate"
        )
        return HybridWorkflowResult(
            static_analysis=static_analysis,
            dynamic_evidence=dynamic_evidence,
            diagnostics=None,
            diagnostics_unavailable_reason=reason,
            trace_dir=request.trace_dir,
        )

    correlation_binding = _correlation_binding(
        static_snapshot,
        dynamic_evidence,
        static_policy_sha256_before=policy_sha256_before,
        static_policy_sha256_after=policy_sha256_after_static,
    )
    diagnostic_report = _at_stage(
        WorkflowStage.DIAGNOSTICS,
        lambda: build_diagnostic_report(
            static_snapshot,
            dynamic_evidence.snapshot,
            static_certificate_schema_version=(
                static_analysis.canonical_certificate.certificate.schema_version
            ),
            trace_certificate_schema_version=dynamic_evidence.certificate.schema_version,
            trace_certificate_sha256=dynamic_evidence.trace_sha256,
            correlation_binding=correlation_binding,
        ),
    )
    affine_report = _at_stage(
        WorkflowStage.DIAGNOSTICS,
        lambda: build_affine_validation_report(
            static_snapshot,
            dynamic_evidence.snapshot,
            correlations=(diagnostic_report.correlations,),
        ),
    )
    products = DiagnosticProducts(
        static_snapshot=static_snapshot,
        correlation_binding=correlation_binding,
        report=diagnostic_report,
        affine_report=affine_report,
    )
    return HybridWorkflowResult(
        static_analysis=static_analysis,
        dynamic_evidence=dynamic_evidence,
        diagnostics=products,
        diagnostics_unavailable_reason=None,
        trace_dir=request.trace_dir,
    )


__all__ = [
    "DiagnosticProducts",
    "HybridWorkflowError",
    "HybridWorkflowRequest",
    "HybridWorkflowResult",
    "WorkflowStage",
    "analyze_workload",
]
