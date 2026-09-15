"""动态辅助静态诊断的 typed report。

报告是只读的审计结果，不是新的 proof domain。它把原始静态 verdict、两条
快照的身份、相关记录和诊断提示放在同一份可序列化边界内，但不提供任何
把 ObservedFact 转成 ProofFact 或关闭 Unknown 的入口。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from collections.abc import Iterable
from typing import Final

from bmo_check_core import (
    BinaryClosureId,
    CorrelationBinding,
    CertificateVerdict,
    DiagnosticHint,
    DynamicDiagnosticSnapshot,
    EvidenceId,
    ObservedFact,
    ProducerId,
    StaticDiagnosticSnapshot,
    TraceId,
    UnknownFact,
)

from .correlation import (
    CorrelationError,
    CorrelationRecord,
    CorrelationStatus,
    DiagnosticCorrelationReport,
    correlate_unknowns,
)
from .classification import DiagnosticRootCause, classify_unknown


class DiagnosticReportError(ValueError):
    """报告输入不满足身份或 evidence 引用约束时抛出的错误。"""


_REPORT_SCHEMA: Final[str] = "diagnostic-report-v3"
_HINT_SCHEMA: Final[str] = "diagnostic-hint-v1"
_HINT_PRODUCER: Final[ProducerId] = ProducerId("bmo-check-diagnostics", "d4")
_NO_PROOF_CHANGE: Final[str] = (
    "Dynamic observations and diagnostic hints did not modify the static proof or verdict."
)


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DiagnosticReportError(f"{name} must be a non-empty string without NUL")
    return value


def _digest(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    value = _text(name, value).lower()
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise DiagnosticReportError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _count(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DiagnosticReportError(f"{name} must be a non-negative integer")
    return value


def _ids(name: str, values: Iterable[EvidenceId]) -> tuple[EvidenceId, ...]:
    result = tuple(values)
    if any(not isinstance(value, EvidenceId) for value in result):
        raise DiagnosticReportError(f"{name} must contain EvidenceId values")
    return tuple(sorted(set(result), key=lambda value: value.value))


def _stable_subject_digest(
    *,
    schema_version: str,
    scope: str,
    verdict: str,
    trace_id: str | None,
    binary_closure: str | None,
    evidence_ids: tuple[str, ...],
) -> str:
    material = "\n".join(
        (
            schema_version,
            scope,
            verdict,
            trace_id or "",
            binary_closure or "",
            *evidence_ids,
        )
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True, slots=True)
class CertificateIdentity:
    """诊断所绑定的证书身份，不把文件路径当作语义身份。"""

    # kind 明确这是静态还是动态证书，防止两个 verdict 枚举混用。
    kind: str
    # certificate_id 是调用者提供的稳定证书标识，缺省时由 snapshot 内容生成。
    certificate_id: str
    # schema_version 让报告消费者拒绝无法解释的证书版本。
    schema_version: str
    # binary_closure 绑定可执行文件、库集合和 ABI。
    binary_closure: BinaryClosureId | None
    # trace_id 只对 dynamic 证书存在，限制观察的执行实例。
    trace_id: TraceId | None
    # artifact_sha256 可选地绑定证书文件内容，而不是路径。
    artifact_sha256: str | None = None
    # scope 记录证书实际覆盖的静态或动态范围。
    scope: str = ""

    def __post_init__(self) -> None:
        if self.kind not in {"static", "dynamic"}:
            raise DiagnosticReportError("certificate identity kind must be static or dynamic")
        _text("certificate id", self.certificate_id)
        _text("certificate schema version", self.schema_version)
        if self.binary_closure is not None and not isinstance(
            self.binary_closure, BinaryClosureId
        ):
            raise DiagnosticReportError("certificate binary_closure is invalid")
        if self.trace_id is not None and not isinstance(self.trace_id, TraceId):
            raise DiagnosticReportError("certificate trace_id is invalid")
        if self.kind == "static" and self.trace_id is not None:
            raise DiagnosticReportError("static certificate cannot bind a trace")
        if self.kind == "dynamic" and self.trace_id is None:
            raise DiagnosticReportError("dynamic certificate must bind a trace")
        _digest("certificate artifact_sha256", self.artifact_sha256)
        _text("certificate scope", self.scope)


@dataclass(frozen=True, slots=True)
class DiagnosticCoverage:
    """报告中可复核的观察覆盖计数。

    这些数字描述本次输入快照，不代表未执行路径，也不能替代静态 proof。
    """

    # observed_fact_count 是动态快照中保留下来的 ObservedFact 数量。
    observed_fact_count: int
    # observed_unknown_count 是动态采集仍未闭合的 Unknown 数量。
    observed_unknown_count: int
    # observed_subject_count 是有稳定 subject 的不同观察站点数量。
    observed_subject_count: int
    # observed_thread_count 是观察中不同 ThreadInstanceId 的数量。
    observed_thread_count: int
    # selected_unknown_count 是报告选择解释的静态 Unknown 数量。
    selected_unknown_count: int
    # blocking_unknown_count 是证书回放后仍未闭合的静态 obligation 数量。
    blocking_unknown_count: int
    # discharged_unknown_count 是有证据记录、且不再阻塞当前结论的 Unknown 数量。
    discharged_unknown_count: int
    # exact_count 是闭包和 subject 均匹配的静态 Unknown 数量。
    exact_count: int
    # ambiguous_count 是有候选但身份材料不足的数量。
    ambiguous_count: int
    # unmatched_count 是没有安全候选或闭包冲突的数量。
    unmatched_count: int

    def __post_init__(self) -> None:
        fields = (
            ("observed_fact_count", self.observed_fact_count),
            ("observed_unknown_count", self.observed_unknown_count),
            ("observed_subject_count", self.observed_subject_count),
            ("observed_thread_count", self.observed_thread_count),
            ("selected_unknown_count", self.selected_unknown_count),
            ("blocking_unknown_count", self.blocking_unknown_count),
            ("discharged_unknown_count", self.discharged_unknown_count),
            ("exact_count", self.exact_count),
            ("ambiguous_count", self.ambiguous_count),
            ("unmatched_count", self.unmatched_count),
        )
        for name, value in fields:
            _count(name, value)
        if (
            self.exact_count + self.ambiguous_count + self.unmatched_count
            != self.selected_unknown_count
        ):
            raise DiagnosticReportError(
                "correlation status counts do not cover selected Unknowns"
            )
        if self.selected_unknown_count > self.blocking_unknown_count:
            raise DiagnosticReportError(
                "selected Unknown count exceeds current blocking obligations"
            )


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    """动态辅助诊断的 immutable、versioned report。"""

    # schema_version 让 report reader 能明确拒绝未知字段语义。
    schema_version: str
    # static_verdict 必须逐字复制静态 snapshot，诊断不能升级它。
    static_verdict: CertificateVerdict
    # static_certificate 保存静态证书的身份和闭包绑定。
    static_certificate: CertificateIdentity
    # trace_certificate 保存动态证书/快照的 trace 绑定。
    trace_certificate: CertificateIdentity
    # static_snapshot_schema_version 保留静态输入格式版本。
    static_snapshot_schema_version: str
    # dynamic_snapshot_schema_version 保留动态输入格式版本。
    dynamic_snapshot_schema_version: str
    # trace_id 冗余保存以便不解析 nested identity 也能筛选报告。
    trace_id: TraceId
    # trace_complete 复制动态 snapshot 完整性，不代表静态完整。
    trace_complete: bool
    # blocking_unknowns 是静态证书回放后仍未闭合的全部 obligation。
    blocking_unknowns: tuple[UnknownFact, ...]
    # selected_unknowns 是完整 typed UnknownFact，而不是列表序号或字符串摘要。
    # 它只能是 blocking_unknowns 的子集，表示本次需要关联解释的项目。
    selected_unknowns: tuple[UnknownFact, ...]
    # discharged_unknowns 保留已由 proof closure 关闭的历史 Unknown，不参与诊断选择。
    discharged_unknowns: tuple[UnknownFact, ...]
    # correlations 保存 Exact/Ambiguous/Unmatched 的逐项理由。
    correlations: DiagnosticCorrelationReport
    # observed_facts 保留 trace-bound 动态事实供审计和回查。
    observed_facts: tuple[ObservedFact, ...]
    # dynamic_unknowns 不静默丢弃动态采集自身的缺口。
    dynamic_unknowns: tuple[UnknownFact, ...]
    # coverage 汇总事实数量和相关状态分布。
    coverage: DiagnosticCoverage
    # hints 只引用上述 Unknown/Observed，不可作为 proof premise。
    hints: tuple[DiagnosticHint, ...]
    # static_proof_unchanged 是机器可检查的越权声明，必须保持 True。
    static_proof_unchanged: bool = True
    # statement 面向人和 agent，明确诊断不能改变 static proof。
    statement: str = _NO_PROOF_CHANGE

    def __post_init__(self) -> None:
        _text("diagnostic report schema_version", self.schema_version)
        if not isinstance(self.static_verdict, CertificateVerdict):
            raise DiagnosticReportError("report static_verdict is invalid")
        if not isinstance(self.static_certificate, CertificateIdentity):
            raise DiagnosticReportError("report static_certificate is invalid")
        if not isinstance(self.trace_certificate, CertificateIdentity):
            raise DiagnosticReportError("report trace_certificate is invalid")
        if self.static_certificate.kind != "static":
            raise DiagnosticReportError("static_certificate must have static kind")
        if self.trace_certificate.kind != "dynamic":
            raise DiagnosticReportError("trace_certificate must have dynamic kind")
        if self.static_certificate.scope == "":
            raise DiagnosticReportError("static certificate scope is missing")
        if self.trace_certificate.scope == "":
            raise DiagnosticReportError("trace certificate scope is missing")
        _text("static snapshot schema_version", self.static_snapshot_schema_version)
        _text("dynamic snapshot schema_version", self.dynamic_snapshot_schema_version)
        if not isinstance(self.trace_id, TraceId):
            raise DiagnosticReportError("report trace_id is invalid")
        if self.trace_certificate.trace_id != self.trace_id:
            raise DiagnosticReportError("trace certificate trace_id differs from report")
        if not isinstance(self.trace_complete, bool):
            raise DiagnosticReportError("report trace_complete must be boolean")
        if not isinstance(self.static_proof_unchanged, bool) or not self.static_proof_unchanged:
            raise DiagnosticReportError("diagnostic report must state static proof is unchanged")
        if self.statement != _NO_PROOF_CHANGE:
            raise DiagnosticReportError("diagnostic report has an invalid proof-boundary statement")
        blocking = tuple(self.blocking_unknowns)
        if any(not isinstance(item, UnknownFact) for item in blocking):
            raise DiagnosticReportError("blocking_unknowns must contain UnknownFact values")
        unknowns = tuple(self.selected_unknowns)
        if any(not isinstance(item, UnknownFact) for item in unknowns):
            raise DiagnosticReportError("selected_unknowns must contain UnknownFact values")
        discharged = tuple(self.discharged_unknowns)
        if any(not isinstance(item, UnknownFact) for item in discharged):
            raise DiagnosticReportError("discharged_unknowns must contain UnknownFact values")
        observations = tuple(self.observed_facts)
        if any(not isinstance(item, ObservedFact) for item in observations):
            raise DiagnosticReportError("observed_facts must contain ObservedFact values")
        dynamic_unknowns = tuple(self.dynamic_unknowns)
        if any(not isinstance(item, UnknownFact) for item in dynamic_unknowns):
            raise DiagnosticReportError("dynamic_unknowns must contain UnknownFact values")
        if any(item.scope != self.static_certificate.scope for item in (*blocking, *unknowns, *discharged)):
            raise DiagnosticReportError("static Unknown scope differs from static certificate")
        if any(item.scope != self.trace_certificate.scope for item in dynamic_unknowns):
            raise DiagnosticReportError("dynamic Unknown scope differs from trace certificate")
        if any(item.trace_id != self.trace_id for item in observations):
            raise DiagnosticReportError("observed fact belongs to another trace")
        if not isinstance(self.correlations, DiagnosticCorrelationReport):
            raise DiagnosticReportError("correlations have an invalid type")
        if not isinstance(self.coverage, DiagnosticCoverage):
            raise DiagnosticReportError("coverage has an invalid type")
        object.__setattr__(
            self,
            "blocking_unknowns",
            tuple(sorted(set(blocking), key=lambda item: item.id.value)),
        )
        object.__setattr__(
            self,
            "selected_unknowns",
            tuple(sorted(set(unknowns), key=lambda item: item.id.value)),
        )
        object.__setattr__(
            self,
            "discharged_unknowns",
            tuple(sorted(set(discharged), key=lambda item: item.id.value)),
        )
        object.__setattr__(
            self,
            "observed_facts",
            tuple(sorted(set(observations), key=lambda item: item.id.value)),
        )
        object.__setattr__(
            self,
            "dynamic_unknowns",
            tuple(sorted(set(dynamic_unknowns), key=lambda item: item.id.value)),
        )
        if self.correlations.static_verdict != self.static_verdict:
            raise DiagnosticReportError("correlation changed the static verdict")
        if self.correlations.trace_id != self.trace_id:
            raise DiagnosticReportError("correlation trace_id differs from report")
        if self.correlations.trace_complete != self.trace_complete:
            raise DiagnosticReportError("correlation completeness differs from report")
        blocking_ids = {item.id for item in self.blocking_unknowns}
        selected_ids = {item.id for item in self.selected_unknowns}
        discharged_ids = {item.id for item in self.discharged_unknowns}
        if not selected_ids.issubset(blocking_ids):
            raise DiagnosticReportError("selected Unknown is not a current blocking obligation")
        if blocking_ids & discharged_ids:
            raise DiagnosticReportError("an Unknown cannot be both blocking and discharged")
        observed_ids = {item.id for item in self.observed_facts}
        if any(item.unknown_id not in selected_ids for item in self.correlations.records):
            raise DiagnosticReportError("correlation references an unselected Unknown")
        if any(
            observed_id not in observed_ids
            for record in self.correlations.records
            for observed_id in record.observed_ids
        ):
            raise DiagnosticReportError("correlation references an absent observation")
        for hint in self.hints:
            if not isinstance(hint, DiagnosticHint):
                raise DiagnosticReportError("hints must contain DiagnosticHint values")
            try:
                DiagnosticRootCause(hint.root_cause)
            except ValueError as error:
                raise DiagnosticReportError(
                    f"hint root cause is not registered: {hint.root_cause}"
                ) from error
            if hint.scope != self.static_certificate.scope:
                raise DiagnosticReportError("hint scope differs from static certificate")
            if not set(hint.unknown_ids).issubset(selected_ids):
                raise DiagnosticReportError("hint references an unselected Unknown")
            if not set(hint.observed_ids).issubset(observed_ids):
                raise DiagnosticReportError("hint references an absent observation")
        expected = DiagnosticCoverage(
            observed_fact_count=len(self.observed_facts),
            observed_unknown_count=len(self.dynamic_unknowns),
            observed_subject_count=len(
                {item.subject for item in self.observed_facts if item.subject is not None}
            ),
            observed_thread_count=len({item.execution_id for item in self.observed_facts}),
            selected_unknown_count=len(self.selected_unknowns),
            blocking_unknown_count=len(self.blocking_unknowns),
            discharged_unknown_count=len(self.discharged_unknowns),
            exact_count=sum(
                item.status == CorrelationStatus.EXACT
                for item in self.correlations.records
            ),
            ambiguous_count=sum(
                item.status == CorrelationStatus.AMBIGUOUS
                for item in self.correlations.records
            ),
            unmatched_count=sum(
                item.status == CorrelationStatus.UNMATCHED
                for item in self.correlations.records
            ),
        )
        if self.coverage != expected:
            raise DiagnosticReportError("coverage does not match report evidence")

    def to_dict(self) -> dict[str, object]:
        """通过显式 serialization boundary 导出 JSON-compatible 文档。"""

        from .serialization import report_to_dict

        return report_to_dict(self)

    def to_json(self) -> str:
        """返回稳定排序的 versioned JSON 文本。"""

        from .serialization import report_to_json

        return report_to_json(self)

    @property
    def records(self) -> tuple[CorrelationRecord, ...]:
        """兼容调用者直接读取逐项相关结果。"""

        return self.correlations.records

    @property
    def unknowns(self) -> tuple[UnknownFact, ...]:
        """报告选择的静态 Unknown 别名。"""

        return self.selected_unknowns


def _default_certificate_id(
    *,
    prefix: str,
    schema_version: str,
    scope: str,
    verdict: str,
    trace_id: str | None,
    binary_closure: BinaryClosureId | None,
    evidence_ids: tuple[EvidenceId, ...],
) -> str:
    digest = _stable_subject_digest(
        schema_version=schema_version,
        scope=scope,
        verdict=verdict,
        trace_id=trace_id,
        binary_closure=binary_closure.value if binary_closure else None,
        evidence_ids=tuple(item.value for item in evidence_ids),
    )
    return f"{prefix}:{digest}"


def _selected_records(
    correlation: DiagnosticCorrelationReport,
    selected_ids: set[EvidenceId],
) -> DiagnosticCorrelationReport:
    return DiagnosticCorrelationReport(
        schema_version=correlation.schema_version,
        static_verdict=correlation.static_verdict,
        trace_id=correlation.trace_id,
        trace_complete=correlation.trace_complete,
        records=tuple(
            record for record in correlation.records if record.unknown_id in selected_ids
        ),
        binding=correlation.binding,
    )


def _make_hints(
    static: StaticDiagnosticSnapshot,
    records: tuple[CorrelationRecord, ...],
    *,
    trace_complete: bool,
) -> tuple[DiagnosticHint, ...]:
    unknowns = {
        node.id: node
        for node in static.evidence.nodes
        if isinstance(node, UnknownFact)
    }
    hints: list[DiagnosticHint] = []
    for record in records:
        unknown = unknowns.get(record.unknown_id)
        if unknown is None:
            raise DiagnosticReportError(
                f"correlation references an absent static Unknown: {record.unknown_id.value}"
            )
        classification = classify_unknown(
            unknown,
            correlation=record,
            trace_complete=trace_complete,
        )
        # 相关状态比分类器更严格：没有稳定候选时，提示不能显示为高置信度。
        status_cap = {
            CorrelationStatus.EXACT: 1.0,
            CorrelationStatus.AMBIGUOUS: 0.5,
            CorrelationStatus.UNMATCHED: 0.0,
        }[record.status]
        confidence = min(classification.confidence, status_cap)
        hint = DiagnosticHint.create(
            schema_version=_HINT_SCHEMA,
            producer=_HINT_PRODUCER,
            scope=static.scope,
            unknown_ids=(record.unknown_id,),
            observed_ids=record.observed_ids,
            root_cause=classification.root_cause.value,
            confidence=confidence,
            explanation=(
                f"{classification.rationale}; {record.reason}. "
                "This diagnostic only locates a static precision gap; "
                "it does not discharge the Unknown or change the static verdict."
            ),
        )
        hints.append(hint)
    return tuple(sorted(hints, key=lambda item: item.id.value))


def build_diagnostic_report(
    static: StaticDiagnosticSnapshot,
    dynamic: DynamicDiagnosticSnapshot,
    *,
    static_certificate_id: str | None = None,
    trace_certificate_id: str | None = None,
    static_certificate_schema_version: str | None = None,
    trace_certificate_schema_version: str | None = None,
    static_certificate_sha256: str | None = None,
    trace_certificate_sha256: str | None = None,
    selected_unknown_ids: Iterable[EvidenceId] | None = None,
    correlation_binding: CorrelationBinding | None = None,
) -> DiagnosticReport:
    """从两个 snapshot 生成诊断报告，且保留原始 static verdict。"""

    if not isinstance(static, StaticDiagnosticSnapshot):
        raise DiagnosticReportError("static input is not a StaticDiagnosticSnapshot")
    if not isinstance(dynamic, DynamicDiagnosticSnapshot):
        raise DiagnosticReportError("dynamic input is not a DynamicDiagnosticSnapshot")
    try:
        correlation = correlate_unknowns(
            static,
            dynamic,
            binding=correlation_binding,
        )
    except CorrelationError as error:
        raise DiagnosticReportError(f"cannot correlate diagnostic snapshots: {error}") from error

    all_unknowns = tuple(
        node for node in static.evidence.nodes if isinstance(node, UnknownFact)
    )
    by_id = {node.id: node for node in all_unknowns}
    if static.blocking_unknown_ids is None:
        # v1 / hand-built snapshots have no certificate-replayed partition. Do not
        # infer a discharge from their payload; conservatively keep every Unknown active.
        blocking_ids = set(by_id)
        discharged = ()
    else:
        blocking_ids = set(static.blocking_unknown_ids)
        discharged = tuple(
            node for node in all_unknowns if node.id not in blocking_ids
        )
    blocking = tuple(node for node in all_unknowns if node.id in blocking_ids)
    requested = (
        _ids("selected_unknown_ids", selected_unknown_ids)
        if selected_unknown_ids is not None
        else tuple(node.id for node in blocking)
    )
    missing = [item.value for item in requested if item not in by_id]
    if missing:
        raise DiagnosticReportError(f"selected Unknown is absent from static snapshot: {missing}")
    non_blocking = [item.value for item in requested if item not in blocking_ids]
    if non_blocking:
        raise DiagnosticReportError(
            f"selected Unknown is discharged and is not a blocking obligation: {non_blocking}"
        )
    selected = tuple(by_id[item] for item in requested)
    selected_set = set(requested)
    selected_correlation = _selected_records(correlation, selected_set)
    observations = tuple(
        node for node in dynamic.evidence.nodes if isinstance(node, ObservedFact)
    )
    dynamic_unknowns = tuple(
        node for node in dynamic.evidence.nodes if isinstance(node, UnknownFact)
    )
    static_schema = static_certificate_schema_version or static.schema_version
    trace_schema = trace_certificate_schema_version or dynamic.schema_version
    static_id = static_certificate_id or _default_certificate_id(
        prefix="static-snapshot",
        schema_version=static.schema_version,
        scope=static.scope,
        verdict=static.verdict.value,
        trace_id=None,
        binary_closure=static.binary_closure,
        evidence_ids=tuple(node.id for node in static.evidence.nodes),
    )
    trace_id = trace_certificate_id or _default_certificate_id(
        prefix="trace-snapshot",
        schema_version=dynamic.schema_version,
        scope=dynamic.scope,
        verdict="trace",
        trace_id=dynamic.trace_id.value,
        binary_closure=dynamic.binary_closure,
        evidence_ids=tuple(node.id for node in dynamic.evidence.nodes),
    )
    try:
        static_identity = CertificateIdentity(
            kind="static",
            certificate_id=static_id,
            schema_version=static_schema,
            binary_closure=static.binary_closure,
            trace_id=None,
            artifact_sha256=static_certificate_sha256,
            scope=static.scope,
        )
        trace_identity = CertificateIdentity(
            kind="dynamic",
            certificate_id=trace_id,
            schema_version=trace_schema,
            binary_closure=dynamic.binary_closure,
            trace_id=dynamic.trace_id,
            artifact_sha256=trace_certificate_sha256,
            scope=dynamic.scope,
        )
        coverage = DiagnosticCoverage(
            observed_fact_count=len(observations),
            observed_unknown_count=len(dynamic_unknowns),
            observed_subject_count=len(
                {item.subject for item in observations if item.subject is not None}
            ),
            observed_thread_count=len({item.execution_id for item in observations}),
            selected_unknown_count=len(selected),
            blocking_unknown_count=len(blocking),
            discharged_unknown_count=len(discharged),
            exact_count=sum(
                item.status == CorrelationStatus.EXACT
                for item in selected_correlation.records
            ),
            ambiguous_count=sum(
                item.status == CorrelationStatus.AMBIGUOUS
                for item in selected_correlation.records
            ),
            unmatched_count=sum(
                item.status == CorrelationStatus.UNMATCHED
                for item in selected_correlation.records
            ),
        )
        return DiagnosticReport(
            schema_version=_REPORT_SCHEMA,
            static_verdict=static.verdict,
            static_certificate=static_identity,
            trace_certificate=trace_identity,
            static_snapshot_schema_version=static.schema_version,
            dynamic_snapshot_schema_version=dynamic.schema_version,
            trace_id=dynamic.trace_id,
            trace_complete=dynamic.complete,
            blocking_unknowns=blocking,
            selected_unknowns=selected,
            discharged_unknowns=discharged,
            correlations=selected_correlation,
            observed_facts=observations,
            dynamic_unknowns=dynamic_unknowns,
            coverage=coverage,
            hints=_make_hints(
                static,
                selected_correlation.records,
                trace_complete=dynamic.complete,
            ),
        )
    except (TypeError, ValueError) as error:
        raise DiagnosticReportError(f"diagnostic report construction failed: {error}") from error


# ``diagnose`` is a short service alias for callers that do not need the builder name.
diagnose = build_diagnostic_report


__all__ = [
    "CertificateIdentity",
    "DiagnosticCoverage",
    "DiagnosticReport",
    "DiagnosticReportError",
    "build_diagnostic_report",
    "diagnose",
]
