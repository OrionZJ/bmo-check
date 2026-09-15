"""把一次 hybrid workflow 投影为严格、可回读的顶层报告。

这里仅整理已有 route/diagnostic 结果，不运行 checker、不创建证据，也不合并 verdict。
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    field_validator,
    model_validator,
)

from bmo_check_core import (
    BindingDimension,
    BindingStatus,
    CertificateVerdict,
    ProofFact,
    UnknownFact,
    UnknownKind,
)
from bmo_check_diagnostics import (
    DiagnosticRootCause,
    affine_report_to_dict,
)
from bmo_check_diagnostics.affine import ObservedAffineStatus, ObservedOverlap
from bmo_check_diagnostics.correlation import CorrelationKey, CorrelationStatus
from bmo_check_diagnostics.serialization import report_to_dict
from bmo_check_dynamic.model import DynamicCertificate, TraceManifest
from bmo_check_static.model import CheckerConclusion, CheckerLimits
from bmo_check_static.model.unknown import UnknownFact as LegacyUnknownFact
from bmo_check_workflow.application import HybridWorkflowResult


_REPORT_SCHEMA = "hybrid-workflow-report-v1"
_STATIC_BOUNDARY = "Static SAFE requires a replayed static ProofFact closure."
_TRACE_BOUNDARY = "Dynamic verdicts apply only to the trace bound in this report."
_DIAGNOSTIC_BOUNDARY = (
    "ObservedFact and DiagnosticHint locate static gaps; they never modify static proof or verdict."
)


def _sha256(value: str) -> bool:
    return (
        len(value) == 64
        and value == value.lower()
        and all(char in "0123456789abcdef" for char in value)
    )


class HybridReportError(ValueError):
    """报告输入、序列化或读取违反 versioned contract 时抛出。"""


class _StrictModel(BaseModel):
    """拒绝未声明字段，避免旧读取器悄悄接受新报告含义。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ObligationIdentitySource(StrEnum):
    """指出 blocker 使用 canonical evidence ID，还是旧静态报告字段。"""

    CANONICAL = "canonical_evidence"  # ID 可回到 canonical static ledger。
    LEGACY = "legacy_report"  # 旧证书没有稳定 EvidenceId，只能保留来源位置。


class CausalStatus(StrEnum):
    """当前 D5 只给分类候选，尚无 typed edge 支持因果根因。"""

    UNRESOLVED = "causal_relation_unresolved"  # 当前 provenance 没有 typed cause edge。


class ProducerSummary(_StrictModel):
    # name 指出产生该 evidence 的静态分析或动态归一化组件。
    name: str
    # version 绑定组件版本，便于之后解释分类或 observation 的差异。
    version: str


class AttributeSummary(_StrictModel):
    # name 是 trace normalizer 已归一化的 observation 字段名。
    name: str
    # value 保留原始规范文本，不把观察重新解释成 proof。
    value: str


class EvidenceUnknownSummary(_StrictModel):
    # category 固定为 UnknownFact，避免把未闭合 obligation 误读为观察。
    category: Literal["UnknownFact"]
    # id 可用于回到静态或动态 evidence ledger。
    id: str
    # schema_version 固定 Unknown kind、scope 和 provenance 的解释方式。
    schema_version: str
    # producer 记录产生 Unknown 的分析 pass。
    producer: ProducerSummary
    # kind 使用 core 注册的 typed Unknown 名称。
    kind: UnknownKind
    # reason 说明这个 obligation 仍缺少什么证明材料。
    reason: str
    # subject 指向可稳定识别的指令、对象、事件或范围。
    subject: str | None
    # scope 区分静态证书范围和 trace 内的动态分析范围。
    scope: str
    # provenance 保留 Unknown 的静态父 evidence ID。
    provenance: tuple[str, ...]
    # supporting_context 可携带位置等线索，但不是 proof premise。
    supporting_context: tuple[str, ...]


class ObservedEvidenceSummary(_StrictModel):
    # category 固定为 ObservedFact，避免动态值流入静态证明字段。
    category: Literal["ObservedFact"]
    # id 是带 trace identity 的观察 ID。
    id: str
    # schema_version 固定 observation 属性的解释方式。
    schema_version: Literal["dynamic-observed-v1"]
    # producer 记录生成 observation 的 tracer adapter 版本。
    producer: ProducerSummary
    # trace_id 把该事实限制在一次具体采集。
    trace_id: str
    # execution_id 区分同一 trace 里的线程实例。
    execution_id: str
    # subject 是有静态身份对应项时的指令或 operand ID。
    subject: str | None
    # observation_kind 说明该事实记录的是访存、目标或其他动态事件。
    observation_kind: str
    # attributes 保留已归一化字段，地址仍是观察而非静态边界。
    attributes: tuple[AttributeSummary, ...]


class DiagnosticHintSummary(_StrictModel):
    # category 使 JSON consumer 不会把 hint 解析成 ProofFact。
    category: Literal["DiagnosticHint"]
    # id 是该分类线索的稳定 identity。
    id: str
    # schema_version 固定 hint 的字段解释方式。
    schema_version: Literal["diagnostic-hint-v1"]
    # producer 记录 correlator/classifier 的来源版本。
    producer: ProducerSummary
    # scope 限定 hint 可解释的静态分析范围。
    scope: str
    # unknown_ids 指向仍未闭合的 static obligations。
    unknown_ids: tuple[str, ...]
    # observed_ids 指向 trace-bound facts，不能充当证明前提。
    observed_ids: tuple[str, ...]
    # root_cause 是 D5 注册表里的候选分类，不是因果结论。
    root_cause: DiagnosticRootCause
    # confidence 只表示诊断提示强弱，不表示 proof 强度。
    confidence: float
    # explanation 面向维护者，不能改变分析 verdict。
    explanation: str


class CertificateIdentitySummary(_StrictModel):
    # kind 区分 static 与 dynamic certificate identity。
    kind: Literal["static", "dynamic"]
    # certificate_id 稳定绑定诊断输入，不依赖文件路径。
    certificate_id: str
    # schema_version 指明被 D4 引用的证书格式。
    schema_version: str
    # binary_closure 在有完整材料时绑定 executable 与 library closure。
    binary_closure: str | None
    # trace_id 只对 dynamic certificate 存在。
    trace_id: str | None
    # artifact_sha256 可选地绑定原证书文件的内容。
    artifact_sha256: str | None
    # scope 保留这份 identity 原本覆盖的分析范围。
    scope: str


class BindingCheckSummary(_StrictModel):
    # dimension 指明比较的是 binary、DBT contract 还是分析范围。
    dimension: BindingDimension
    # status 区分已核对相同、冲突和缺少材料。
    status: BindingStatus
    # reason 记录做出该判断的具体材料或缺口。
    reason: str


class BindingSummary(_StrictModel):
    # status 是各 binding dimension 中最保守的总状态。
    status: BindingStatus
    # checks 保留每个维度的原始比对理由。
    checks: tuple[BindingCheckSummary, ...]

    @model_validator(mode="after")
    def validate_dimensions_and_summary(self) -> "BindingSummary":
        dimensions = tuple(item.dimension for item in self.checks)
        if set(dimensions) != set(BindingDimension) or len(dimensions) != len(
            BindingDimension
        ):
            raise ValueError("binding must contain each dimension exactly once")
        if any(item.status == BindingStatus.MISMATCH for item in self.checks):
            expected = BindingStatus.MISMATCH
        elif any(item.status == BindingStatus.UNVERIFIED for item in self.checks):
            expected = BindingStatus.UNVERIFIED
        else:
            expected = BindingStatus.MATCH
        if self.status != expected:
            raise ValueError("binding summary differs from its dimension checks")
        return self


class CorrelationRecordSummary(_StrictModel):
    # unknown_id 是本条关联试图解释的静态 blocker。
    unknown_id: str
    # observed_ids 是被允许关联的 trace observation 集合。
    observed_ids: tuple[str, ...]
    # status 仅表达静态 site 与观察之间的定位强度。
    status: CorrelationStatus
    # key 说明本次用稳定 subject、位置或 binding 做了匹配。
    key: CorrelationKey
    # reason 解释 Exact、Ambiguous 或 Unmatched 的具体依据。
    reason: str


class CorrelationReportSummary(_StrictModel):
    # schema_version 固定相关器报告字段含义。
    schema_version: Literal["diagnostic-correlation-v2"]
    # static_verdict 必须与静态 route 输出相同。
    static_verdict: CertificateVerdict
    # trace_id 绑定所有 records 对应的动态执行。
    trace_id: str
    # trace_complete 只说明采集完整性，不覆盖未执行路径。
    trace_complete: bool
    # binding 缺失时旧 snapshot-only 报告不能声称跨 route 完全匹配。
    binding: BindingSummary | None
    # records 给出每个静态 Unknown 的逐项匹配结果。
    records: tuple[CorrelationRecordSummary, ...]


class DiagnosticCoverageSummary(_StrictModel):
    # 下列计数描述报告保留的事实，不代表 static proof coverage。
    observed_fact_count: int
    observed_unknown_count: int
    observed_subject_count: int
    observed_thread_count: int
    blocking_unknown_count: int
    discharged_unknown_count: int
    selected_unknown_count: int
    exact_count: int
    ambiguous_count: int
    unmatched_count: int


class D4ReportSummary(_StrictModel):
    """保留 D4 原有 diagnostic-report-v3 子 schema 的所有字段。"""

    # schema_version 必须仍是 D4 serializer 自己的版本。
    schema_version: Literal["diagnostic-report-v3"]
    # static_verdict 原样复制，不受 trace 观察影响。
    static_verdict: CertificateVerdict
    # static_certificate 保留 D4 实际绑定的静态 certificate identity。
    static_certificate: CertificateIdentitySummary
    # trace_certificate 保留 D4 实际绑定的 trace certificate identity。
    trace_certificate: CertificateIdentitySummary
    # static_snapshot_schema_version 固定静态 snapshot 格式。
    static_snapshot_schema_version: Literal["static-diagnostic-v2"]
    # dynamic_snapshot_schema_version 固定 trace snapshot 格式。
    dynamic_snapshot_schema_version: Literal["dynamic-diagnostic-v1"]
    # trace_id 是内容派生身份，不是 manifest 中的启动器字符串 ID。
    trace_id: str
    # trace_complete 说明该 snapshot 是否包含完整采集记录。
    trace_complete: bool
    # blocking_unknowns 是经过证书回放后仍未闭合的静态 obligation。
    blocking_unknowns: tuple[EvidenceUnknownSummary, ...]
    # selected_unknowns 是本次实际交给 correlator 的 blocker 子集。
    selected_unknowns: tuple[EvidenceUnknownSummary, ...]
    # discharged_unknowns 保留由静态 ProofFact 关闭的历史 Unknown。
    discharged_unknowns: tuple[EvidenceUnknownSummary, ...]
    # correlations 保留逐项关联和跨 route binding 原因。
    correlations: CorrelationReportSummary
    # observed_facts 只能描述上面 trace_id 对应的实际执行。
    observed_facts: tuple[ObservedEvidenceSummary, ...]
    # dynamic_unknowns 记录采集或归一化阶段尚未关闭的问题。
    dynamic_unknowns: tuple[EvidenceUnknownSummary, ...]
    # coverage 保留 D4 的计数，而不是重新解释计数含义。
    coverage: DiagnosticCoverageSummary
    # hints 是可选定位建议，不能进入静态 proof closure。
    hints: tuple[DiagnosticHintSummary, ...]
    # static_proof_unchanged 必须固定为 True。
    static_proof_unchanged: Literal[True]
    # statement 是 D4 对不修改静态 proof 的固定声明。
    statement: Literal[
        "Dynamic observations and diagnostic hints did not modify the static proof or verdict."
    ]

    @model_validator(mode="after")
    def preserve_d4_evidence_references(self) -> "D4ReportSummary":
        if self.correlations.static_verdict != self.static_verdict:
            raise ValueError("D4 correlation changed the static verdict")
        if self.correlations.trace_id != self.trace_id:
            raise ValueError("D4 correlation refers to another trace")
        if self.correlations.trace_complete != self.trace_complete:
            raise ValueError("D4 correlation completeness differs from the report")
        if self.trace_certificate.trace_id != self.trace_id:
            raise ValueError("D4 trace certificate refers to another trace")
        if any(
            item.scope != self.static_certificate.scope
            for item in (
                *self.blocking_unknowns,
                *self.selected_unknowns,
                *self.discharged_unknowns,
            )
        ):
            raise ValueError("D4 static Unknown scope differs from its certificate")
        if any(
            item.scope != self.trace_certificate.scope
            for item in self.dynamic_unknowns
        ):
            raise ValueError("D4 dynamic Unknown scope differs from its trace certificate")
        if any(item.trace_id != self.trace_id for item in self.observed_facts):
            raise ValueError("D4 observation belongs to another trace")

        blockers = {item.id for item in self.blocking_unknowns}
        selected = {item.id for item in self.selected_unknowns}
        discharged = {item.id for item in self.discharged_unknowns}
        observations = {item.id for item in self.observed_facts}
        if len(blockers) != len(self.blocking_unknowns):
            raise ValueError("D4 blocking Unknown IDs are not unique")
        if not selected.issubset(blockers) or blockers & discharged:
            raise ValueError("D4 selected/discharged Unknowns do not match blockers")
        record_unknown_ids = tuple(item.unknown_id for item in self.correlations.records)
        if set(record_unknown_ids) != selected or len(record_unknown_ids) != len(selected):
            raise ValueError("D4 must contain one correlation record per selected Unknown")
        if any(item.unknown_id not in selected for item in self.correlations.records):
            raise ValueError("D4 correlation references an unselected Unknown")
        if any(
            not set(item.observed_ids).issubset(observations)
            for item in self.correlations.records
        ):
            raise ValueError("D4 correlation references an absent observation")
        if any(
            not set(item.unknown_ids).issubset(selected)
            or not set(item.observed_ids).issubset(observations)
            for item in self.hints
        ):
            raise ValueError("D4 hint references evidence outside this report")
        if self.coverage.blocking_unknown_count != len(self.blocking_unknowns):
            raise ValueError("D4 blocking Unknown count does not match evidence")
        if self.coverage.selected_unknown_count != len(self.selected_unknowns):
            raise ValueError("D4 selected Unknown count does not match evidence")
        if self.coverage.discharged_unknown_count != len(self.discharged_unknowns):
            raise ValueError("D4 discharged Unknown count does not match evidence")
        if self.coverage.observed_fact_count != len(self.observed_facts):
            raise ValueError("D4 observation count does not match evidence")
        if self.coverage.observed_unknown_count != len(self.dynamic_unknowns):
            raise ValueError("D4 dynamic Unknown count does not match evidence")
        if (
            self.coverage.exact_count
            + self.coverage.ambiguous_count
            + self.coverage.unmatched_count
            != len(self.correlations.records)
        ):
            raise ValueError("D4 correlation counts do not match records")
        if self.correlations.binding is not None:
            binding = self.correlations.binding
            if binding.status != BindingStatus.MATCH and any(
                item.status == CorrelationStatus.EXACT
                for item in self.correlations.records
            ):
                raise ValueError("D4 cannot mark a correlation exact when binding is not matched")
        return self


class AffineThreadSummary(_StrictModel):
    # execution_id 标识具体动态线程实例，不是静态 thread role。
    execution_id: str
    # sample_count 是该线程在相关站点的动态访问次数。
    sample_count: int
    # distinct_address_count 可能是采样截断后的下界。
    distinct_address_count: int
    # address_min 是观测到的最小地址，不是静态下界。
    address_min: str | None
    # address_max_end 是观测到的最大访问结束地址。
    address_max_end: str | None
    # sample_addresses 是受预算限制的地址样本序列。
    sample_addresses: tuple[str, ...]
    # sample_complete 表明地址样本是否完整。
    sample_complete: bool
    # stride_candidates 是相邻动态样本的差值集合。
    stride_candidates: tuple[int, ...]
    # stride_complete 表明差值候选是否触及采样上限。
    stride_complete: bool
    # role_candidates 是 tracer 提供的动态角色标签。
    role_candidates: tuple[str, ...]


class AffinePatternSummary(_StrictModel):
    # schema_version 固定 E1 pattern 子 schema。
    schema_version: Literal["observed-affine-pattern-v1"]
    # unknown_id 回到对应的 static affine-bound obligation。
    unknown_id: str
    # correlation_status 表示这一 pattern 的 site 身份确定程度。
    correlation_status: CorrelationStatus
    # correlation_key 说明 E1 使用的稳定位置字段。
    correlation_key: CorrelationKey
    # observed_ids 可回查支撑该摘要的具体 ObservedFact。
    observed_ids: tuple[str, ...]
    # trace_ids 明确 pattern 来自哪些动态执行。
    trace_ids: tuple[str, ...]
    # instruction_subjects 是可回查的指令 ID，而非地址证明。
    instruction_subjects: tuple[str, ...]
    # operand_subjects 是可回查的内存 operand ID。
    operand_subjects: tuple[str, ...]
    # sample_count 是受限采样中保留的地址数。
    sample_count: int
    # base_candidates 是十六进制编码的观察起点候选。
    base_candidates: tuple[str, ...]
    # stride_candidates 是观察步长候选，不是循环归纳证明。
    stride_candidates: tuple[int, ...]
    # thread_observations 保留每个 trace thread instance 的有界摘要。
    thread_observations: tuple[AffineThreadSummary, ...]
    # overlap 描述本次观察到的线程地址重叠状态。
    overlap: ObservedOverlap
    # repetition_stable 只表示当前样本中的差值是否相同。
    repetition_stable: bool | None
    # complete 表示 trace 和样本都没有被相关预算截断。
    complete: bool
    # status 是 E1 的观察质量枚举，不是 static verdict。
    status: ObservedAffineStatus
    # limitations 说明样本、角色或 trace 的具体限制。
    limitations: tuple[str, ...]


class AffineCoverageSummary(_StrictModel):
    # 下列计数保留 E1 原 coverage 字段。
    exercised_count: int
    ambiguous_count: int
    not_executed_count: int
    unmatched_count: int


class AffineReportSummary(_StrictModel):
    """保留 E1 affine-validation-report-v1 子 schema 的所有字段。"""

    # schema_version 固定 E1 汇总 schema。
    schema_version: Literal["affine-validation-report-v1"]
    # static_verdict 是 E1 读取时的静态结论，不会被 pattern 修改。
    static_verdict: CertificateVerdict
    # static_unknown_count 是快照中的全部静态 Unknown 数。
    static_unknown_count: int
    # affine_unknown_count 是其中 affine-bound Unknown 数。
    affine_unknown_count: int
    # trace_ids 标明 pattern 依赖的执行身份。
    trace_ids: tuple[str, ...]
    # trace_complete 表示所有输入 trace 的完整度合取。
    trace_complete: bool
    # coverage 保留 E1 的匹配状态汇总。
    coverage: AffineCoverageSummary
    # static_proof_unchanged 必须固定为 True。
    static_proof_unchanged: Literal[True]
    # statement 明确 affine pattern 仍只是 trace-bound observation。
    statement: Literal[
        "Observed affine patterns describe trace coverage only; the static verdict and proof remain unchanged."
    ]
    # patterns 保存每个 affine Unknown 的动态观察摘要。
    patterns: tuple[AffinePatternSummary, ...]

    @model_validator(mode="after")
    def preserve_affine_observation_scope(self) -> "AffineReportSummary":
        if self.static_proof_unchanged is not True:
            raise ValueError("E1 affine report cannot modify static proof")
        if self.static_unknown_count < self.affine_unknown_count:
            raise ValueError("affine Unknown count exceeds all static Unknowns")
        if len(self.patterns) != self.affine_unknown_count:
            raise ValueError("E1 pattern count does not cover its affine Unknowns")
        pattern_ids = [item.unknown_id for item in self.patterns]
        if len(pattern_ids) != len(set(pattern_ids)):
            raise ValueError("E1 patterns repeat a static Unknown")
        if any(not set(item.trace_ids).issubset(self.trace_ids) for item in self.patterns):
            raise ValueError("E1 pattern refers to a trace outside its report")
        if (
            self.coverage.exercised_count
            + self.coverage.ambiguous_count
            + self.coverage.unmatched_count
            != self.affine_unknown_count
        ):
            raise ValueError("E1 affine coverage counts do not match patterns")
        if self.coverage.not_executed_count > self.coverage.unmatched_count:
            raise ValueError("E1 not-executed count exceeds unmatched patterns")
        exercised = sum(
            item.correlation_status == CorrelationStatus.EXACT
            and bool(item.observed_ids)
            for item in self.patterns
        )
        ambiguous = sum(
            item.correlation_status == CorrelationStatus.AMBIGUOUS
            for item in self.patterns
        )
        unmatched = len(self.patterns) - exercised - ambiguous
        if (
            self.coverage.exercised_count != exercised
            or self.coverage.ambiguous_count != ambiguous
            or self.coverage.unmatched_count != unmatched
        ):
            raise ValueError("E1 coverage counts differ from the pattern correlation states")
        return self


class RootCauseAssessment(_StrictModel):
    # unknown_id 指向一项仍未闭合的静态 obligation。
    unknown_id: str
    # hint_id 将候选分类绑定回现有 D5 DiagnosticHint。
    hint_id: str | None
    # candidate 是诊断分类，不等同于已经证明的因果根因。
    candidate: DiagnosticRootCause | None
    # confidence 原样来自 D5，不能当作 proof confidence。
    confidence: float | None
    # correlation_status 说明分类所依赖的 site 匹配质量。
    correlation_status: CorrelationStatus | None
    # causal_status 在当前无 typed cause edge 时必须保持 unresolved。
    causal_status: CausalStatus
    # rationale 解释分类线索，同时指出因果链仍未确立。
    rationale: str

    @model_validator(mode="after")
    def keep_candidate_fields_together(self) -> "RootCauseAssessment":
        if (self.hint_id is None) != (self.candidate is None):
            raise ValueError("a root-cause candidate and its hint ID must appear together")
        if (self.hint_id is None) != (self.confidence is None):
            raise ValueError("a root-cause candidate and confidence must appear together")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("diagnostic confidence must be in [0, 1]")
        return self


class DiagnosticBundleSummary(_StrictModel):
    # d4_report 是独立的 static-unknown/dynamic-observation 相关结果。
    d4_report: D4ReportSummary
    # affine_report 保留 E1 pattern 子报告，不重解释其观察含义。
    affine_report: AffineReportSummary
    # root_cause_assessments 把 D5 提示与因果状态放在一起展示。
    root_cause_assessments: tuple[RootCauseAssessment, ...]


class StaticScopeSummary(_StrictModel):
    # executable_sha256 绑定静态恢复使用的主 ELF 内容。
    executable_sha256: str
    # library_sha256 绑定静态分析的运行库闭包。
    library_sha256: tuple[str, ...]
    # dbt_contract_version 指出静态 route 使用的 lowering 契约版本。
    dbt_contract_version: str
    # dbt_revision 绑定 DBT 实现，而非只绑定模型名称。
    dbt_revision: str
    # 两个摘要界定静态分析期间 contract 是否被修改。
    dbt_contract_sha256_before: str
    dbt_contract_sha256_after: str
    # function_effect_contract_version 说明外部函数摘要假设的版本。
    function_effect_contract_version: str | None
    # function_effect_contract_sha256 绑定该摘要文件内容。
    function_effect_contract_sha256: str | None
    # argv 限定当前静态 workload scope。
    argv: tuple[str, ...]
    # thread_count_min 是静态证明允许的最少线程数。
    thread_count_min: int | None
    # thread_count_max 是静态证明允许的最多线程数。
    thread_count_max: int | None
    # analysis_scope 区分 full 与显式 application scope。
    analysis_scope: str
    # analysis_config_sha256 绑定 checker 与环境配置摘要。
    analysis_config_sha256: str | None

    @model_validator(mode="after")
    def validate_static_fingerprints(self) -> "StaticScopeSummary":
        if not _sha256(self.executable_sha256) or any(
            not _sha256(item) for item in self.library_sha256
        ):
            raise ValueError("static binary hashes must be lowercase SHA-256 digests")
        if not _sha256(self.dbt_contract_sha256_before) or not _sha256(
            self.dbt_contract_sha256_after
        ):
            raise ValueError("static DBT contract hashes must be SHA-256 digests")
        for digest in (
            self.function_effect_contract_sha256,
            self.analysis_config_sha256,
        ):
            if digest is not None and not _sha256(digest):
                raise ValueError("static contract/config hashes must be SHA-256 digests")
        return self


class StaticCoverageSummary(_StrictModel):
    # modules/functions 说明二进制恢复规模。
    modules: int
    functions: int
    # indirect_sites/incomplete_indirect_sites 表示间接控制流闭合程度。
    indirect_sites: int
    incomplete_indirect_sites: int
    # thread_roles/unknown_thread_entries 表示静态线程角色恢复结果。
    thread_roles: int
    unknown_thread_entries: int
    # memory_events/shared_events 表示访存提取和共享切片规模。
    memory_events: int
    shared_events: int
    # unknown_memory_effects 记录未闭合的普通访存 effect 数量。
    unknown_memory_effects: int
    # shared_objects/unknown_shared_objects 记录地址分类规模。
    shared_objects: int
    unknown_shared_objects: int


class StaticCheckerSummary(_StrictModel):
    # backend/version 绑定静态 certificate 原样记录的 checker 实现。
    backend: str
    backend_version: str
    # bounded=True 时不允许把有限搜索当成 SAFE。
    bounded: bool
    # conclusion 是 checker 内部结论，不与最终 route verdict 混用。
    conclusion: CheckerConclusion
    # limits 是此次静态 checker 的事件、线程、枚举和时间预算。
    limits: CheckerLimits
    # examined_executions 记录已枚举的有限执行数。
    examined_executions: int
    # reason 说明 checker 为什么给出当前结论。
    reason: str
    # unsupported_events 列出阻止编码的事件 ID。
    unsupported_events: tuple[str, ...]
    # assumptions 明示有限模型依赖的边界。
    assumptions: tuple[str, ...]


class RemovalSummary(_StrictModel):
    # event_id 是被静态剪枝的 MemoryEvent ID。
    event_id: str
    # proof_id 必须指向报告内 proof closure 的 ProofFact。
    proof_id: str
    # scope 限定这条 removal decision 的覆盖范围。
    scope: str


class CanonicalStaticCertificateSummary(_StrictModel):
    # schema_version 是通过 replay 的 canonical static certificate schema。
    schema_version: str
    # verdict 必须和兼容 route 报告中的静态 verdict 相同。
    verdict: CertificateVerdict
    # binary_closure_id 绑定主 ELF、库闭包和 ABI。
    binary_closure_id: str
    # dbt_contract_version 绑定实际 lowering rule。
    dbt_contract_version: str
    # dbt_revision 绑定被分析的 DBT 实现 revision。
    dbt_revision: str
    # scope 是 proof closure 可以覆盖的分析边界。
    scope: str
    # proof_root_ids 是 replay 从中展开 closure 的入口。
    proof_root_ids: tuple[str, ...]
    # proof_closure_ids 是 replay 验证通过的完整 ProofFact closure。
    proof_closure_ids: tuple[str, ...]
    # removal_decisions 把每个剪枝事件绑定到 closure 中的证明。
    removal_decisions: tuple[RemovalSummary, ...]
    # relevant_unknown_ids 必须保留所有未闭合的 static obligations。
    relevant_unknown_ids: tuple[str, ...]
    # discharged_unknown_ids 是 canonical replay 验证过的静态 discharge。
    discharged_unknown_ids: tuple[str, ...]
    # bounded 阻止有限 no-counterexample 被外推成 SAFE。
    bounded: bool


class StaticObligationSummary(_StrictModel):
    # identity_source 说明是否已有 canonical EvidenceId。
    identity_source: ObligationIdentitySource
    # evidence_id 在 legacy-only 路径没有稳定 canonical identity。
    evidence_id: str | None
    # kind 保留 Unknown registry 的名称。
    kind: UnknownKind
    # reason 描述未闭合 proof obligation 的具体缺口。
    reason: str
    # scope 说明 obligation 阻塞的静态分析范围。
    scope: str
    # producer 指出产生 Unknown 的分析 pass（旧证书可能没有该字段）。
    producer: str | None
    # subject 指向已稳定识别的静态对象或指令。
    subject: str | None
    # provenance_ids 保留可追溯的静态父证据。
    provenance_ids: tuple[str, ...]
    # supporting_context 保留 PC、函数等定位线索。
    supporting_context: tuple[str, ...]
    # impact 是旧静态模型对这项 Unknown 的影响说明。
    impact: str | None
    # module/function/pc 兼容保存旧 report 有、canonical Unknown 未归一化的定位字段。
    module: str | None
    function: str | None
    pc: int | None

    @model_validator(mode="after")
    def require_identity_for_canonical(self) -> "StaticObligationSummary":
        if self.identity_source == ObligationIdentitySource.CANONICAL:
            if self.evidence_id is None:
                raise ValueError("canonical obligation requires an EvidenceId")
        elif self.evidence_id is not None:
            raise ValueError("legacy obligation cannot claim a canonical EvidenceId")
        return self


class StaticWorkflowSummary(_StrictModel):
    # verdict 保留 static route 自己的 SAFE/COUNTEREXAMPLE/UNKNOWN。
    verdict: CertificateVerdict
    # legacy_schema_version 让兼容 certificate 格式可被审计。
    legacy_schema_version: int
    # scope 固定静态证明适用的 binary、contract、argv 和线程范围。
    scope: StaticScopeSummary
    # coverage 汇总静态恢复到 shared slice 的入口覆盖。
    coverage: StaticCoverageSummary
    # checker 是 legacy 静态证书里的底层 solver 结果。
    checker: StaticCheckerSummary
    # canonical_certificate 只在已 replay 成功时出现。
    canonical_certificate: CanonicalStaticCertificateSummary | None
    # canonical_error 明示没有 replayed certificate 的原因。
    canonical_error: str | None
    # blocking_unknowns 是当前仍未闭合的 obligations，不包含已 discharge 项。
    blocking_unknowns: tuple[StaticObligationSummary, ...]

    @model_validator(mode="after")
    def keep_canonical_route_in_step(self) -> "StaticWorkflowSummary":
        if (self.canonical_certificate is None) != (self.canonical_error is not None):
            raise ValueError("canonical certificate and explicit error must be complementary")
        if self.canonical_certificate is not None:
            if self.canonical_certificate.verdict != self.verdict:
                raise ValueError("canonical and legacy static verdicts differ")
            if self.canonical_certificate.bounded != self.checker.bounded:
                raise ValueError("canonical and legacy checker boundedness differs")
            if self.canonical_certificate.scope != self.scope.analysis_scope:
                raise ValueError("canonical and legacy static scopes differ")
            if self.canonical_certificate.dbt_revision != self.scope.dbt_revision:
                raise ValueError("canonical and legacy DBT revisions differ")
            if self.canonical_certificate.dbt_contract_version != self.scope.dbt_contract_version:
                raise ValueError("canonical and legacy DBT contract versions differ")
            proof_ids = set(self.canonical_certificate.proof_closure_ids)
            proof_roots = self.canonical_certificate.proof_root_ids
            relevant_unknown_ids = self.canonical_certificate.relevant_unknown_ids
            discharged_unknown_ids = self.canonical_certificate.discharged_unknown_ids
            removal_decisions = self.canonical_certificate.removal_decisions
            if len(proof_ids) != len(self.canonical_certificate.proof_closure_ids):
                raise ValueError("static proof closure contains duplicate EvidenceIds")
            if len(set(proof_roots)) != len(proof_roots) or not set(proof_roots).issubset(proof_ids):
                raise ValueError("static proof roots are absent from the replayed closure")
            if len(set(relevant_unknown_ids)) != len(relevant_unknown_ids):
                raise ValueError("static certificate repeats a relevant Unknown")
            if not set(discharged_unknown_ids).issubset(set(relevant_unknown_ids)):
                raise ValueError("discharged Unknown is absent from the certificate obligations")
            if any(item.proof_id not in proof_ids for item in removal_decisions):
                raise ValueError("removed event references a proof outside the closure")
            if len({item.event_id for item in removal_decisions}) != len(removal_decisions):
                raise ValueError("static certificate repeats a removal decision")
            unknown_ids = {
                item.evidence_id
                for item in self.blocking_unknowns
                if item.evidence_id is not None
            }
            if len(unknown_ids) != len(self.blocking_unknowns):
                raise ValueError("static certificate repeats a blocking Unknown")
            if unknown_ids != set(relevant_unknown_ids):
                raise ValueError("static blocker IDs differ from canonical certificate")
            if any(
                item.identity_source != ObligationIdentitySource.CANONICAL
                for item in self.blocking_unknowns
            ):
                raise ValueError("canonical certificate blockers must have EvidenceIds")
        elif self.verdict != CertificateVerdict.UNKNOWN:
            raise ValueError("static result without replayed certificate cannot claim a verdict")
        if self.verdict == CertificateVerdict.SAFE:
            if (
                self.checker.conclusion != CheckerConclusion.STRUCTURAL_SAFE
                or self.checker.bounded
                or self.blocking_unknowns
                or self.canonical_certificate is None
                or self.canonical_certificate.bounded
                or self.canonical_certificate.relevant_unknown_ids
            ):
                raise ValueError("SAFE requires an unbounded, closed static proof")
        elif self.verdict == CertificateVerdict.COUNTEREXAMPLE:
            if self.checker.conclusion != CheckerConclusion.TARGET_ONLY:
                raise ValueError("static counterexample must retain a target-only checker result")
        elif self.checker.conclusion in {
            CheckerConclusion.STRUCTURAL_SAFE,
            CheckerConclusion.TARGET_ONLY,
        }:
            raise ValueError("UNKNOWN cannot hide a conclusive static checker result")
        return self


class BinaryFingerprintSummary(_StrictModel):
    # path 供用户定位已绑定的 ELF，不参与内容身份比较。
    path: str
    # sha256 是模块内容身份。
    sha256: str
    # build_id 是可选的 ELF build-id 说明。
    build_id: str | None

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _sha256(value):
            raise ValueError("binary fingerprint sha256 must be lowercase hexadecimal")
        return value


class EnvironmentEntry(_StrictModel):
    # name 是传给同一 workload 的环境变量名。
    name: str
    # value_sha256 让报告可比对输入，又不复制可能含 token 的原始值。
    value_sha256: str

    @field_validator("value_sha256")
    @classmethod
    def validate_value_sha256(cls, value: str) -> str:
        if not _sha256(value):
            raise ValueError("environment value digest must be lowercase hexadecimal")
        return value


class CountEntry(_StrictModel):
    # name 是 drop counter 或其他按原因统计的稳定类别名。
    name: str
    # count 是该原因下的非负丢失事件数。
    count: int


class TraceManifestSummary(_StrictModel):
    # schema_version 固定 DynamoRIO trace manifest 的解释方式。
    schema_version: str
    # manifest_trace_id 是 launcher ID，不等于内容派生 TraceId。
    manifest_trace_id: str
    # created_at 记录 trace manifest 的生成时间。
    created_at: str
    # platform/architecture 说明 trace 的采集环境。
    platform: str
    architecture: str
    # command/cwd/env 绑定实际启动的同一份 workload。
    command: tuple[str, ...]
    working_directory: str
    environment: tuple[EnvironmentEntry, ...]
    # executable/libraries 绑定加载的模块内容。
    executable: BinaryFingerprintSummary
    libraries: tuple[BinaryFingerprintSummary, ...]
    # dynamorio_version/client_version 固定采集实现身份。
    dynamorio_version: str
    client_version: str
    # complete/exit/drop 字段暴露采集是否完整及丢失情况。
    complete: bool
    exit_code: int | None
    dropped_events: int
    dropped_by_reason: tuple[CountEntry, ...]
    # control_flow_closed 表示 manifest 自己的控制流尾标记是否完整。
    control_flow_closed: bool
    # limitations 保留 tracer 明示的采集边界。
    limitations: tuple[str, ...]


class DynamicWorkflowSummary(_StrictModel):
    # certificate 保留动态 checker 的原始 trace-bound verdict 和范围。
    certificate: DynamicCertificate
    # manifest 保留采集输入、模块闭包、client 和丢事件状态。
    manifest: TraceManifestSummary
    # content_trace_id 是 trace bytes 派生的稳定 ID。
    content_trace_id: str
    # trace_sha256 绑定 manifest、module map、marker 和 trace chunks。
    trace_sha256: str
    # dbt_contract_sha256 绑定 target lowering contract 的实际字节。
    dbt_contract_sha256: str

    @model_validator(mode="after")
    def keep_trace_binding_closed(self) -> "DynamicWorkflowSummary":
        certificate = self.certificate
        manifest = self.manifest
        if certificate.scope.trace_ids != (manifest.manifest_trace_id,):
            raise ValueError("dynamic certificate and manifest trace IDs differ")
        if certificate.scope.trace_sha256 != (self.trace_sha256,):
            raise ValueError("dynamic certificate and report trace digests differ")
        if certificate.dbt_contract_sha256 != self.dbt_contract_sha256:
            raise ValueError("dynamic certificate and report DBT contract digests differ")
        if (
            certificate.scope.executable.path != manifest.executable.path
            or certificate.scope.executable.sha256 != manifest.executable.sha256
            or certificate.scope.executable.build_id != manifest.executable.build_id
        ):
            raise ValueError("dynamic certificate and manifest executable differ")
        if len(certificate.scope.libraries) != len(manifest.libraries) or any(
            left.path != right.path
            or left.sha256 != right.sha256
            or left.build_id != right.build_id
            for left, right in zip(certificate.scope.libraries, manifest.libraries)
        ):
            raise ValueError("dynamic certificate and manifest library closure differs")
        if certificate.scope.commands != (manifest.command,):
            raise ValueError("dynamic certificate and manifest commands differ")
        if certificate.scope.working_directories != (manifest.working_directory,):
            raise ValueError("dynamic certificate and manifest working directories differ")
        if certificate.trace_complete != manifest.complete:
            raise ValueError("dynamic certificate and manifest completeness differ")
        if certificate.scope.analysis_scope not in {"full", "application"}:
            raise ValueError("dynamic certificate has an unsupported analysis scope")
        if not self.content_trace_id:
            raise ValueError("trace content and contract identities must be present")
        if not _sha256(self.trace_sha256) or not _sha256(self.dbt_contract_sha256):
            raise ValueError("trace and DBT contract identities must be SHA-256 digests")
        return self


class ProofBoundarySummary(_StrictModel):
    # static_statement 明确静态 SAFE 需要独立 replay 的静态 proof closure。
    static_statement: Literal["Static SAFE requires a replayed static ProofFact closure."]
    # trace_statement 限定动态 verdict 只适用于报告绑定的执行轨迹。
    trace_statement: Literal["Dynamic verdicts apply only to the trace bound in this report."]
    # diagnostic_statement 禁止观察和 hint 改写静态 proof 或 verdict。
    diagnostic_statement: Literal[
        "ObservedFact and DiagnosticHint locate static gaps; they never modify static proof or verdict."
    ]
    # observations_enter_static_proof 必须固定为 False。
    observations_enter_static_proof: Literal[False]
    # hints_discharge_unknowns 必须固定为 False。
    hints_discharge_unknowns: Literal[False]
    # combined_verdict 明确表示系统没有合并 static/dynamic verdict。
    combined_verdict: Literal["not_defined"]


class HybridWorkflowReport(_StrictModel):
    """一次 workload 的静态、动态与诊断结果；没有 combined verdict 字段。"""

    # schema_version 固定此顶层 report 的字段语义。
    schema_version: Literal["hybrid-workflow-report-v1"]
    # static 是静态 analyzer 与 canonical replay 的结果摘要。
    static: StaticWorkflowSummary
    # dynamic 是绑定到 manifest、trace 内容和 DBT contract 的动态结果。
    dynamic: DynamicWorkflowSummary
    # diagnostics 只有 static canonical certificate replay 成功时才出现。
    diagnostics: DiagnosticBundleSummary | None
    # diagnostics_unavailable_reason 解释无法安全跨 route 关联的原因。
    diagnostics_unavailable_reason: str | None
    # proof_boundary 是机器可检查的静态/动态隔离声明。
    proof_boundary: ProofBoundarySummary

    @model_validator(mode="after")
    def preserve_independent_verdicts_and_evidence(self) -> "HybridWorkflowReport":
        if (self.diagnostics is None) != (self.diagnostics_unavailable_reason is not None):
            raise ValueError("diagnostics and explicit unavailable reason must be complementary")
        if self.diagnostics is None and self.static.canonical_certificate is not None:
            raise ValueError("replayed static certificate cannot silently lose diagnostics")
        if self.diagnostics is not None and self.static.canonical_certificate is None:
            raise ValueError("diagnostics cannot exist without a replayed static certificate")
        if self.diagnostics is not None:
            d4 = self.diagnostics.d4_report
            affine = self.diagnostics.affine_report
            if d4.static_verdict != self.static.verdict or affine.static_verdict != self.static.verdict:
                raise ValueError("diagnostic child report changed the static verdict")
            if d4.trace_id != self.dynamic.content_trace_id:
                raise ValueError("D4 report is bound to another trace content identity")
            if d4.trace_complete != self.dynamic.certificate.trace_complete:
                raise ValueError("D4 and dynamic certificate completeness differ")
            if d4.trace_certificate.trace_id != self.dynamic.content_trace_id:
                raise ValueError("D4 certificate identity is bound to another content TraceId")
            if d4.trace_certificate.scope != (
                f"dynamic.{self.dynamic.certificate.scope.analysis_scope}"
            ):
                raise ValueError("D4 trace certificate and dynamic analysis scopes differ")
            if d4.trace_certificate.artifact_sha256 != self.dynamic.trace_sha256:
                raise ValueError("D4 trace certificate is bound to another trace digest")
            canonical = self.static.canonical_certificate
            assert canonical is not None
            if d4.static_certificate.binary_closure != canonical.binary_closure_id:
                raise ValueError("D4 static identity differs from canonical certificate closure")
            if d4.static_certificate.scope != self.static.scope.analysis_scope:
                raise ValueError("D4 static identity differs from static analysis scope")
            binding = d4.correlations.binding
            if binding is None:
                raise ValueError("hybrid diagnostics require explicit cross-route binding")
            binary_check = next(
                item for item in binding.checks
                if item.dimension == BindingDimension.BINARY_CLOSURE
            )
            static_closure = d4.static_certificate.binary_closure
            dynamic_closure = d4.trace_certificate.binary_closure
            if binary_check.status == BindingStatus.MATCH and (
                static_closure is None
                or dynamic_closure is None
                or static_closure != dynamic_closure
            ):
                raise ValueError("matched binary closure differs from D4 certificate identities")
            if binary_check.status == BindingStatus.MISMATCH and (
                static_closure is None
                or dynamic_closure is None
                or static_closure == dynamic_closure
            ):
                raise ValueError("binary closure mismatch lacks distinct certificate identities")
            if binary_check.status == BindingStatus.UNVERIFIED and (
                static_closure is not None and dynamic_closure is not None
            ):
                raise ValueError("binary closure is unverified despite both identities")
            policy_check = next(
                item for item in binding.checks
                if item.dimension == BindingDimension.TRANSLATION_POLICY
            )
            if (
                self.static.scope.dbt_contract_sha256_before
                != self.static.scope.dbt_contract_sha256_after
            ):
                expected_policy_status = BindingStatus.UNVERIFIED
            elif (
                self.static.scope.dbt_contract_sha256_after
                == self.dynamic.dbt_contract_sha256
            ):
                expected_policy_status = BindingStatus.MATCH
            else:
                expected_policy_status = BindingStatus.MISMATCH
            if policy_check.status != expected_policy_status:
                raise ValueError(
                    "translation-policy binding differs from the recorded contract hashes"
                )
            scope_check = next(
                item for item in binding.checks
                if item.dimension == BindingDimension.ANALYSIS_SCOPE
            )
            same_scope = (
                self.static.scope.analysis_scope
                == self.dynamic.certificate.scope.analysis_scope
            )
            expected_scope_status = (
                BindingStatus.MATCH if same_scope else BindingStatus.MISMATCH
            )
            if scope_check.status != expected_scope_status:
                raise ValueError("scope binding status differs from route scope values")
            d4_blockers = {item.id for item in d4.blocking_unknowns}
            static_blockers = {
                item.evidence_id
                for item in self.static.blocking_unknowns
                if item.evidence_id is not None
            }
            if d4_blockers != static_blockers:
                raise ValueError("D4 and static summary blocker sets differ")
            if affine.trace_ids != (self.dynamic.content_trace_id,):
                raise ValueError("E1 affine report is bound to another trace")
            observation_ids = {item.id for item in d4.observed_facts}
            blocker_ids = d4_blockers
            for record in d4.correlations.records:
                if record.unknown_id not in blocker_ids:
                    raise ValueError("correlation references a non-blocking Unknown")
                if not set(record.observed_ids).issubset(observation_ids):
                    raise ValueError("correlation references an absent observation")
            for hint in d4.hints:
                if not set(hint.unknown_ids).issubset(blocker_ids):
                    raise ValueError("hint references a non-blocking Unknown")
                if not set(hint.observed_ids).issubset(observation_ids):
                    raise ValueError("hint references an absent observation")
            for pattern in affine.patterns:
                blocker = next(
                    (item for item in d4.blocking_unknowns if item.id == pattern.unknown_id),
                    None,
                )
                if blocker is None:
                    raise ValueError("affine pattern references a non-blocking Unknown")
                if blocker.kind != UnknownKind.UNKNOWN_AFFINE_BOUNDS:
                    raise ValueError("affine pattern does not reference UnknownAffineBounds")
                if not set(pattern.observed_ids).issubset(observation_ids):
                    raise ValueError("affine pattern references an absent observation")
            assessments = self.diagnostics.root_cause_assessments
            assessment_ids = [item.unknown_id for item in assessments]
            if len(assessment_ids) != len(set(assessment_ids)) or set(assessment_ids) != blocker_ids:
                raise ValueError("root-cause assessments must cover each blocker exactly once")
            hints_by_id = {item.id: item for item in d4.hints}
            records_by_unknown = {
                item.unknown_id: item for item in d4.correlations.records
            }
            for assessment in assessments:
                if assessment.causal_status != CausalStatus.UNRESOLVED:
                    raise ValueError("D5 classification cannot claim a causal root")
                if assessment.hint_id is not None:
                    hint = hints_by_id.get(assessment.hint_id)
                    if hint is None or assessment.unknown_id not in hint.unknown_ids:
                        raise ValueError("root-cause assessment is detached from its D5 hint")
                    if assessment.candidate != hint.root_cause or assessment.confidence != hint.confidence:
                        raise ValueError("root-cause assessment changed its D5 candidate")
                record = records_by_unknown.get(assessment.unknown_id)
                expected_correlation = record.status if record is not None else None
                if assessment.correlation_status != expected_correlation:
                    raise ValueError("root-cause assessment changed its D4 correlation status")
            proof_ids = set(
                self.static.canonical_certificate.proof_closure_ids
                if self.static.canonical_certificate is not None
                else ()
            )
            hint_ids = {item.id for item in d4.hints}
            if proof_ids & (observation_ids | hint_ids):
                raise ValueError("dynamic evidence and hints cannot appear in static proof closure")
        return self

    def to_dict(self) -> dict[str, object]:
        """通过显式 serializer 导出严格、JSON-compatible 的对象。"""

        return self.model_dump(mode="json")

    def to_json(self) -> str:
        """使用稳定字段排序序列化，便于保存和 review。"""

        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)


def _canonical_obligation(unknown: UnknownFact) -> StaticObligationSummary:
    return StaticObligationSummary(
        identity_source=ObligationIdentitySource.CANONICAL,
        evidence_id=unknown.id.value,
        kind=unknown.kind,
        reason=unknown.reason,
        scope=unknown.scope,
        producer=unknown.producer.value,
        subject=unknown.subject.value if unknown.subject is not None else None,
        provenance_ids=tuple(item.value for item in unknown.provenance),
        supporting_context=unknown.supporting_context,
        impact=None,
        module=None,
        function=None,
        pc=None,
    )


def _legacy_obligation(unknown: LegacyUnknownFact, scope: str) -> StaticObligationSummary:
    return StaticObligationSummary(
        identity_source=ObligationIdentitySource.LEGACY,
        evidence_id=None,
        kind=UnknownKind(unknown.kind.value),
        reason=unknown.reason,
        scope=scope,
        producer=None,
        subject=None,
        provenance_ids=(),
        supporting_context=(),
        impact=unknown.impact,
        module=unknown.module,
        function=unknown.function,
        pc=unknown.pc,
    )


def _binding_for_static(result: HybridWorkflowResult) -> tuple[str, str, str]:
    static = result.static_analysis.canonical_certificate
    if static is None:
        raise HybridReportError("canonical static binding is unavailable")
    binding = static.certificate.binding
    return binding.binary_closure.value, binding.dbt_contract_version, binding.scope


def _static_summary(result: HybridWorkflowResult) -> StaticWorkflowSummary:
    legacy = result.static_analysis.legacy_certificate
    scope = legacy.scope
    canonical = result.static_analysis.canonical_certificate
    if canonical is None:
        blockers = tuple(
            _legacy_obligation(item, scope.analysis_scope)
            for item in legacy.relevant_unknowns
        )
        canonical_summary = None
    else:
        certificate = canonical.certificate
        verification = canonical.verification
        if verification.certificate != certificate:
            raise HybridReportError("static replay result refers to another certificate")
        if any(not isinstance(item, ProofFact) for item in verification.proof_closure):
            raise HybridReportError("static replay closure contains a non-ProofFact")
        if result.diagnostics is not None:
            blockers = tuple(
                _canonical_obligation(item)
                for item in result.diagnostics.report.blocking_unknowns
            )
        else:
            canonical_blockers: list[StaticObligationSummary] = []
            for evidence_id in certificate.relevant_unknowns:
                unknown = canonical.ledger.get(evidence_id)
                if not isinstance(unknown, UnknownFact):
                    raise HybridReportError(
                        "canonical certificate references a missing or non-Unknown blocker"
                    )
                canonical_blockers.append(_canonical_obligation(unknown))
            blockers = tuple(canonical_blockers)
        binary_closure_id, _contract_version, _scope = _binding_for_static(result)
        canonical_summary = CanonicalStaticCertificateSummary(
            schema_version=certificate.schema_version,
            verdict=certificate.verdict,
            binary_closure_id=binary_closure_id,
            dbt_contract_version=certificate.binding.dbt_contract_version,
            dbt_revision=certificate.binding.dbt_revision,
            scope=certificate.binding.scope,
            proof_root_ids=tuple(item.value for item in certificate.proof_roots),
            proof_closure_ids=tuple(item.id.value for item in verification.proof_closure),
            removal_decisions=tuple(
                RemovalSummary(
                    event_id=item.event_id.value,
                    proof_id=item.proof_id.value,
                    scope=item.scope,
                )
                for item in certificate.removal_decisions
            ),
            relevant_unknown_ids=tuple(item.value for item in certificate.relevant_unknowns),
            discharged_unknown_ids=tuple(item.value for item in verification.discharged_unknowns),
            bounded=certificate.bounded,
        )
    return StaticWorkflowSummary(
        verdict=CertificateVerdict(legacy.verdict.value),
        legacy_schema_version=legacy.schema_version,
        scope=StaticScopeSummary(
            executable_sha256=scope.executable_sha256,
            library_sha256=scope.library_sha256,
            dbt_contract_version=scope.dbt_contract_version,
            dbt_revision=scope.dbt_revision,
            dbt_contract_sha256_before=result.static_policy_sha256_before,
            dbt_contract_sha256_after=result.static_policy_sha256_after,
            function_effect_contract_version=scope.function_effect_contract_version,
            function_effect_contract_sha256=scope.function_effect_contract_sha256,
            argv=scope.argv,
            thread_count_min=scope.thread_count_min,
            thread_count_max=scope.thread_count_max,
            analysis_scope=scope.analysis_scope,
            analysis_config_sha256=scope.analysis_config_sha256,
        ),
        coverage=StaticCoverageSummary(
            modules=legacy.coverage.modules,
            functions=legacy.coverage.functions,
            indirect_sites=legacy.coverage.indirect_sites,
            incomplete_indirect_sites=legacy.coverage.incomplete_indirect_sites,
            thread_roles=legacy.coverage.thread_roles,
            unknown_thread_entries=legacy.coverage.unknown_thread_entries,
            memory_events=legacy.coverage.memory_events,
            shared_events=legacy.coverage.shared_events,
            unknown_memory_effects=legacy.coverage.unknown_memory_effects,
            shared_objects=legacy.coverage.shared_objects,
            unknown_shared_objects=legacy.coverage.unknown_shared_objects,
        ),
        checker=StaticCheckerSummary(
            backend=legacy.checker.backend,
            backend_version=legacy.checker.backend_version,
            bounded=legacy.checker.bounded,
            conclusion=legacy.checker.conclusion,
            limits=legacy.checker.limits,
            examined_executions=legacy.checker.examined_executions,
            reason=legacy.checker.reason,
            unsupported_events=legacy.checker.unsupported_events,
            assumptions=legacy.checker.assumptions,
        ),
        canonical_certificate=canonical_summary,
        canonical_error=result.static_analysis.canonical_error,
        blocking_unknowns=blockers,
    )


def _manifest_summary(manifest: TraceManifest) -> TraceManifestSummary:
    return TraceManifestSummary(
        schema_version=manifest.schema_version,
        manifest_trace_id=manifest.trace_id,
        created_at=manifest.created_at,
        platform=manifest.platform,
        architecture=manifest.architecture,
        command=manifest.command,
        working_directory=manifest.working_directory,
        environment=tuple(
            EnvironmentEntry(
                name=name,
                value_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
            )
            for name, value in sorted(manifest.environment.items())
        ),
        executable=BinaryFingerprintSummary(
            path=manifest.executable.path,
            sha256=manifest.executable.sha256,
            build_id=manifest.executable.build_id,
        ),
        libraries=tuple(
            BinaryFingerprintSummary(
                path=item.path,
                sha256=item.sha256,
                build_id=item.build_id,
            )
            for item in manifest.libraries
        ),
        dynamorio_version=manifest.dynamorio_version,
        client_version=manifest.client_version,
        complete=manifest.complete,
        exit_code=manifest.exit_code,
        dropped_events=manifest.dropped_events,
        dropped_by_reason=tuple(
            CountEntry(name=name, count=count)
            for name, count in sorted(manifest.dropped_by_reason.items())
        ),
        control_flow_closed=manifest.control_flow_closed,
        limitations=manifest.limitations,
    )


def _dynamic_summary(result: HybridWorkflowResult) -> DynamicWorkflowSummary:
    bound = result.dynamic_evidence
    try:
        certificate = DynamicCertificate.model_validate_json(
            bound.certificate.model_dump_json()
        )
    except ValidationError as error:
        raise HybridReportError(f"dynamic certificate is not serializable: {error}") from error
    return DynamicWorkflowSummary(
        certificate=certificate,
        manifest=_manifest_summary(bound.manifest),
        content_trace_id=bound.content_trace_id.value,
        trace_sha256=bound.trace_sha256,
        dbt_contract_sha256=bound.dbt_contract_sha256,
    )


def _diagnostic_bundle(result: HybridWorkflowResult) -> DiagnosticBundleSummary | None:
    products = result.diagnostics
    if products is None:
        return None
    d4_payload = report_to_dict(products.report)
    affine_payload = affine_report_to_dict(products.affine_report)
    try:
        d4 = D4ReportSummary.model_validate_json(json.dumps(d4_payload))
        affine = AffineReportSummary.model_validate_json(json.dumps(affine_payload))
    except ValidationError as error:
        raise HybridReportError(f"D4/E1 report failed the workflow schema: {error}") from error

    records = {item.unknown_id: item for item in products.report.correlations.records}
    hints = {
        unknown_id: hint
        for hint in products.report.hints
        for unknown_id in hint.unknown_ids
    }
    assessments: list[RootCauseAssessment] = []
    for unknown in products.report.blocking_unknowns:
        record = records.get(unknown.id)
        hint = hints.get(unknown.id)
        assessments.append(
            RootCauseAssessment(
                unknown_id=unknown.id.value,
                hint_id=hint.id.value if hint is not None else None,
                candidate=(
                    DiagnosticRootCause(hint.root_cause) if hint is not None else None
                ),
                confidence=hint.confidence if hint is not None else None,
                correlation_status=record.status if record is not None else None,
                causal_status=CausalStatus.UNRESOLVED,
                rationale=(
                    hint.explanation
                    if hint is not None
                    else "D4 produced no D5 hint for this blocker; causal relation remains unresolved."
                ),
            )
        )
    return DiagnosticBundleSummary(
        d4_report=d4,
        affine_report=affine,
        root_cause_assessments=tuple(assessments),
    )


def build_hybrid_workflow_report(result: HybridWorkflowResult) -> HybridWorkflowReport:
    """把 H4 service 结果投影成一个不合并 verdict 的 versioned report。"""

    if not isinstance(result, HybridWorkflowResult):
        raise HybridReportError("build_hybrid_workflow_report expects HybridWorkflowResult")
    try:
        return HybridWorkflowReport(
            schema_version=_REPORT_SCHEMA,
            static=_static_summary(result),
            dynamic=_dynamic_summary(result),
            diagnostics=_diagnostic_bundle(result),
            diagnostics_unavailable_reason=result.diagnostics_unavailable_reason,
            proof_boundary=ProofBoundarySummary(
                static_statement=_STATIC_BOUNDARY,
                trace_statement=_TRACE_BOUNDARY,
                diagnostic_statement=_DIAGNOSTIC_BOUNDARY,
                observations_enter_static_proof=False,
                hints_discharge_unknowns=False,
                combined_verdict="not_defined",
            ),
        )
    except HybridReportError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError) as error:
        raise HybridReportError(f"cannot build hybrid workflow report: {error}") from error


def hybrid_report_from_dict(payload: object) -> HybridWorkflowReport:
    """严格解析顶层 report；未知 schema 或字段不做静默兼容。"""

    if not isinstance(payload, dict):
        raise HybridReportError("hybrid report must be a JSON object")
    try:
        return HybridWorkflowReport.model_validate_json(
            json.dumps(payload, ensure_ascii=False, allow_nan=False)
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise HybridReportError(f"invalid hybrid workflow report: {error}") from error


def hybrid_report_from_json(payload: str) -> HybridWorkflowReport:
    """读取一个 JSON 文档，并拒绝缺 schema 或未声明字段。"""

    if not isinstance(payload, str):
        raise HybridReportError("hybrid report JSON must be text")
    try:
        report = HybridWorkflowReport.model_validate_json(payload)
    except (ValueError, ValidationError) as error:
        raise HybridReportError(f"invalid hybrid workflow report JSON: {error}") from error
    if report.schema_version != _REPORT_SCHEMA:
        raise HybridReportError(f"unsupported hybrid report schema: {report.schema_version}")
    return report


def save_hybrid_workflow_report(report: HybridWorkflowReport, path: Path) -> None:
    """写到调用者指定的位置；大 trace 仍留在独立 trace directory。"""

    if not isinstance(report, HybridWorkflowReport):
        raise HybridReportError("save expects a HybridWorkflowReport")
    if not isinstance(path, Path):
        raise HybridReportError("report path must be a Path")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.to_json() + "\n", encoding="utf-8")
    except OSError as error:
        raise HybridReportError(f"cannot save hybrid report: {error}") from error


def load_hybrid_workflow_report(path: Path) -> HybridWorkflowReport:
    """按顶层 schema 读取 report，未知版本直接失败。"""

    if not isinstance(path, Path):
        raise HybridReportError("report path must be a Path")
    try:
        return hybrid_report_from_json(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise HybridReportError(f"cannot read hybrid report: {error}") from error


__all__ = [
    "CausalStatus",
    "HybridReportError",
    "HybridWorkflowReport",
    "build_hybrid_workflow_report",
    "hybrid_report_from_dict",
    "hybrid_report_from_json",
    "load_hybrid_workflow_report",
    "save_hybrid_workflow_report",
]
