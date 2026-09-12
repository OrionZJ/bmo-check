"""静态 Unknown 的保守根因分类。

分类器只读取静态 ``UnknownFact`` 和相关状态。它输出诊断用的 enum，不会
创建 ``ProofFact``、关闭 Unknown，或把一次动态观察提升为静态事实。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from bmo_check_core import EvidenceId, UnknownFact, UnknownKind

from .correlation import CorrelationRecord, CorrelationStatus


class ClassificationError(ValueError):
    """分类输入或 registry 不完整时抛出的错误。"""


class DiagnosticRootCause(StrEnum):
    """可演进的诊断代码；它们不是 proof rule，也不是 verdict。"""

    MISSING_INDUCTION_VARIABLE = "MissingInductionVariable"
    MISSING_LOOP_BOUND = "MissingLoopBound"
    MISSING_PHI_RECURRENCE = "MissingPhiRecurrence"
    MISSING_ARGUMENT_PROVENANCE = "MissingArgumentProvenance"
    MISSING_FIELD_PROVENANCE = "MissingFieldProvenance"
    MISSING_GLOBAL_SUMMARY = "MissingGlobalSummary"
    MISSING_THREAD_ID_PROVENANCE = "MissingThreadIdProvenance"
    MISSING_LIFECYCLE_BOUND = "MissingLifecycleBound"
    MISSING_ALIAS_PRECISION = "MissingAliasPrecision"
    OPAQUE_CALL_BOUNDARY = "OpaqueCallBoundary"
    UNRESOLVED_INDIRECT = "UnresolvedIndirect"
    UNSUPPORTED_ADDRESS_NORMALIZATION = "UnsupportedAddressNormalization"
    NOT_EXECUTED_IN_OBSERVED_TRACE = "NotExecutedInObservedTrace"
    DYNAMIC_PATTERN_NOT_STABLE = "DynamicPatternNotStable"
    UNKNOWN_ROOT_CAUSE = "UnknownRootCause"


@dataclass(frozen=True, slots=True)
class RootCauseDescriptor:
    """registry 中一个代码的稳定说明。"""

    # code 是序列化到 DiagnosticHint 的稳定分类名。
    code: DiagnosticRootCause
    # description 只供报告和 CLI 阅读，不参与分析分支。
    description: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, DiagnosticRootCause):
            raise ClassificationError("root-cause descriptor code is invalid")
        if not isinstance(self.description, str) or not self.description:
            raise ClassificationError("root-cause descriptor description is empty")


_DESCRIPTIONS: dict[DiagnosticRootCause, str] = {
    DiagnosticRootCause.MISSING_INDUCTION_VARIABLE: "循环归纳变量的来源没有闭合",
    DiagnosticRootCause.MISSING_LOOP_BOUND: "循环上界或迭代范围没有闭合",
    DiagnosticRootCause.MISSING_PHI_RECURRENCE: "控制流合流点的递归关系没有闭合",
    DiagnosticRootCause.MISSING_ARGUMENT_PROVENANCE: "调用参数的地址来源没有闭合",
    DiagnosticRootCause.MISSING_FIELD_PROVENANCE: "对象字段或偏移的来源没有闭合",
    DiagnosticRootCause.MISSING_GLOBAL_SUMMARY: "全局对象或函数摘要没有闭合",
    DiagnosticRootCause.MISSING_THREAD_ID_PROVENANCE: "事件所属线程角色没有闭合",
    DiagnosticRootCause.MISSING_LIFECYCLE_BOUND: "线程生命周期边界没有闭合",
    DiagnosticRootCause.MISSING_ALIAS_PRECISION: "别名或共享对象分类的精度不足",
    DiagnosticRootCause.OPAQUE_CALL_BOUNDARY: "不透明调用的普通访存 effect 没有闭合",
    DiagnosticRootCause.UNRESOLVED_INDIRECT: "间接控制流目标集合没有闭合",
    DiagnosticRootCause.UNSUPPORTED_ADDRESS_NORMALIZATION: "地址形式无法归一化",
    DiagnosticRootCause.NOT_EXECUTED_IN_OBSERVED_TRACE: "该静态 site 未出现在当前轨迹",
    DiagnosticRootCause.DYNAMIC_PATTERN_NOT_STABLE: "动态观察模式不足以形成稳定线索",
    DiagnosticRootCause.UNKNOWN_ROOT_CAUSE: "当前证据不足以分类根因",
}
ROOT_CAUSE_REGISTRY: Mapping[DiagnosticRootCause, RootCauseDescriptor] = MappingProxyType(
    {
        code: RootCauseDescriptor(code, description)
        for code, description in _DESCRIPTIONS.items()
    }
)


def validate_root_cause_registry() -> None:
    """启动/测试时检查每个 enum 都有可序列化描述。"""

    missing = set(DiagnosticRootCause) - set(ROOT_CAUSE_REGISTRY)
    extra = set(ROOT_CAUSE_REGISTRY) - set(DiagnosticRootCause)
    if missing or extra:
        raise ClassificationError(
            f"root-cause registry mismatch: missing={sorted(missing)}, extra={sorted(extra)}"
        )
    for code, descriptor in ROOT_CAUSE_REGISTRY.items():
        if descriptor.code != code:
            raise ClassificationError("root-cause registry descriptor key mismatch")


validate_root_cause_registry()


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """一次分类结果；confidence 只能表达诊断线索强弱。"""

    # unknown_id 让结果可以回到静态证据图，而不是依赖列表顺序。
    unknown_id: EvidenceId
    # root_cause 是 registry 中的 enum，不能由自由字符串拼出新状态。
    root_cause: DiagnosticRootCause
    # confidence 不允许被当作 proof 强度或 verdict。
    confidence: float
    # rationale 说明选择该代码的静态依据。
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.unknown_id, EvidenceId):
            raise ClassificationError("classification unknown_id must be an EvidenceId")
        if not isinstance(self.root_cause, DiagnosticRootCause):
            raise ClassificationError("classification root_cause is invalid")
        if not isinstance(self.confidence, (float, int)) or isinstance(self.confidence, bool):
            raise ClassificationError("classification confidence must be numeric")
        if not 0 <= float(self.confidence) <= 1:
            raise ClassificationError("classification confidence must be in [0, 1]")
        if not isinstance(self.rationale, str) or not self.rationale:
            raise ClassificationError("classification rationale is empty")
        object.__setattr__(self, "confidence", float(self.confidence))


def _text(value: UnknownFact) -> str:
    return " ".join((value.reason, *value.supporting_context)).casefold()


def _contextual_affine(value: UnknownFact, text: str) -> DiagnosticRootCause:
    if "phi" in text or "recurrence" in text or "合流" in text:
        return DiagnosticRootCause.MISSING_PHI_RECURRENCE
    if "induction" in text or "归纳" in text or "indvar" in text:
        return DiagnosticRootCause.MISSING_INDUCTION_VARIABLE
    if any(token in text for token in ("bound", "upper", "limit", "range", "上界", "范围")):
        return DiagnosticRootCause.MISSING_LOOP_BOUND
    return DiagnosticRootCause.UNKNOWN_ROOT_CAUSE


def _classify_static(value: UnknownFact) -> tuple[DiagnosticRootCause, float, str]:
    text = _text(value)
    if value.kind == UnknownKind.UNKNOWN_AFFINE_BOUNDS:
        code = _contextual_affine(value, text)
        confidence = 0.8 if code != DiagnosticRootCause.UNKNOWN_ROOT_CAUSE else 0.2
        return code, confidence, "UnknownAffineBounds 的上下文提供了仿射缺口线索"
    if value.kind in {
        UnknownKind.UNRESOLVED_INDIRECT_CALL,
        UnknownKind.INCOMPLETE_INDIRECT_TARGET,
    }:
        return (
            DiagnosticRootCause.UNRESOLVED_INDIRECT,
            0.95,
            "Unknown kind 直接表示间接目标集合未闭合",
        )
    if value.kind in {
        UnknownKind.UNKNOWN_MEMORY_EFFECT,
        UnknownKind.INVALID_FUNCTION_EFFECT_CONTRACT,
        UnknownKind.MISSING_SYMBOL_IMPLEMENTATION,
    }:
        return (
            DiagnosticRootCause.OPAQUE_CALL_BOUNDARY,
            0.85,
            "Unknown kind 指向调用 effect 或实现边界",
        )
    if value.kind in {UnknownKind.UNKNOWN_ESCAPE, UnknownKind.UNKNOWN_SHARED_ADDRESS}:
        return (
            DiagnosticRootCause.MISSING_ALIAS_PRECISION,
            0.85,
            "Unknown kind 指向逃逸或共享地址分类",
        )
    if value.kind in {
        UnknownKind.UNKNOWN_THREAD_ENTRY,
        UnknownKind.UNKNOWN_THREAD_ROLE,
        UnknownKind.REACHING_DEFINITION_FAILURE,
    }:
        return (
            DiagnosticRootCause.MISSING_THREAD_ID_PROVENANCE,
            0.75,
            "Unknown kind 指向线程角色或来源传播",
        )
    if value.kind in {
        UnknownKind.UNKNOWN_JOIN_RELATION,
        UnknownKind.UNKNOWN_SYNCHRONIZATION,
    }:
        return (
            DiagnosticRootCause.MISSING_LIFECYCLE_BOUND,
            0.75,
            "Unknown kind 指向线程生命周期或同步边界",
        )
    if value.kind == UnknownKind.MISSING_PROVENANCE:
        if any(token in text for token in ("field", "offset", "字段")):
            return (
                DiagnosticRootCause.MISSING_FIELD_PROVENANCE,
                0.7,
                "上下文指向字段地址来源",
            )
        return (
            DiagnosticRootCause.MISSING_ARGUMENT_PROVENANCE,
            0.6,
            "Unknown kind 指向地址来源传播",
        )
    if value.kind in {
        UnknownKind.INVALID_ELF,
        UnknownKind.DISASSEMBLY_FAILURE,
        UnknownKind.MEMORY_EVENT_RECOVERY_FAILURE,
        UnknownKind.UNSUPPORTED_PORTABILITY_INPUT,
    }:
        return (
            DiagnosticRootCause.UNSUPPORTED_ADDRESS_NORMALIZATION,
            0.7,
            "输入或访存形式无法归一化",
        )
    if value.kind == UnknownKind.MISSING_LIBRARY:
        return (
            DiagnosticRootCause.MISSING_GLOBAL_SUMMARY,
            0.7,
            "全局模块或函数摘要未绑定",
        )
    if any(token in text for token in ("argument", "parameter", "实参", "参数")):
        return (
            DiagnosticRootCause.MISSING_ARGUMENT_PROVENANCE,
            0.55,
            "文本上下文指向参数来源",
        )
    if any(token in text for token in ("field", "offset", "字段")):
        return (
            DiagnosticRootCause.MISSING_FIELD_PROVENANCE,
            0.55,
            "文本上下文指向字段来源",
        )
    if any(token in text for token in ("summary", "global", "全局", "摘要")):
        return (
            DiagnosticRootCause.MISSING_GLOBAL_SUMMARY,
            0.55,
            "文本上下文指向全局或函数摘要",
        )
    return (
        DiagnosticRootCause.UNKNOWN_ROOT_CAUSE,
        0.0,
        "Unknown kind 和上下文没有足够的注册表线索",
    )


def classify_unknown(
    unknown: UnknownFact,
    *,
    correlation: CorrelationRecord | None = None,
) -> ClassificationResult:
    """分类一个 Unknown；动态相关状态只会降低/解释线索，不会造 proof。"""

    if not isinstance(unknown, UnknownFact):
        raise ClassificationError("classify_unknown expects an UnknownFact")
    if correlation is not None:
        if correlation.unknown_id != unknown.id:
            raise ClassificationError("correlation does not reference the Unknown")
        if correlation.status == CorrelationStatus.UNMATCHED and not correlation.observed_ids:
            # 未命中只能说明当前 trace 没有给出观察，不能说明静态对象不存在。
            return ClassificationResult(
                unknown_id=unknown.id,
                root_cause=DiagnosticRootCause.NOT_EXECUTED_IN_OBSERVED_TRACE,
                confidence=0.0,
                rationale="当前轨迹没有可接受的同 site 观察；这不是 NoAlias 或静态证明",
            )
        if correlation.status == CorrelationStatus.AMBIGUOUS:
            return ClassificationResult(
                unknown_id=unknown.id,
                root_cause=DiagnosticRootCause.DYNAMIC_PATTERN_NOT_STABLE,
                confidence=0.25,
                rationale="有动态候选但稳定身份材料不足，不能任选一个",
            )
    root_cause, confidence, rationale = _classify_static(unknown)
    return ClassificationResult(unknown.id, root_cause, confidence, rationale)


def classify_unknowns(
    unknowns: tuple[UnknownFact, ...],
    correlations: tuple[CorrelationRecord, ...] = (),
) -> tuple[ClassificationResult, ...]:
    """按稳定 EvidenceId 顺序分类一组 Unknown。"""

    by_id = {item.unknown_id: item for item in correlations}
    results = tuple(
        classify_unknown(item, correlation=by_id.get(item.id)) for item in unknowns
    )
    return tuple(sorted(results, key=lambda item: item.unknown_id.value))


__all__ = [
    "ClassificationError",
    "ClassificationResult",
    "DiagnosticRootCause",
    "ROOT_CAUSE_REGISTRY",
    "RootCauseDescriptor",
    "classify_unknown",
    "classify_unknowns",
    "validate_root_cause_registry",
]
