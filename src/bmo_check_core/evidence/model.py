from __future__ import annotations

import json
import math
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from ..identity import EvidenceId, MemoryEventId, StableId, ThreadInstanceId, TraceId


class EvidenceMaterialError(ValueError):
    """证据字段缺少稳定语义时抛出的输入错误。"""


class EvidenceCategory(StrEnum):
    # PROOF_FACT 可以进入静态 SAFE 的 proof closure。
    PROOF_FACT = "ProofFact"
    # OBSERVED_FACT 必须绑定具体 trace，不能被当成静态证明。
    OBSERVED_FACT = "ObservedFact"
    # DIAGNOSTIC_HINT 只帮助定位缺口，不能改变任何 verdict。
    DIAGNOSTIC_HINT = "DiagnosticHint"
    # UNKNOWN_FACT 记录尚未闭合的 proof obligation。
    UNKNOWN_FACT = "UnknownFact"


class UnknownKind(StrEnum):
    # INCOMPLETE_RECOVERY 表示二进制或控制流闭包没有完成。
    INCOMPLETE_RECOVERY = "IncompleteRecovery"
    # UNSUPPORTED_INPUT 表示输入超出当前分析器的支持范围。
    UNSUPPORTED_INPUT = "UnsupportedInput"
    # RESOURCE_LIMIT 表示预算耗尽，不能把部分结果当作完整结果。
    RESOURCE_LIMIT = "ResourceLimit"
    # MISSING_PROVENANCE 表示地址、线程或对象来源无法继续追踪。
    MISSING_PROVENANCE = "MissingProvenance"
    # MISSING_EXECUTABLE 表示主程序不存在，不能假设它没有访存。
    MISSING_EXECUTABLE = "MissingExecutable"
    # INVALID_ELF 表示输入不是可解析的目标 ELF。
    INVALID_ELF = "InvalidElf"
    # UNSUPPORTED_ARCHITECTURE 表示目标架构不在验证范围内。
    UNSUPPORTED_ARCHITECTURE = "UnsupportedArchitecture"
    # MISSING_INTERPRETER 表示 ELF 声明的解释器未能绑定到闭包。
    MISSING_INTERPRETER = "MissingInterpreter"
    # MISSING_LIBRARY 表示依赖闭包缺少一个运行时模块。
    MISSING_LIBRARY = "MissingLibrary"
    # AMBIGUOUS_LIBRARY 表示同名依赖无法唯一绑定到模块内容。
    AMBIGUOUS_LIBRARY = "AmbiguousLibrary"
    # ELF_BACKEND_FAILURE 表示 ELF 后端没有产生可审计结果。
    ELF_BACKEND_FAILURE = "ElfBackendFailure"
    # DISASSEMBLY_FAILURE 表示指令字节无法形成完整事实。
    DISASSEMBLY_FAILURE = "DisassemblyFailure"
    # INCOMPLETE_INSTRUCTION 表示指令事实缺少必要字段。
    INCOMPLETE_INSTRUCTION = "IncompleteInstructionFact"
    # UNRESOLVED_INDIRECT_CALL 表示间接调用目标集合没有闭合。
    UNRESOLVED_INDIRECT_CALL = "UnresolvedIndirectCall"
    # UNKNOWN_THREAD_ENTRY 表示线程角色入口无法唯一恢复。
    UNKNOWN_THREAD_ENTRY = "UnknownThreadEntry"
    # UNKNOWN_MEMORY_EFFECT 表示调用的普通访存 effect 没有闭合。
    UNKNOWN_MEMORY_EFFECT = "UnknownMemoryEffect"
    # UNKNOWN_SHARED_ADDRESS 表示共享地址分类仍可能与其他事件重叠。
    UNKNOWN_SHARED_ADDRESS = "UnknownSharedAddress"
    # UNKNOWN_ESCAPE 表示对象是否逃逸到其他线程无法证明。
    UNKNOWN_ESCAPE = "UnknownEscape"
    # UNKNOWN_SYNCHRONIZATION 表示同步边缺少可用的排序事实。
    UNKNOWN_SYNCHRONIZATION = "UnknownSynchronization"
    # UNSUPPORTED_DYNAMIC_CODE 表示 JIT 或自修改代码超出静态输入范围。
    UNSUPPORTED_DYNAMIC_CODE = "UnsupportedDynamicCode"
    # MISSING_DBT_REVISION 表示证书不能绑定实际 DBT lowering 版本。
    MISSING_DBT_REVISION = "MissingDbtRevision"
    # INVALID_DBT_CONTRACT 表示 DBT memory-order 契约格式或内容无效。
    INVALID_DBT_CONTRACT = "InvalidDbtContract"
    # INVALID_FUNCTION_EFFECT_CONTRACT 表示外部函数 effect 假设无法复核。
    INVALID_FUNCTION_EFFECT_CONTRACT = "InvalidFunctionEffectContract"
    # CFG_BACKEND_FAILURE 表示 CFG 后端没有产出可审计的控制流事实。
    CFG_BACKEND_FAILURE = "CfgBackendFailure"
    # INCOMPLETE_INDIRECT_TARGET 表示间接目标候选集尚未封闭。
    INCOMPLETE_INDIRECT_TARGET = "IncompleteIndirectTarget"
    # MISSING_SYMBOL_IMPLEMENTATION 表示符号存在但实现无法绑定到模块。
    MISSING_SYMBOL_IMPLEMENTATION = "MissingSymbolImplementation"
    # REACHING_DEFINITION_FAILURE 表示调用实参或角色来源无法唯一恢复。
    REACHING_DEFINITION_FAILURE = "ReachingDefinitionFailure"
    # UNKNOWN_JOIN_RELATION 表示 join handle 与 child role 的关系不明确。
    UNKNOWN_JOIN_RELATION = "UnknownJoinRelation"
    # MEMORY_EVENT_RECOVERY_FAILURE 表示访存 effect 提取失败，不能当作空集合。
    MEMORY_EVENT_RECOVERY_FAILURE = "MemoryEventRecoveryFailure"
    # UNKNOWN_AFFINE_BOUNDS 表示仿射地址缺少循环或线程边界。
    UNKNOWN_AFFINE_BOUNDS = "UnknownAffineBounds"
    # UNKNOWN_THREAD_ROLE 表示事件无法归属到唯一的静态线程角色。
    UNKNOWN_THREAD_ROLE = "UnknownThreadRole"
    # UNKNOWN_ROOT_CAUSE 表示当前还没有更细的缺口分类。
    UNKNOWN_ROOT_CAUSE = "UnknownRootCause"
    # UNSUPPORTED_PORTABILITY_INPUT 表示 checker 不支持当前事件或地址形态。
    UNSUPPORTED_PORTABILITY_INPUT = "UnsupportedPortabilityInput"
    # PORTABILITY_CHECK_INCOMPLETE 表示 memory-model obligation 没有闭合。
    PORTABILITY_CHECK_INCOMPLETE = "PortabilityCheckIncomplete"
    # PORTABILITY_CHECK_TIMEOUT 表示求解器超出明确的时间预算。
    PORTABILITY_CHECK_TIMEOUT = "PortabilityCheckTimeout"
    # PORTABILITY_CHECK_BOUND 表示有限枚举到达上限，不能外推无界结论。
    PORTABILITY_CHECK_BOUND = "PortabilityCheckBound"
    # STALE_CERTIFICATE 表示证书绑定的输入或契约已经发生变化。
    STALE_CERTIFICATE = "StaleCertificate"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise EvidenceMaterialError(f"{name} must be a non-empty string without NUL")
    return value


def _schema(value: str) -> str:
    return _text("evidence schema version", value)


def _subject_value(subject: StableId | None, scope: str) -> str:
    if subject is not None and not isinstance(subject, StableId):
        raise EvidenceMaterialError("evidence subject must be a StableId")
    return subject.value if subject is not None else f"scope:{scope}"


def _evidence_ids(name: str, values: tuple[EvidenceId, ...]) -> tuple[EvidenceId, ...]:
    normalized: list[EvidenceId] = []
    for value in values:
        if not isinstance(value, EvidenceId):
            raise EvidenceMaterialError(f"{name} must contain EvidenceId values")
        normalized.append(value)
    return tuple(sorted(set(normalized), key=lambda item: item.value))


def _memory_event_ids(
    name: str, values: tuple[MemoryEventId, ...]
) -> tuple[MemoryEventId, ...]:
    normalized: list[MemoryEventId] = []
    for value in values:
        if not isinstance(value, MemoryEventId):
            raise EvidenceMaterialError(f"{name} must contain MemoryEventId values")
        normalized.append(value)
    return tuple(sorted(set(normalized), key=lambda item: item.value))


def _attributes(
    values: tuple["EvidenceAttribute", ...],
) -> tuple["EvidenceAttribute", ...]:
    for value in values:
        if not isinstance(value, EvidenceAttribute):
            raise EvidenceMaterialError("evidence attributes must be typed")
    return tuple(sorted(values, key=lambda item: (item.name, item.value)))


def _canonical_content(content: object) -> str:
    try:
        return json.dumps(
            content,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise EvidenceMaterialError("evidence content is not canonical JSON") from error


def _make_id(
    category: EvidenceCategory,
    schema_version: str,
    producer: "ProducerId",
    subject: StableId | None,
    scope: str,
    premises: tuple[EvidenceId, ...],
    content: object,
) -> EvidenceId:
    return EvidenceId.from_parts(
        category=category.value,
        schema_version=schema_version,
        producer=producer.value,
        subject=_subject_value(subject, scope),
        premises=premises,
        content_discriminator=_canonical_content(content),
    )


@dataclass(frozen=True, slots=True)
class ProducerId:
    # name 标识生成证据的分析器或契约实现。
    name: str
    # version 绑定生成器版本，避免同名实现复用旧证据。
    version: str

    def __post_init__(self) -> None:
        _text("producer name", self.name)
        _text("producer version", self.version)

    @property
    def value(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass(frozen=True, slots=True)
class EvidenceAttribute:
    # name 是可查询的观察字段名，不承载业务分支。
    name: str
    # value 使用稳定文本保存一个已归一化的值，复杂结构应另建类型。
    value: str

    def __post_init__(self) -> None:
        _text("evidence attribute name", self.name)
        _text("evidence attribute value", self.value)


@dataclass(frozen=True, slots=True)
class ProofFact:
    # id 必须等于当前字段重算出的 EvidenceId，ledger 会再次检查。
    id: EvidenceId
    # schema_version 让证据解释规则可以显式演进。
    schema_version: str
    # producer 固定生成该事实的实现和版本。
    producer: ProducerId
    # subject 指向被证明的指令、对象、事件或其他稳定实体。
    subject: StableId | None
    # rule 是静态规则名称；它不能由动态观察临时改写。
    rule: str
    # scope 限定证明可以覆盖的二进制、线程或分析范围。
    scope: str
    # premises 只能引用其他 ProofFact，具体类别由 ledger 检查。
    premises: tuple[EvidenceId, ...] = ()
    # covered_events 保存一份证明覆盖的静态访存事件，避免旧适配器把
    # 一个 proof object 的多事件范围压缩成无法回查的单个 rule。
    covered_events: tuple[MemoryEventId, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, EvidenceId):
            raise EvidenceMaterialError("ProofFact id must be an EvidenceId")
        _schema(self.schema_version)
        if not isinstance(self.producer, ProducerId):
            raise EvidenceMaterialError("ProofFact producer must be a ProducerId")
        _subject_value(self.subject, self.scope)
        _text("proof rule", self.rule)
        _text("proof scope", self.scope)
        object.__setattr__(self, "premises", _evidence_ids("proof premises", self.premises))
        object.__setattr__(
            self,
            "covered_events",
            _memory_event_ids("proof covered_events", self.covered_events),
        )

    @classmethod
    def create(
        cls,
        *,
        schema_version: str,
        producer: ProducerId,
        subject: StableId | None,
        rule: str,
        scope: str,
        premises: tuple[EvidenceId, ...] = (),
        covered_events: tuple[MemoryEventId, ...] = (),
    ) -> "ProofFact":
        normalized = _evidence_ids("proof premises", premises)
        schema_version = _schema(schema_version)
        _text("proof scope", scope)
        if not isinstance(producer, ProducerId):
            raise EvidenceMaterialError("ProofFact producer must be a ProducerId")
        return cls(
            id=_make_id(
                EvidenceCategory.PROOF_FACT,
                schema_version,
                producer,
                subject,
                scope,
                normalized,
                {
                    "covered_events": [item.value for item in _memory_event_ids(
                        "proof covered_events", covered_events
                    )],
                    "rule": rule,
                    "scope": scope,
                },
            ),
            schema_version=schema_version,
            producer=producer,
            subject=subject,
            rule=rule,
            scope=scope,
            premises=normalized,
            covered_events=_memory_event_ids("proof covered_events", covered_events),
        )

    def expected_id(self) -> EvidenceId:
        return _make_id(
            EvidenceCategory.PROOF_FACT,
            self.schema_version,
            self.producer,
            self.subject,
            self.scope,
            self.premises,
            {
                "covered_events": [item.value for item in self.covered_events],
                "rule": self.rule,
                "scope": self.scope,
            },
        )


@dataclass(frozen=True, slots=True)
class ObservedFact:
    # id 绑定 trace、执行实例和观察内容，不能脱离运行记录复用。
    id: EvidenceId
    # schema_version 固定观察字段的解释方式。
    schema_version: str
    # producer 记录实际 trace normalizer 的版本。
    producer: ProducerId
    # trace_id 把观察限定在一条完整执行轨迹。
    trace_id: TraceId
    # execution_id 区分同一 trace 中不同线程实例。
    execution_id: ThreadInstanceId
    # subject 指向执行中实际对应的静态实体；无法对应时可为空。
    subject: StableId | None
    # observation_kind 区分地址、范围、目标和生命周期等观察类别。
    observation_kind: str
    # attributes 保存已归一化的观察值，不使用开放式字典协议。
    attributes: tuple[EvidenceAttribute, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, EvidenceId):
            raise EvidenceMaterialError("ObservedFact id must be an EvidenceId")
        _schema(self.schema_version)
        if not isinstance(self.producer, ProducerId):
            raise EvidenceMaterialError("ObservedFact producer must be a ProducerId")
        if not isinstance(self.trace_id, TraceId):
            raise EvidenceMaterialError("ObservedFact trace_id must be a TraceId")
        if not isinstance(self.execution_id, ThreadInstanceId):
            raise EvidenceMaterialError("ObservedFact execution_id must be a ThreadInstanceId")
        if self.subject is not None and not isinstance(self.subject, StableId):
            raise EvidenceMaterialError("ObservedFact subject must be a StableId")
        _text("observation kind", self.observation_kind)
        object.__setattr__(
            self,
            "attributes",
            _attributes(self.attributes),
        )

    @classmethod
    def create(
        cls,
        *,
        schema_version: str,
        producer: ProducerId,
        trace_id: TraceId,
        execution_id: ThreadInstanceId,
        subject: StableId | None,
        observation_kind: str,
        attributes: tuple[EvidenceAttribute, ...] = (),
    ) -> "ObservedFact":
        normalized = _attributes(attributes)
        schema_version = _schema(schema_version)
        if not isinstance(producer, ProducerId):
            raise EvidenceMaterialError("ObservedFact producer must be a ProducerId")
        if not isinstance(trace_id, TraceId):
            raise EvidenceMaterialError("ObservedFact trace_id must be a TraceId")
        if not isinstance(execution_id, ThreadInstanceId):
            raise EvidenceMaterialError("ObservedFact execution_id must be a ThreadInstanceId")
        return cls(
            id=_make_id(
                EvidenceCategory.OBSERVED_FACT,
                schema_version,
                producer,
                subject,
                trace_id.value,
                (),
                {
                    "attributes": [(item.name, item.value) for item in normalized],
                    "execution_id": execution_id.value,
                    "observation_kind": observation_kind,
                    "trace_id": trace_id.value,
                },
            ),
            schema_version=schema_version,
            producer=producer,
            trace_id=trace_id,
            execution_id=execution_id,
            subject=subject,
            observation_kind=observation_kind,
            attributes=normalized,
        )

    def expected_id(self) -> EvidenceId:
        return _make_id(
            EvidenceCategory.OBSERVED_FACT,
            self.schema_version,
            self.producer,
            self.subject,
            self.trace_id.value,
            (),
            {
                "attributes": [(item.name, item.value) for item in self.attributes],
                "execution_id": self.execution_id.value,
                "observation_kind": self.observation_kind,
                "trace_id": self.trace_id.value,
            },
        )


@dataclass(frozen=True, slots=True)
class DiagnosticHint:
    # id 绑定所有引用和分类，改动诊断内容会得到新的事实身份。
    id: EvidenceId
    # schema_version 固定诊断报告的解释方式。
    schema_version: str
    # producer 记录生成提示的 correlator/classifier 版本。
    producer: ProducerId
    # scope 限定提示对应的静态分析范围。
    scope: str
    # unknown_ids 是被定位的静态 Unknown 集合。
    unknown_ids: tuple[EvidenceId, ...]
    # observed_ids 是支持定位的动态观察集合。
    observed_ids: tuple[EvidenceId, ...]
    # root_cause 是可扩展的根因注册名，不是 verdict。
    root_cause: str
    # confidence 只表达诊断可信度，不能越权成为 proof。
    confidence: float
    # explanation 供人和 coding agent 阅读，不作为证明前提。
    explanation: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, EvidenceId):
            raise EvidenceMaterialError("DiagnosticHint id must be an EvidenceId")
        _schema(self.schema_version)
        if not isinstance(self.producer, ProducerId):
            raise EvidenceMaterialError("DiagnosticHint producer must be a ProducerId")
        _text("diagnostic scope", self.scope)
        object.__setattr__(self, "unknown_ids", _evidence_ids("diagnostic unknown_ids", self.unknown_ids))
        object.__setattr__(self, "observed_ids", _evidence_ids("diagnostic observed_ids", self.observed_ids))
        _text("diagnostic root cause", self.root_cause)
        if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
            raise EvidenceMaterialError("diagnostic confidence must be finite in [0, 1]")
        _text("diagnostic explanation", self.explanation)

    @classmethod
    def create(
        cls,
        *,
        schema_version: str,
        producer: ProducerId,
        scope: str,
        unknown_ids: tuple[EvidenceId, ...],
        observed_ids: tuple[EvidenceId, ...],
        root_cause: str,
        confidence: float,
        explanation: str,
    ) -> "DiagnosticHint":
        normalized_unknowns = _evidence_ids("diagnostic unknown_ids", unknown_ids)
        normalized_observations = _evidence_ids("diagnostic observed_ids", observed_ids)
        schema_version = _schema(schema_version)
        if not isinstance(producer, ProducerId):
            raise EvidenceMaterialError("DiagnosticHint producer must be a ProducerId")
        return cls(
            id=_make_id(
                EvidenceCategory.DIAGNOSTIC_HINT,
                schema_version,
                producer,
                None,
                scope,
                (*normalized_unknowns, *normalized_observations),
                {
                    "confidence": confidence,
                    "explanation": explanation,
                    "root_cause": root_cause,
                    "scope": scope,
                    "unknown_ids": [item.value for item in normalized_unknowns],
                    "observed_ids": [item.value for item in normalized_observations],
                },
            ),
            schema_version=schema_version,
            producer=producer,
            scope=scope,
            unknown_ids=normalized_unknowns,
            observed_ids=normalized_observations,
            root_cause=root_cause,
            confidence=confidence,
            explanation=explanation,
        )

    def expected_id(self) -> EvidenceId:
        return _make_id(
            EvidenceCategory.DIAGNOSTIC_HINT,
            self.schema_version,
            self.producer,
            None,
            self.scope,
            (*self.unknown_ids, *self.observed_ids),
            {
                "confidence": self.confidence,
                "explanation": self.explanation,
                "root_cause": self.root_cause,
                "scope": self.scope,
                "unknown_ids": [item.value for item in self.unknown_ids],
                "observed_ids": [item.value for item in self.observed_ids],
            },
        )


@dataclass(frozen=True, slots=True)
class UnknownFact:
    # id 绑定 Unknown 的完整原因和来源，避免用“缺少记录”表达 Unknown。
    id: EvidenceId
    # schema_version 固定 Unknown kind 和 provenance 的解释方式。
    schema_version: str
    # producer 记录哪个分析 pass 产生了该缺口。
    producer: ProducerId
    # kind 使用统一注册表，不能靠任意字符串拼写出新状态。
    kind: UnknownKind
    # reason 说明当前具体缺少什么事实。
    reason: str
    # subject 指向受影响的指令、对象、事件或范围。
    subject: StableId | None
    # scope 说明该 Unknown 阻塞哪一个分析范围。
    scope: str
    # provenance 只能引用静态 ProofFact/UnknownFact，不能引用动态事实。
    provenance: tuple[EvidenceId, ...] = ()
    # supporting_context 保留定位信息，但不充当 proof premise。
    supporting_context: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, EvidenceId):
            raise EvidenceMaterialError("UnknownFact id must be an EvidenceId")
        _schema(self.schema_version)
        if not isinstance(self.producer, ProducerId):
            raise EvidenceMaterialError("UnknownFact producer must be a ProducerId")
        if not isinstance(self.kind, UnknownKind):
            raise EvidenceMaterialError("UnknownFact kind must be an UnknownKind")
        _text("unknown reason", self.reason)
        _subject_value(self.subject, self.scope)
        _text("unknown scope", self.scope)
        object.__setattr__(self, "provenance", _evidence_ids("unknown provenance", self.provenance))
        normalized_context = tuple(_text("unknown context", item) for item in self.supporting_context)
        object.__setattr__(self, "supporting_context", normalized_context)

    @classmethod
    def create(
        cls,
        *,
        schema_version: str,
        producer: ProducerId,
        kind: UnknownKind,
        reason: str,
        subject: StableId | None,
        scope: str,
        provenance: tuple[EvidenceId, ...] = (),
        supporting_context: tuple[str, ...] = (),
    ) -> "UnknownFact":
        normalized_provenance = _evidence_ids("unknown provenance", provenance)
        schema_version = _schema(schema_version)
        if not isinstance(producer, ProducerId):
            raise EvidenceMaterialError("UnknownFact producer must be a ProducerId")
        if not isinstance(kind, UnknownKind):
            raise EvidenceMaterialError("UnknownFact kind must be an UnknownKind")
        context = tuple(_text("unknown context", item) for item in supporting_context)
        return cls(
            id=_make_id(
                EvidenceCategory.UNKNOWN_FACT,
                schema_version,
                producer,
                subject,
                scope,
                normalized_provenance,
                {
                    "context": list(context),
                    "kind": kind.value,
                    "reason": reason,
                    "scope": scope,
                },
            ),
            schema_version=schema_version,
            producer=producer,
            kind=kind,
            reason=reason,
            subject=subject,
            scope=scope,
            provenance=normalized_provenance,
            supporting_context=context,
        )

    def expected_id(self) -> EvidenceId:
        return _make_id(
            EvidenceCategory.UNKNOWN_FACT,
            self.schema_version,
            self.producer,
            self.subject,
            self.scope,
            self.provenance,
            {
                "context": list(self.supporting_context),
                "kind": self.kind.value,
                "reason": self.reason,
                "scope": self.scope,
            },
        )


EvidenceNode: TypeAlias = ProofFact | ObservedFact | DiagnosticHint | UnknownFact


@dataclass(frozen=True, slots=True)
class UnknownDischarge:
    # unknown_id 指向要关闭的 Unknown；它仍保留在 ledger 中供审计。
    unknown_id: EvidenceId
    # proof_id 指向真正能够关闭该 Unknown 的静态 ProofFact。
    proof_id: EvidenceId
    # scope 必须同时匹配 Unknown 和 ProofFact 的声明范围。
    scope: str

    def __post_init__(self) -> None:
        if not isinstance(self.unknown_id, EvidenceId):
            raise EvidenceMaterialError("discharge unknown_id must be an EvidenceId")
        if not isinstance(self.proof_id, EvidenceId):
            raise EvidenceMaterialError("discharge proof_id must be an EvidenceId")
        _text("discharge scope", self.scope)
