"""动态观察得到的仿射模式与 E2 覆盖汇总。

这里的类型只描述某条 trace 中看到的地址样本。它们不会实现静态格、不会
创建 ``ProofFact``，也没有入口可以关闭 ``UnknownFact``。
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from bmo_check_core import (
    CertificateVerdict,
    DynamicDiagnosticSnapshot,
    EvidenceId,
    ObservedFact,
    StableId,
    StaticDiagnosticSnapshot,
    ThreadInstanceId,
    TraceId,
    UnknownFact,
    UnknownKind,
)

from .correlation import (
    CorrelationKey,
    CorrelationRecord,
    CorrelationStatus,
    DiagnosticCorrelationReport,
    correlate_unknowns,
)


class AffineObservationError(ValueError):
    """观察模式或 E2 报告不满足 typed contract。"""


class ObservedAffineStatus(StrEnum):
    """只说明观察质量，不表示任何静态证明结果。"""

    # 没有找到可回查的动态访存样本。
    NOT_OBSERVED = "NotObserved"
    # 样本太少，不能判断重复访问的差分模式。
    INSUFFICIENT = "Insufficient"
    # 当前有界样本的差分候选保持不变，但仍不是静态证明。
    STABLE = "Stable"
    # 同一站点观察到了多个差分候选，不能归纳成单一模式。
    VARIABLE = "Variable"
    # trace 或有界采样被截断，完整地址集合不可见。
    INCOMPLETE = "Incomplete"
    # 一个静态缺口对应多个动态候选，身份材料不足以任选其一。
    AMBIGUOUS = "Ambiguous"


class ObservedOverlap(StrEnum):
    """线程样本之间实际看到的重叠情况。"""

    # 完整样本中没有观察到不同线程的相同起始地址。
    NONE_OBSERVED = "NoneObserved"
    # 完整样本中观察到不同线程使用了相同起始地址。
    OVERLAP_OBSERVED = "OverlapObserved"
    # 线程少于两个或至少一个地址集合被截断，不能判断重叠。
    UNKNOWN = "Unknown"


_PATTERN_SCHEMA: Final[str] = "observed-affine-pattern-v1"
_REPORT_SCHEMA: Final[str] = "affine-validation-report-v1"
_NO_PROOF_CHANGE: Final[str] = (
    "Observed affine patterns describe trace coverage only; the static verdict and proof remain unchanged."
)


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise AffineObservationError(f"{name} must be a non-empty string without NUL")
    return value


def _count(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AffineObservationError(f"{name} must be a non-negative integer")
    return value


def _address(name: str, value: int) -> int:
    return _count(name, value)


def _ids(name: str, values: Iterable[EvidenceId]) -> tuple[EvidenceId, ...]:
    result = tuple(values)
    if any(not isinstance(value, EvidenceId) for value in result):
        raise AffineObservationError(f"{name} must contain EvidenceId values")
    return tuple(sorted(set(result), key=lambda item: item.value))


def _stable_ids(name: str, values: Iterable[StableId]) -> tuple[StableId, ...]:
    result = tuple(values)
    if any(not isinstance(value, StableId) for value in result):
        raise AffineObservationError(f"{name} must contain StableId values")
    return tuple(sorted(set(result), key=lambda item: item.value))


def _trace_ids(values: Iterable[TraceId]) -> tuple[TraceId, ...]:
    result = tuple(values)
    if any(not isinstance(value, TraceId) for value in result):
        raise AffineObservationError("trace_ids must contain TraceId values")
    return tuple(sorted(set(result), key=lambda item: item.value))


def _strings(name: str, values: Iterable[str]) -> tuple[str, ...]:
    result = tuple(_text(name, value) for value in values)
    return tuple(sorted(set(result)))


def _ints(name: str, values: Iterable[int]) -> tuple[int, ...]:
    result = tuple(value for value in values)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in result):
        raise AffineObservationError(f"{name} must contain integers")
    return tuple(sorted(set(result)))


@dataclass(frozen=True, slots=True)
class ObservedAffineThread:
    """一个 trace 线程实例的有界地址摘要。"""

    # execution_id 绑定动态线程实例，不能被解释成静态 ThreadRole。
    execution_id: ThreadInstanceId
    # sample_count 是该线程在匹配站点执行的动态次数。
    sample_count: int
    # distinct_address_count 可能是达到采样上限后的下界。
    distinct_address_count: int
    # address_min/address_max_end 描述观察到的范围，不是静态边界。
    address_min: int | None = None
    address_max_end: int | None = None
    # sample_addresses 只保留首次遇到的有界样本，顺序用于推测步长。
    sample_addresses: tuple[int, ...] = ()
    # sample_complete=False 表示地址集合被采样上限截断。
    sample_complete: bool = True
    # stride_candidates 是相邻动态样本的差分候选，不是循环步长证明。
    stride_candidates: tuple[int, ...] = ()
    # stride_complete=False 表示候选集合达到上限。
    stride_complete: bool = True
    # role_candidates 只记录 tracer 提供的标签；缺失时保持空元组。
    role_candidates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.execution_id, ThreadInstanceId):
            raise AffineObservationError("execution_id must be a ThreadInstanceId")
        _count("sample_count", self.sample_count)
        _count("distinct_address_count", self.distinct_address_count)
        if self.address_min is not None:
            _address("address_min", self.address_min)
        if self.address_max_end is not None:
            _address("address_max_end", self.address_max_end)
        if (
            self.address_min is not None
            and self.address_max_end is not None
            and self.address_max_end < self.address_min
        ):
            raise AffineObservationError("address_max_end precedes address_min")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in self.sample_addresses
        ):
            raise AffineObservationError("sample_addresses must be non-negative integers")
        if len(set(self.sample_addresses)) != len(self.sample_addresses):
            raise AffineObservationError("sample_addresses must be unique")
        if self.distinct_address_count < len(self.sample_addresses):
            raise AffineObservationError("distinct_address_count is smaller than samples")
        if not isinstance(self.sample_complete, bool):
            raise AffineObservationError("sample_complete must be boolean")
        object.__setattr__(self, "stride_candidates", _ints("stride_candidates", self.stride_candidates))
        if not isinstance(self.stride_complete, bool):
            raise AffineObservationError("stride_complete must be boolean")
        object.__setattr__(self, "role_candidates", _strings("role_candidates", self.role_candidates))


@dataclass(frozen=True, slots=True)
class ObservedAffinePattern:
    """绑定一个静态 Unknown 的 trace-bound 仿射观察。"""

    # schema_version 固定字段解释，避免旧摘要被当作新证据。
    schema_version: str
    # unknown_id 是静态缺口的稳定身份，而不是数组下标。
    unknown_id: EvidenceId
    # correlation_status/key 保留定位是否唯一，不把观察强行绑定到静态 site。
    correlation_status: CorrelationStatus
    correlation_key: CorrelationKey
    # observed_ids/trace_ids 让报告可回到原始动态事实和执行。
    observed_ids: tuple[EvidenceId, ...]
    trace_ids: tuple[TraceId, ...]
    # normalized subjects 只用于回查，不承诺地址表达式已经静态归一化。
    instruction_subjects: tuple[StableId, ...] = ()
    operand_subjects: tuple[StableId, ...] = ()
    # sample_count、base/stride 候选全部是本次运行的观察值。
    sample_count: int = 0
    base_candidates: tuple[int, ...] = ()
    stride_candidates: tuple[int, ...] = ()
    thread_observations: tuple[ObservedAffineThread, ...] = ()
    overlap: ObservedOverlap = ObservedOverlap.UNKNOWN
    repetition_stable: bool | None = None
    complete: bool = False
    status: ObservedAffineStatus = ObservedAffineStatus.NOT_OBSERVED
    # limitations 把截断、缺角色和闭包问题显式留在报告中。
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text("pattern schema_version", self.schema_version)
        if not isinstance(self.unknown_id, EvidenceId):
            raise AffineObservationError("unknown_id must be an EvidenceId")
        if not isinstance(self.correlation_status, CorrelationStatus):
            raise AffineObservationError("invalid correlation_status")
        if not isinstance(self.correlation_key, CorrelationKey):
            raise AffineObservationError("invalid correlation_key")
        object.__setattr__(self, "observed_ids", _ids("observed_ids", self.observed_ids))
        object.__setattr__(self, "trace_ids", _trace_ids(self.trace_ids))
        object.__setattr__(
            self,
            "instruction_subjects",
            _stable_ids("instruction_subjects", self.instruction_subjects),
        )
        object.__setattr__(self, "operand_subjects", _stable_ids("operand_subjects", self.operand_subjects))
        _count("sample_count", self.sample_count)
        object.__setattr__(self, "base_candidates", _ints("base_candidates", self.base_candidates))
        object.__setattr__(self, "stride_candidates", _ints("stride_candidates", self.stride_candidates))
        if any(not isinstance(item, ObservedAffineThread) for item in self.thread_observations):
            raise AffineObservationError("thread_observations has an invalid item")
        if not isinstance(self.overlap, ObservedOverlap):
            raise AffineObservationError("invalid overlap status")
        if self.repetition_stable is not None and not isinstance(self.repetition_stable, bool):
            raise AffineObservationError("repetition_stable must be boolean or None")
        if not isinstance(self.complete, bool):
            raise AffineObservationError("complete must be boolean")
        if not isinstance(self.status, ObservedAffineStatus):
            raise AffineObservationError("invalid observed affine status")
        object.__setattr__(self, "limitations", _strings("limitations", self.limitations))


@dataclass(frozen=True, slots=True)
class AffineValidationReport:
    """E2 汇总；它同时保留静态 verdict 与动态覆盖的边界。"""

    # schema_version 让报告读取器拒绝未声明的字段变化。
    schema_version: str
    # static_verdict 原样复制，诊断没有升级入口。
    static_verdict: CertificateVerdict
    # static_unknown_count/affine_unknown_count 是静态输入的事实计数。
    static_unknown_count: int
    affine_unknown_count: int
    # trace_ids/trace_complete 绑定参与本次汇总的执行。
    trace_ids: tuple[TraceId, ...]
    trace_complete: bool
    # patterns 是每个 UnknownAffineBounds 的完整观察结果。
    patterns: tuple[ObservedAffinePattern, ...]
    # exercised/ambiguous/unmatched 覆盖静态 affine Unknown；not_executed 是
    # unmatched 中明确没有动态候选的子集，闭包不匹配不会冒充“未执行”。
    exercised_count: int
    ambiguous_count: int
    not_executed_count: int
    unmatched_count: int
    # 这是强制的越权声明；任何 False 都使构造失败。
    static_proof_unchanged: bool = True
    statement: str = _NO_PROOF_CHANGE

    def __post_init__(self) -> None:
        _text("report schema_version", self.schema_version)
        if not isinstance(self.static_verdict, CertificateVerdict):
            raise AffineObservationError("static_verdict must be a CertificateVerdict")
        _count("static_unknown_count", self.static_unknown_count)
        _count("affine_unknown_count", self.affine_unknown_count)
        object.__setattr__(self, "trace_ids", _trace_ids(self.trace_ids))
        if not isinstance(self.trace_complete, bool):
            raise AffineObservationError("trace_complete must be boolean")
        if any(not isinstance(item, ObservedAffinePattern) for item in self.patterns):
            raise AffineObservationError("patterns has an invalid item")
        object.__setattr__(
            self,
            "patterns",
            tuple(sorted(self.patterns, key=lambda item: item.unknown_id.value)),
        )
        for name, value in (
            ("exercised_count", self.exercised_count),
            ("ambiguous_count", self.ambiguous_count),
            ("not_executed_count", self.not_executed_count),
            ("unmatched_count", self.unmatched_count),
        ):
            _count(name, value)
        if self.exercised_count + self.ambiguous_count + self.unmatched_count != self.affine_unknown_count:
            raise AffineObservationError("affine coverage counts do not cover patterns")
        if self.not_executed_count > self.unmatched_count:
            raise AffineObservationError("not_executed_count exceeds unmatched_count")
        if not isinstance(self.static_proof_unchanged, bool) or not self.static_proof_unchanged:
            raise AffineObservationError("static proof must be declared unchanged")
        if self.statement != _NO_PROOF_CHANGE:
            raise AffineObservationError("invalid static proof boundary statement")


def _attributes(fact: ObservedFact) -> dict[str, str]:
    return {item.name: item.value for item in fact.attributes}


def _integer(value: str | None, *, allow_negative: bool = False) -> int | None:
    if value is None or value in {"", "none", "None"}:
        return None
    try:
        result = int(value, 0)
    except ValueError:
        try:
            result = int(value, 10)
        except ValueError:
            return None
    if not allow_negative and result < 0:
        return None
    return result


def _integer_list(value: str | None, *, allow_negative: bool = False) -> tuple[int, ...]:
    if value is None or value in {"", "none", "None"}:
        return ()
    values: list[int] = []
    for part in value.split(","):
        parsed = _integer(part.strip(), allow_negative=allow_negative)
        if parsed is not None:
            values.append(parsed)
    return _ints("parsed integer list", values)


def _address_list(value: str | None) -> tuple[int, ...]:
    """保留 adapter 的首次观察顺序，避免把访问序列伪造成升序循环。"""

    if value is None or value in {"", "none", "None"}:
        return ()
    result: list[int] = []
    seen: set[int] = set()
    for part in value.split(","):
        parsed = _integer(part.strip())
        if parsed is not None and parsed not in seen:
            seen.add(parsed)
            result.append(parsed)
    return tuple(result)


def _boolean(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    if value.casefold() in {"true", "1", "yes"}:
        return True
    if value.casefold() in {"false", "0", "no"}:
        return False
    return default


def _thread_observation(facts: tuple[ObservedFact, ...], execution_id: ThreadInstanceId) -> ObservedAffineThread:
    sample_count = 0
    reported_distinct: list[int] = []
    minimum: int | None = None
    maximum: int | None = None
    samples: list[int] = []
    sample_seen: set[int] = set()
    sample_complete = True
    strides: set[int] = set()
    stride_complete = True
    roles: set[str] = set()
    for fact in facts:
        values = _attributes(fact)
        sample_count += _integer(values.get("sample_count")) or 0
        observed_distinct = _integer(values.get("address_distinct_count"))
        if observed_distinct is not None:
            reported_distinct.append(observed_distinct)
        minimum_value = _integer(values.get("address_min"))
        maximum_value = _integer(values.get("address_max_end"))
        if minimum_value is not None:
            minimum = minimum_value if minimum is None else min(minimum, minimum_value)
        if maximum_value is not None:
            maximum = maximum_value if maximum is None else max(maximum, maximum_value)
        for address in _address_list(values.get("address_samples")):
            if address not in sample_seen:
                sample_seen.add(address)
                samples.append(address)
        sample_complete = sample_complete and (
            "address_sample_complete" in values
            and _boolean(values.get("address_sample_complete"), False)
        )
        for stride in _integer_list(values.get("stride_candidates"), allow_negative=True):
            strides.add(stride)
        stride_complete = stride_complete and (
            "stride_candidates_complete" in values
            and _boolean(values.get("stride_candidates_complete"), False)
        )
        role = values.get("thread_role")
        if role:
            roles.add(role)
    # Complete samples can be unioned exactly.  Once one source was capped, the
    # per-fact count is only a lower bound; taking the maximum avoids claiming
    # distinctness merely because the same address appeared in two trace chunks.
    if sample_complete and sample_seen:
        distinct = len(sample_seen)
    else:
        distinct = max((*reported_distinct, len(sample_seen)), default=0)
    return ObservedAffineThread(
        execution_id=execution_id,
        sample_count=sample_count,
        distinct_address_count=distinct,
        address_min=minimum,
        address_max_end=maximum,
        sample_addresses=tuple(samples),
        sample_complete=sample_complete,
        stride_candidates=tuple(strides),
        stride_complete=stride_complete,
        role_candidates=tuple(roles),
    )


def _repetition_stability(facts: tuple[ObservedFact, ...]) -> bool | None:
    signatures: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
    for fact in facts:
        values = _attributes(fact)
        strides = _integer_list(values.get("stride_candidates"), allow_negative=True)
        samples = _address_list(values.get("address_samples"))
        deltas = tuple(right - left for left, right in zip(samples, samples[1:]))
        if strides or deltas:
            signatures.append((strides, deltas))
    if not signatures:
        return None
    return len(set(signatures)) == 1


def _overlap(threads: tuple[ObservedAffineThread, ...]) -> ObservedOverlap:
    if len(threads) < 2 or any(not item.sample_complete for item in threads):
        return ObservedOverlap.UNKNOWN
    address_sets = [set(item.sample_addresses) for item in threads]
    if any(left & right for index, left in enumerate(address_sets) for right in address_sets[index + 1 :]):
        return ObservedOverlap.OVERLAP_OBSERVED
    return ObservedOverlap.NONE_OBSERVED


def _memory_observations(
    observed: Mapping[EvidenceId, ObservedFact],
    ids: Iterable[EvidenceId],
) -> tuple[ObservedFact, ...]:
    result = tuple(
        observed[item]
        for item in ids
        if item in observed
        and observed[item].observation_kind
        not in {"explicit-fence", "atomic-boundary", "indirect-target", "signal"}
    )
    return tuple(sorted(result, key=lambda item: item.id.value))


def _pattern(
    unknown: UnknownFact,
    records: tuple[CorrelationRecord, ...],
    observations: Mapping[EvidenceId, ObservedFact],
    trace_ids: tuple[TraceId, ...],
    trace_complete: bool,
) -> ObservedAffinePattern:
    relevant = tuple(record for record in records if record.unknown_id == unknown.id)
    candidate_ids = tuple(
        sorted(
            {
                observed_id
                for record in relevant
                for observed_id in record.observed_ids
                if observed_id in observations
            },
            key=lambda item: item.value,
        )
    )
    matched = _memory_observations(observations, candidate_ids)
    # 只有带地址的普通访存才能说明 affine observation；同一 PC 的 fence、
    # 原子边界和控制事件仍由通用诊断报告保留，但不冒充 affine 样本。
    observed_ids = tuple(item.id for item in matched)
    statuses = {record.status for record in relevant}
    if CorrelationStatus.AMBIGUOUS in statuses:
        correlation_status = CorrelationStatus.AMBIGUOUS
    elif CorrelationStatus.EXACT in statuses:
        correlation_status = CorrelationStatus.EXACT
    else:
        correlation_status = CorrelationStatus.UNMATCHED
    correlation_key = next(
        (record.key for record in relevant if record.status == correlation_status),
        CorrelationKey.NONE,
    )
    threads_by_id: dict[ThreadInstanceId, list[ObservedFact]] = defaultdict(list)
    for fact in matched:
        threads_by_id[fact.execution_id].append(fact)
    threads = tuple(
        _thread_observation(tuple(facts), execution_id)
        for execution_id, facts in sorted(threads_by_id.items(), key=lambda item: item[0].value)
    )
    base_candidates = tuple(
        sorted({item.sample_addresses[0] for item in threads if item.sample_addresses})
    )
    stride_candidates = tuple(sorted({stride for item in threads for stride in item.stride_candidates}))
    sample_count = sum(item.sample_count for item in threads)
    limitations: list[str] = []
    if correlation_status == CorrelationStatus.AMBIGUOUS:
        limitations.append("correlation has more than one possible static operand")
    if correlation_status == CorrelationStatus.UNMATCHED:
        limitations.append("no uniquely matched dynamic memory site")
    if not matched:
        limitations.append("no address samples were observed for this Unknown")
    if matched and not any(_attributes(item).get("thread_role") for item in matched):
        limitations.append("dynamic trace did not record a static thread-role candidate")
    if any(not item.sample_complete for item in threads):
        limitations.append("address samples reached the adapter limit")
        if any("address_sample_complete" not in _attributes(item) for item in matched):
            limitations.append("dynamic fact lacks bounded address sample metadata")
    if any(not item.stride_complete for item in threads):
        limitations.append("stride candidates reached the adapter limit")
        if any("stride_candidates_complete" not in _attributes(item) for item in matched):
            limitations.append("dynamic fact lacks bounded stride metadata")
    complete = bool(trace_complete and matched and all(item.sample_complete and item.stride_complete for item in threads))
    repetition_stable = _repetition_stability(matched)
    if correlation_status == CorrelationStatus.AMBIGUOUS:
        status = ObservedAffineStatus.AMBIGUOUS
    elif not matched:
        status = ObservedAffineStatus.NOT_OBSERVED
    elif not complete:
        status = ObservedAffineStatus.INCOMPLETE
    elif sample_count < 2 or not stride_candidates:
        status = ObservedAffineStatus.INSUFFICIENT
    elif repetition_stable is True and len(stride_candidates) == 1:
        status = ObservedAffineStatus.STABLE
    else:
        status = ObservedAffineStatus.VARIABLE
    subjects = tuple(fact.subject for fact in matched if fact.subject is not None)
    instruction_subjects = tuple(item for item in subjects if item.prefix == "instruction")
    operand_subjects = tuple(item for item in subjects if item.prefix == "operand")
    if unknown.subject is not None:
        if unknown.subject.prefix == "instruction":
            instruction_subjects += (unknown.subject,)
        elif unknown.subject.prefix == "operand":
            operand_subjects += (unknown.subject,)
    return ObservedAffinePattern(
        schema_version=_PATTERN_SCHEMA,
        unknown_id=unknown.id,
        correlation_status=correlation_status,
        correlation_key=correlation_key,
        observed_ids=observed_ids,
        trace_ids=trace_ids,
        instruction_subjects=instruction_subjects,
        operand_subjects=operand_subjects,
        sample_count=sample_count,
        base_candidates=base_candidates,
        stride_candidates=stride_candidates,
        thread_observations=threads,
        overlap=_overlap(threads),
        repetition_stable=repetition_stable,
        complete=complete,
        status=status,
        limitations=tuple(limitations),
    )


def _normalize_dynamic_snapshots(
    dynamic: DynamicDiagnosticSnapshot | Iterable[DynamicDiagnosticSnapshot],
) -> tuple[DynamicDiagnosticSnapshot, ...]:
    if isinstance(dynamic, DynamicDiagnosticSnapshot):
        result = (dynamic,)
    else:
        result = tuple(dynamic)
    if any(not isinstance(item, DynamicDiagnosticSnapshot) for item in result):
        raise AffineObservationError("dynamic snapshots have an invalid type")
    if not result:
        raise AffineObservationError("at least one dynamic snapshot is required")
    return result


def summarize_observed_affine_patterns(
    static: StaticDiagnosticSnapshot,
    dynamic: DynamicDiagnosticSnapshot | Iterable[DynamicDiagnosticSnapshot],
    *,
    correlations: Iterable[object] | None = None,
) -> tuple[ObservedAffinePattern, ...]:
    """汇总所有 ``UnknownAffineBounds``，但不生成静态 proof。"""

    if not isinstance(static, StaticDiagnosticSnapshot):
        raise AffineObservationError("static snapshot has an invalid type")
    dynamics = _normalize_dynamic_snapshots(dynamic)
    if correlations is None:
        reports = tuple(correlate_unknowns(static, item) for item in dynamics)
    else:
        supplied = tuple(correlations)
        if len(supplied) != len(dynamics):
            raise AffineObservationError("correlations must align with dynamic snapshots")
        reports = supplied
    if any(not isinstance(item, DiagnosticCorrelationReport) for item in reports):
        raise AffineObservationError("correlations have an invalid type")
    records_by_unknown: dict[EvidenceId, list[CorrelationRecord]] = defaultdict(list)
    observations: dict[EvidenceId, ObservedFact] = {}
    for dynamic_snapshot, report in zip(dynamics, reports):
        for node in dynamic_snapshot.evidence.nodes:
            if isinstance(node, ObservedFact):
                observations[node.id] = node
        for record in report.records:
            records_by_unknown[record.unknown_id].append(record)
    static_unknowns = tuple(
        node
        for node in static.evidence.nodes
        if isinstance(node, UnknownFact) and node.kind == UnknownKind.UNKNOWN_AFFINE_BOUNDS
    )
    trace_ids = _trace_ids(item.trace_id for item in dynamics)
    trace_complete = all(item.complete for item in dynamics)
    return tuple(
        _pattern(
            unknown,
            tuple(records_by_unknown.get(unknown.id, ())),
            observations,
            trace_ids,
            trace_complete,
        )
        for unknown in sorted(static_unknowns, key=lambda item: item.id.value)
    )


def site_filter_for_affine_unknowns(
    static: StaticDiagnosticSnapshot,
) -> set[tuple[str, int]]:
    """提取可用于流式回查的静态模块/PC 集合。

    只有 Unknown provenance 明确给出模块和 PC 时才筛选；缺少位置不能凭
    subject 猜地址，调用者应回退到完整扫描或显式报告资源限制。
    """

    if not isinstance(static, StaticDiagnosticSnapshot):
        raise AffineObservationError("static snapshot has an invalid type")
    sites: set[tuple[str, int]] = set()
    for node in static.evidence.nodes:
        if not isinstance(node, UnknownFact) or node.kind != UnknownKind.UNKNOWN_AFFINE_BOUNDS:
            continue
        values: dict[str, str] = {}
        for context in node.supporting_context:
            name, separator, value = context.partition("=")
            if separator and name.startswith("legacy."):
                values[name[len("legacy.") :]] = value
        module = values.get("module")
        pc = _integer(values.get("pc"))
        if module and pc is not None:
            sites.add((module, pc))
    return sites


def build_affine_validation_report(
    static: StaticDiagnosticSnapshot,
    dynamic: DynamicDiagnosticSnapshot | Iterable[DynamicDiagnosticSnapshot],
    *,
    correlations: Iterable[object] | None = None,
) -> AffineValidationReport:
    """生成 E2 覆盖报告；原始静态 verdict 逐字保留。"""

    dynamics = _normalize_dynamic_snapshots(dynamic)
    supplied = tuple(correlations) if correlations is not None else None
    patterns = summarize_observed_affine_patterns(
        static,
        dynamics,
        correlations=supplied,
    )
    records: tuple[CorrelationRecord, ...]
    if supplied is None:
        records = tuple(
            record
            for item in dynamics
            for record in correlate_unknowns(static, item).records
            if record.unknown_id in {pattern.unknown_id for pattern in patterns}
        )
    else:
        records = tuple(
            record
            for report in supplied
            for record in getattr(report, "records", ())
            if record.unknown_id in {pattern.unknown_id for pattern in patterns}
        )
    by_unknown: dict[EvidenceId, list[CorrelationRecord]] = defaultdict(list)
    for record in records:
        by_unknown[record.unknown_id].append(record)
    exercised = ambiguous = unmatched = not_executed = 0
    for pattern in patterns:
        item_records = tuple(by_unknown.get(pattern.unknown_id, ()))
        # 覆盖率跟随 E1 过滤后的普通访存样本；匹配到 fence 不能冒充地址序列。
        if (
            pattern.correlation_status == CorrelationStatus.EXACT
            and pattern.observed_ids
        ):
            exercised += 1
        elif pattern.correlation_status == CorrelationStatus.AMBIGUOUS:
            ambiguous += 1
        else:
            unmatched += 1
            if item_records and all(
                not record.observed_ids and record.key != CorrelationKey.BINARY_CLOSURE
                for record in item_records
            ):
                not_executed += 1
    return AffineValidationReport(
        schema_version=_REPORT_SCHEMA,
        static_verdict=static.verdict,
        static_unknown_count=sum(isinstance(node, UnknownFact) for node in static.evidence.nodes),
        affine_unknown_count=len(patterns),
        trace_ids=tuple(item.trace_id for item in dynamics),
        trace_complete=all(item.complete for item in dynamics),
        patterns=patterns,
        exercised_count=exercised,
        ambiguous_count=ambiguous,
        not_executed_count=not_executed,
        unmatched_count=unmatched,
    )


def _thread_dict(item: ObservedAffineThread) -> dict[str, object]:
    return {
        "execution_id": item.execution_id.value,
        "sample_count": item.sample_count,
        "distinct_address_count": item.distinct_address_count,
        "address_min": f"0x{item.address_min:x}" if item.address_min is not None else None,
        "address_max_end": f"0x{item.address_max_end:x}" if item.address_max_end is not None else None,
        "sample_addresses": [f"0x{value:x}" for value in item.sample_addresses],
        "sample_complete": item.sample_complete,
        "stride_candidates": list(item.stride_candidates),
        "stride_complete": item.stride_complete,
        "role_candidates": list(item.role_candidates),
    }


def affine_pattern_to_dict(item: ObservedAffinePattern) -> dict[str, object]:
    return {
        "schema_version": item.schema_version,
        "unknown_id": item.unknown_id.value,
        "correlation_status": item.correlation_status.value,
        "correlation_key": item.correlation_key.value,
        "observed_ids": [value.value for value in item.observed_ids],
        "trace_ids": [value.value for value in item.trace_ids],
        "instruction_subjects": [value.value for value in item.instruction_subjects],
        "operand_subjects": [value.value for value in item.operand_subjects],
        "sample_count": item.sample_count,
        "base_candidates": [f"0x{value:x}" for value in item.base_candidates],
        "stride_candidates": list(item.stride_candidates),
        "thread_observations": [_thread_dict(value) for value in item.thread_observations],
        "overlap": item.overlap.value,
        "repetition_stable": item.repetition_stable,
        "complete": item.complete,
        "status": item.status.value,
        "limitations": list(item.limitations),
    }


def affine_report_to_dict(report: AffineValidationReport) -> dict[str, object]:
    return {
        "schema_version": report.schema_version,
        "static_verdict": report.static_verdict.value,
        "static_unknown_count": report.static_unknown_count,
        "affine_unknown_count": report.affine_unknown_count,
        "trace_ids": [value.value for value in report.trace_ids],
        "trace_complete": report.trace_complete,
        "coverage": {
            "exercised_count": report.exercised_count,
            "ambiguous_count": report.ambiguous_count,
            "not_executed_count": report.not_executed_count,
            "unmatched_count": report.unmatched_count,
        },
        "static_proof_unchanged": report.static_proof_unchanged,
        "statement": report.statement,
        "patterns": [affine_pattern_to_dict(item) for item in report.patterns],
    }


def affine_report_to_json(report: AffineValidationReport) -> str:
    return json.dumps(affine_report_to_dict(report), ensure_ascii=False, indent=2, sort_keys=True)


def save_affine_report(report: AffineValidationReport, path: Path) -> None:
    if not isinstance(path, Path):
        raise AffineObservationError("report path must be a Path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(affine_report_to_json(report) + "\n", encoding="utf-8")


__all__ = [
    "AffineObservationError",
    "AffineValidationReport",
    "ObservedAffinePattern",
    "ObservedAffineStatus",
    "ObservedAffineThread",
    "ObservedOverlap",
    "affine_pattern_to_dict",
    "affine_report_to_dict",
    "affine_report_to_json",
    "build_affine_validation_report",
    "save_affine_report",
    "site_filter_for_affine_unknowns",
    "summarize_observed_affine_patterns",
]
