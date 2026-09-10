"""把静态 Unknown 与动态观察做保守、可审计的 stable-ID 对齐。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from bmo_check_core import (
    BinaryClosureId,
    CertificateVerdict,
    DynamicDiagnosticSnapshot,
    EvidenceId,
    ObservedFact,
    StaticDiagnosticSnapshot,
    TraceId,
)


class CorrelationError(ValueError):
    """相关输入不满足同一 trace/scope 约束时抛出的错误。"""


class CorrelationStatus(StrEnum):
    # EXACT 只表示 stable subject 和 binary closure 都能唯一绑定。
    EXACT = "Exact"
    # AMBIGUOUS 表示有候选但缺少足够身份材料，不能任选一个。
    AMBIGUOUS = "Ambiguous"
    # UNMATCHED 表示没有可接受的动态观察或 binary closure 不相容。
    UNMATCHED = "Unmatched"


class CorrelationKey(StrEnum):
    # SUBJECT 是 Instruction/MemoryOperand/Object 等 StableId 的精确相等。
    SUBJECT = "stable_subject"
    # BINARY_CLOSURE 记录闭包不一致导致的拒绝。
    BINARY_CLOSURE = "binary_closure"
    # NONE 表示静态 Unknown 没有任何稳定 subject。
    NONE = "none"


@dataclass(frozen=True, slots=True)
class CorrelationRecord:
    # unknown_id 保留静态缺口的稳定身份，不能替换为列表序号。
    unknown_id: EvidenceId
    # observed_ids 可以包含同一静态 site 的多次真实执行。
    observed_ids: tuple[EvidenceId, ...]
    # status 决定报告能否给出定位提示，但不决定任何 proof verdict。
    status: CorrelationStatus
    # key 说明本次比较使用了哪种身份材料。
    key: CorrelationKey
    # reason 记录缺少何种事实，不能被当成证明 premise。
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.unknown_id, EvidenceId):
            raise CorrelationError("unknown_id must be an EvidenceId")
        if any(not isinstance(item, EvidenceId) for item in self.observed_ids):
            raise CorrelationError("observed_ids must contain EvidenceId values")
        if not isinstance(self.status, CorrelationStatus):
            raise CorrelationError("invalid correlation status")
        if not isinstance(self.key, CorrelationKey):
            raise CorrelationError("invalid correlation key")
        if not isinstance(self.reason, str) or not self.reason:
            raise CorrelationError("correlation reason must be non-empty")
        object.__setattr__(
            self,
            "observed_ids",
            tuple(sorted(set(self.observed_ids), key=lambda item: item.value)),
        )


@dataclass(frozen=True, slots=True)
class DiagnosticCorrelationReport:
    # schema_version 让后续增加 function/block fallback 时可以拒绝旧解释。
    schema_version: str
    # static_verdict 原样回显，相关器不能把 UNKNOWN 改写为 SAFE。
    static_verdict: CertificateVerdict
    # trace_id 绑定所有 ObservedFact 的实际执行。
    trace_id: TraceId
    # trace_complete 只用于限制提示可信度，不改变 static_verdict。
    trace_complete: bool
    # records 是每个静态 Unknown 的完整匹配结果。
    records: tuple[CorrelationRecord, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, str) or not self.schema_version:
            raise CorrelationError("correlation schema_version must be non-empty")
        if not isinstance(self.static_verdict, CertificateVerdict):
            raise CorrelationError("correlation static_verdict is invalid")
        if not isinstance(self.trace_id, TraceId):
            raise CorrelationError("correlation trace_id is invalid")
        if not isinstance(self.trace_complete, bool):
            raise CorrelationError("correlation trace_complete must be boolean")
        if any(not isinstance(item, CorrelationRecord) for item in self.records):
            raise CorrelationError("correlation records have an invalid type")
        object.__setattr__(
            self,
            "records",
            tuple(sorted(self.records, key=lambda item: item.unknown_id.value)),
        )


def _closure_status(
    static: StaticDiagnosticSnapshot,
    dynamic: DynamicDiagnosticSnapshot,
) -> tuple[bool, bool]:
    if static.binary_closure is None or dynamic.binary_closure is None:
        # Missing closure is not a mismatch, but it prevents an Exact result.
        return False, False
    return static.binary_closure == dynamic.binary_closure, True


def correlate_unknowns(
    static: StaticDiagnosticSnapshot,
    dynamic: DynamicDiagnosticSnapshot,
) -> DiagnosticCorrelationReport:
    """按 stable subject 做一对多保守匹配，绝不猜测缺失的 operand。"""

    if not isinstance(static, StaticDiagnosticSnapshot):
        raise CorrelationError("static snapshot has an invalid type")
    if not isinstance(dynamic, DynamicDiagnosticSnapshot):
        raise CorrelationError("dynamic snapshot has an invalid type")
    closure_matches, closure_known = _closure_status(static, dynamic)
    observed = tuple(
        node
        for node in dynamic.evidence.nodes
        if isinstance(node, ObservedFact)
    )
    by_subject: dict[object, list[ObservedFact]] = {}
    for node in observed:
        if node.subject is not None:
            by_subject.setdefault(node.subject, []).append(node)

    records: list[CorrelationRecord] = []
    for node in static.evidence.nodes:
        # UnknownFact is imported indirectly through snapshot. Avoid exposing a
        # second evidence representation in the diagnostics package itself.
        if node.id not in static.unknown_ids:
            continue
        subject = getattr(node, "subject", None)
        if not closure_matches and closure_known:
            records.append(
                CorrelationRecord(
                    unknown_id=node.id,
                    observed_ids=(),
                    status=CorrelationStatus.UNMATCHED,
                    key=CorrelationKey.BINARY_CLOSURE,
                    reason="static and dynamic binary closures differ",
                )
            )
            continue
        if subject is None:
            records.append(
                CorrelationRecord(
                    unknown_id=node.id,
                    observed_ids=(),
                    status=CorrelationStatus.UNMATCHED,
                    key=CorrelationKey.NONE,
                    reason="static Unknown has no stable subject",
                )
            )
            continue
        candidates = tuple(by_subject.get(subject, ()))
        if not candidates:
            records.append(
                CorrelationRecord(
                    unknown_id=node.id,
                    observed_ids=(),
                    status=CorrelationStatus.UNMATCHED,
                    key=CorrelationKey.SUBJECT,
                    reason=(
                        "no observed fact has the same stable subject"
                        if closure_known
                        else "stable subject matched no event and binary closure is absent"
                    ),
                )
            )
            continue
        status = (
            CorrelationStatus.EXACT
            if closure_known
            else CorrelationStatus.AMBIGUOUS
        )
        reason = (
            "stable subject and binary closure identify the observed site"
            if closure_known
            else "stable subject matched, but binary closure is missing"
        )
        records.append(
            CorrelationRecord(
                unknown_id=node.id,
                observed_ids=tuple(item.id for item in candidates),
                status=status,
                key=CorrelationKey.SUBJECT,
                reason=reason,
            )
        )
    return DiagnosticCorrelationReport(
        schema_version="diagnostic-correlation-v1",
        static_verdict=static.verdict,
        trace_id=dynamic.trace_id,
        trace_complete=dynamic.complete,
        records=tuple(records),
    )


__all__ = [
    "CorrelationError",
    "CorrelationKey",
    "CorrelationRecord",
    "CorrelationStatus",
    "DiagnosticCorrelationReport",
    "correlate_unknowns",
]
