"""把静态 Unknown 与动态观察做保守、可审计的 stable-ID 对齐。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from bmo_check_core import (
    BindingDimension,
    BindingStatus,
    BinaryClosureId,
    CertificateVerdict,
    CorrelationBinding,
    DynamicDiagnosticSnapshot,
    EvidenceId,
    ObservedFact,
    StaticDiagnosticSnapshot,
    TraceId,
    UnknownFact,
)


class CorrelationError(ValueError):
    """相关输入不满足同一 trace/scope 约束时抛出的错误。"""


class CorrelationStatus(StrEnum):
    # EXACT 表示 site 唯一，且调用方提供的跨路由绑定（若有）全部通过。
    EXACT = "Exact"
    # AMBIGUOUS 表示有候选但缺少足够身份材料，不能任选一个。
    AMBIGUOUS = "Ambiguous"
    # UNMATCHED 表示没有可接受的动态观察或 binary closure 不相容。
    UNMATCHED = "Unmatched"


class CorrelationKey(StrEnum):
    # SUBJECT 是 Instruction/MemoryOperand/Object 等 StableId 的精确相等。
    SUBJECT = "stable_subject"
    # INSTRUCTION 使用闭包、模块路径、ELF PC 和 effect 类型回查旧适配器事实。
    INSTRUCTION = "module_relative_instruction"
    # BINARY_CLOSURE 记录闭包不一致导致的拒绝。
    BINARY_CLOSURE = "binary_closure"
    # NONE 表示静态 Unknown 没有任何稳定 subject。
    NONE = "none"
    # BINDING 表示 binary、translation policy 或分析范围不兼容。
    BINDING = "cross_route_binding"


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
    # binding 留下跨路由兼容性检查；None 表示旧 snapshot-only 调用未提供比较材料。
    binding: CorrelationBinding | None = None

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
        if self.binding is not None and not isinstance(self.binding, CorrelationBinding):
            raise CorrelationError("correlation binding has an invalid type")
        object.__setattr__(
            self,
            "records",
            tuple(sorted(self.records, key=lambda item: item.unknown_id.value)),
        )


@dataclass(frozen=True, slots=True)
class _StaticLocation:
    """从静态 Unknown 的 provenance 文本中提取的可审计位置。"""

    module: str | None
    pc: int | None
    kind: str | None


@dataclass(frozen=True, slots=True)
class _ObservedLocation:
    """动态观察适配器写入的稳定位置属性。"""

    subject: object
    module: str | None
    pc: int | None
    kind: str | None
    operand: str | None


_LOCATION_PREFIX: Final[str] = "legacy."
_PC_RE: Final[re.Pattern[str]] = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
_EFFECT_LABELS: Final[frozenset[str]] = frozenset(
    {
        "load",
        "store",
        "atomicrmw",
        "lfence",
        "sfence",
        "mfence",
    }
)


def _attributes(observed: ObservedFact) -> dict[str, str]:
    return {item.name: item.value for item in observed.attributes}


def _parse_pc(value: str) -> int | None:
    value = value.strip()
    if not _PC_RE.fullmatch(value):
        return None
    try:
        return int(value, 16 if value.lower().startswith("0x") else 10)
    except ValueError:
        return None


def _static_location(unknown: UnknownFact) -> _StaticLocation:
    values: dict[str, str] = {}
    for context in unknown.supporting_context:
        name, separator, value = context.partition("=")
        if separator and name.startswith(_LOCATION_PREFIX):
            values[name[len(_LOCATION_PREFIX) :]] = value
    kind = values.get("kind")
    # legacy.kind 通常保存 UnknownKind（例如 UnknownAffineBounds），不是访存
    # effect。只有明确的 Load/Store 等 effect 标签才能参与位置匹配；否则把
    # Unknown 分类误当成 effect 会让真实动态站点全部变成 Unmatched。
    if kind is not None and kind.casefold() not in _EFFECT_LABELS:
        kind = None
    return _StaticLocation(
        module=values.get("module"),
        pc=_parse_pc(values["pc"]) if "pc" in values else None,
        kind=kind,
    )


def _observed_location(observed: ObservedFact) -> _ObservedLocation:
    values = _attributes(observed)
    pc_value = values.get("elf_pc") or values.get("instruction_offset")
    return _ObservedLocation(
        subject=observed.subject,
        module=values.get("module_path"),
        pc=_parse_pc(pc_value) if pc_value is not None else None,
        kind=values.get("event_kind"),
        operand=values.get("operand_index") or values.get("operand_identity"),
    )


def _same_location(
    static: _StaticLocation,
    observed: _ObservedLocation,
) -> bool:
    # 缺少 PC 或 effect 类型时不进行模糊猜测；这类 Unknown 仍保留 Unmatched。
    if static.pc is None or observed.pc is None:
        return False
    if static.pc != observed.pc:
        return False
    if static.module is not None and observed.module is not None:
        if static.module != observed.module:
            return False
    elif static.module != observed.module:
        # 两条路径都缺 module 时，PC 不能唯一绑定到一个 ELF。
        return False
    if static.kind is None:
        # 一些 CFG Unknown 只有 call-site PC；该位置仍可由实际间接目标回查。
        # 如果同一 PC 同时出现多个 effect，后面的 ambiguity 检查会保守降级。
        return True
    if observed.kind is None:
        return False
    return static.kind.casefold() == observed.kind.casefold()


def _fallback_candidates(
    unknown: UnknownFact,
    observed: tuple[ObservedFact, ...],
) -> tuple[ObservedFact, ...]:
    location = _static_location(unknown)
    if location.pc is None:
        return ()
    candidates = tuple(
        item
        for item in observed
        if _same_location(location, _observed_location(item))
    )
    if not candidates:
        return ()
    return candidates


def _fallback_is_ambiguous(
    unknown: UnknownFact,
    candidates: tuple[ObservedFact, ...],
    static_site_counts: dict[tuple[str | None, int | None, str | None], int],
) -> bool:
    """判断位置匹配是否缺少 operand 级别的唯一性。"""

    location = _static_location(unknown)
    site = (
        location.module,
        location.pc,
        location.kind.casefold() if location.kind else None,
    )
    operands = {
        _observed_location(item).operand
        for item in candidates
        if _observed_location(item).operand is not None
    }
    kinds = {
        _observed_location(item).kind.casefold()
        for item in candidates
        if _observed_location(item).kind is not None
    }
    if _static_location(unknown).kind is None and len(kinds) > 1:
        return True
    if len(operands) > 1:
        return True
    return "missing" in operands and static_site_counts.get(site, 0) > 1


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
    *,
    binding: CorrelationBinding | None = None,
) -> DiagnosticCorrelationReport:
    """按 stable subject 和位置回退做保守匹配，绝不猜测缺失的 operand。"""

    if not isinstance(static, StaticDiagnosticSnapshot):
        raise CorrelationError("static snapshot has an invalid type")
    if not isinstance(dynamic, DynamicDiagnosticSnapshot):
        raise CorrelationError("dynamic snapshot has an invalid type")
    if binding is not None and not isinstance(binding, CorrelationBinding):
        raise CorrelationError("binding must be a CorrelationBinding")
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

    static_unknowns = tuple(
        node
        for node in static.evidence.nodes
        if isinstance(node, UnknownFact)
    )
    if binding is not None:
        binary_check = binding.check(BindingDimension.BINARY_CLOSURE)
        expected_binary_status = (
            BindingStatus.UNVERIFIED
            if not closure_known
            else BindingStatus.MATCH
            if closure_matches
            else BindingStatus.MISMATCH
        )
        if binary_check.status != expected_binary_status:
            raise CorrelationError(
                "binary-closure binding assessment conflicts with diagnostic snapshots"
            )
        if binding.status == BindingStatus.MISMATCH:
            reasons = "; ".join(
                f"{item.dimension.value}: {item.reason}"
                for item in binding.checks
                if item.status == BindingStatus.MISMATCH
            )
            return DiagnosticCorrelationReport(
                schema_version="diagnostic-correlation-v2",
                static_verdict=static.verdict,
                trace_id=dynamic.trace_id,
                trace_complete=dynamic.complete,
                records=tuple(
                    CorrelationRecord(
                        unknown_id=node.id,
                        observed_ids=(),
                        status=CorrelationStatus.UNMATCHED,
                        key=CorrelationKey.BINDING,
                        reason=f"cross-route inputs are incompatible: {reasons}",
                    )
                    for node in static_unknowns
                ),
                binding=binding,
            )
    static_site_counts: dict[tuple[str | None, int | None, str | None], int] = {}
    for node in static_unknowns:
        location = _static_location(node)
        site = (
            location.module,
            location.pc,
            location.kind.casefold() if location.kind else None,
        )
        if location.pc is not None:
            static_site_counts[site] = static_site_counts.get(site, 0) + 1

    records: list[CorrelationRecord] = []
    for node in static_unknowns:
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
        candidates = tuple(by_subject.get(subject, ())) if subject is not None else ()
        if candidates:
            records.append(
                CorrelationRecord(
                    unknown_id=node.id,
                    observed_ids=tuple(item.id for item in candidates),
                    status=(
                        CorrelationStatus.EXACT
                        if closure_known
                        else CorrelationStatus.AMBIGUOUS
                    ),
                    key=CorrelationKey.SUBJECT,
                    reason=(
                        "stable subject and binary closure identify the observed site"
                        if closure_known
                        else "stable subject matched, but binary closure is missing"
                    ),
                )
            )
            continue

        fallback = _fallback_candidates(node, observed)
        if fallback:
            ambiguous = _fallback_is_ambiguous(node, fallback, static_site_counts)
            if not closure_known:
                ambiguous = True
            records.append(
                CorrelationRecord(
                    unknown_id=node.id,
                    observed_ids=tuple(item.id for item in fallback),
                    status=(
                        CorrelationStatus.AMBIGUOUS
                        if ambiguous
                        else CorrelationStatus.EXACT
                    ),
                    key=CorrelationKey.INSTRUCTION,
                    reason=(
                        "module-relative ELF PC and effect identify the site, "
                        "but operand identity is not unique"
                        if ambiguous
                        else "module-relative ELF PC and effect identify the observed site"
                    ),
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
                    reason="static Unknown has no stable subject or location",
                )
            )
            continue

        records.append(
            CorrelationRecord(
                unknown_id=node.id,
                observed_ids=(),
                status=CorrelationStatus.UNMATCHED,
                key=CorrelationKey.SUBJECT,
                reason=(
                    "no observed fact has the same stable subject or location"
                    if closure_known
                    else "stable subject/location matched no event and binary closure is absent"
                ),
            )
        )
        continue
    if binding is not None and binding.status == BindingStatus.UNVERIFIED:
        reasons = "; ".join(
            f"{item.dimension.value}: {item.reason}"
            for item in binding.checks
            if item.status == BindingStatus.UNVERIFIED
        )
        records = [
            CorrelationRecord(
                unknown_id=item.unknown_id,
                observed_ids=item.observed_ids,
                status=(
                    CorrelationStatus.AMBIGUOUS
                    if item.status == CorrelationStatus.EXACT
                    else item.status
                ),
                key=item.key,
                reason=(
                    f"{item.reason}; cross-route binding remains unverified: {reasons}"
                    if item.status == CorrelationStatus.EXACT
                    else item.reason
                ),
            )
            for item in records
        ]

    return DiagnosticCorrelationReport(
        schema_version=(
            "diagnostic-correlation-v2"
            if binding is not None
            else "diagnostic-correlation-v1"
        ),
        static_verdict=static.verdict,
        trace_id=dynamic.trace_id,
        trace_complete=dynamic.complete,
        records=tuple(records),
        binding=binding,
    )


__all__ = [
    "CorrelationError",
    "CorrelationKey",
    "CorrelationRecord",
    "CorrelationStatus",
    "DiagnosticCorrelationReport",
    "correlate_unknowns",
]
