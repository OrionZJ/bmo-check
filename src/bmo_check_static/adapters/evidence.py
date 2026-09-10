"""把旧静态模型单向转换到 canonical evidence ledger。

为什么需要这个文件：
    静态 producer 和 certificate builder 仍交换 Pydantic report。C4 需要一座
    单向桥，先验证新的身份/evidence 边界，同时不改变现有 verdict 和 JSON 契约。

当前调用者：
    只有 C4 characterization 和 adapter 测试；静态分析与 certificate 生成路径
    还没有调用这里的代码。

不支持的旧 payload：
    空的旧 ID、格式错误的 module hash/PC、不能规范化为 JSON 的 ``details``，以及
    引用了报告外 event 的 proof 都会被拒绝。静默丢掉事实会让新 snapshot 比旧
    report 更不保守。

删除条件：
    所有静态 producer 和 certificate consumer 都直接使用 canonical
    identity/evidence，并且 differential tests 已经退役后，才能删除本模块。
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from bmo_check_core import (
    EvidenceId,
    EvidenceLedger,
    InstructionId,
    MemoryEventId,
    MemoryOperandId,
    ModuleId,
    ProofFact,
    ProducerId,
    StableId,
    ThreadRoleId,
    UnknownFact as CanonicalUnknownFact,
    UnknownKind as CanonicalUnknownKind,
)
from bmo_check_static.model import (
    MemoryEvent,
    ModuleFingerprint,
    ProgramSliceReport,
    ProofObject,
    UnknownFact as LegacyUnknownFact,
)


class StaticAdapterError(ValueError):
    """旧报告不能无损映射到 canonical 身份或证据时抛出的错误。"""


class LegacyFactType(StrEnum):
    # MEMORY_EVENT 是旧报告中的一条静态访存 effect。
    MEMORY_EVENT = "MemoryEvent"
    # PROOF_OBJECT 是旧剪枝层覆盖一组 event 的证明记录。
    PROOF_OBJECT = "ProofObject"
    # UNKNOWN_FACT 是旧分析层产生的未闭合 proof obligation。
    UNKNOWN_FACT = "UnknownFact"


@dataclass(frozen=True, slots=True)
class LegacyEvidenceLink:
    # source_type 说明旧模型中的事实种类，避免调用者猜 canonical_id 的类型。
    source_type: LegacyFactType
    # legacy_id 保留旧报告的稳定 id；Unknown 没有 id 时使用内容摘要。
    legacy_id: str
    # canonical_id 是同一事实在新身份域中的值对象。
    canonical_id: StableId
    # origin 说明事实来自报告的哪一层，但不参与 canonical 身份计算。
    origin: str
    # context 保存旧模型的解释字段；它们不是 proof premise。
    context: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.source_type, LegacyFactType):
            raise StaticAdapterError("legacy link source_type must be LegacyFactType")
        if not isinstance(self.legacy_id, str) or not self.legacy_id:
            raise StaticAdapterError("legacy link legacy_id must be non-empty")
        if not isinstance(self.canonical_id, StableId):
            raise StaticAdapterError("legacy link canonical_id must be a StableId")
        if not isinstance(self.origin, str) or not self.origin:
            raise StaticAdapterError("legacy link origin must be non-empty")
        if any(not isinstance(item, str) or not item for item in self.context):
            raise StaticAdapterError("legacy link context must contain non-empty strings")


@dataclass(frozen=True, slots=True)
class StaticEvidenceSnapshot:
    """静态适配结果；它不包含动态观察或诊断提示。"""

    # ledger 保存 ProofFact 和 UnknownFact；适配器不会创建另外两种 evidence。
    ledger: EvidenceLedger
    # links 让旧事件/证明/Unknown 可以回查 canonical 身份。
    event_links: tuple[LegacyEvidenceLink, ...] = ()
    proof_links: tuple[LegacyEvidenceLink, ...] = ()
    unknown_links: tuple[LegacyEvidenceLink, ...] = ()

    @property
    def event_ids(self) -> tuple[MemoryEventId, ...]:
        return tuple(
            sorted(
                {
                    link.canonical_id
                    for link in self.event_links
                    if isinstance(link.canonical_id, MemoryEventId)
                },
                key=lambda item: item.value,
            )
        )

    @property
    def proof_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            sorted(
                {
                    link.canonical_id
                    for link in self.proof_links
                    if isinstance(link.canonical_id, EvidenceId)
                },
                key=lambda item: item.value,
            )
        )

    @property
    def unknown_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            sorted(
                {
                    link.canonical_id
                    for link in self.unknown_links
                    if isinstance(link.canonical_id, EvidenceId)
                },
                key=lambda item: item.value,
            )
        )


@dataclass(frozen=True, slots=True)
class _ModuleRef:
    path: str
    sha256: str
    role: str
    module_id: ModuleId


@dataclass(frozen=True, slots=True)
class _LegacyUnknownSource:
    origin: str
    fact: LegacyUnknownFact


@dataclass(frozen=True, slots=True)
class _LegacyProofSource:
    origin: str
    fact: ProofObject


def _canonical_json(value: object, *, what: str) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise StaticAdapterError(f"{what} is not canonical JSON") from error


def _legacy_key(fact_type: LegacyFactType, payload: object) -> str:
    digest = hashlib.sha256(
        _canonical_json(payload, what=f"{fact_type.value} identity").encode("utf-8")
    ).hexdigest()
    return f"{fact_type.value.lower()}:{digest}"


def _module_fingerprints(report: ProgramSliceReport) -> tuple[ModuleFingerprint, ...]:
    manifest = report.recovery.manifest
    modules: list[ModuleFingerprint] = []
    for module in (manifest.executable, manifest.interpreter):
        if module is not None:
            modules.append(module)
    modules.extend(manifest.libraries)
    return tuple(
        sorted(
            {
                (module.path, module.sha256, module.role.value): module
                for module in modules
            }.values(),
            key=lambda item: (item.path, item.sha256, item.role.value),
        )
    )


def _module_refs(report: ProgramSliceReport) -> tuple[_ModuleRef, ...]:
    refs: list[_ModuleRef] = []
    for module in _module_fingerprints(report):
        try:
            module_id = ModuleId.from_parts(module.sha256, module.role.value)
        except ValueError as error:
            raise StaticAdapterError(
                f"module {module.path!r} has no valid SHA-256 identity"
            ) from error
        refs.append(
            _ModuleRef(
                path=module.path,
                sha256=module.sha256,
                role=module.role.value,
                module_id=module_id,
            )
        )
    return tuple(refs)


def _module_for_event(event: MemoryEvent, refs: tuple[_ModuleRef, ...]) -> ModuleId:
    matches = tuple(
        ref
        for ref in refs
        if ref.path == event.module and ref.sha256 == event.module_sha256
    )
    if len(matches) == 1:
        return matches[0].module_id
    # 旧 event 已绑定自己的内容 hash。manifest 中找不到的模块仍可定位，
    # 但 role 必须使用保守的 legacy 标记，不能猜成 executable 或 shared library。
    role = "legacy-unbound" if not matches else "legacy-ambiguous"
    try:
        return ModuleId.from_parts(event.module_sha256, role)
    except ValueError as error:
        raise StaticAdapterError(
            f"memory event {event.id!r} has no valid module SHA-256 identity"
        ) from error


def _memory_event_id(
    event: MemoryEvent,
    refs: tuple[_ModuleRef, ...],
) -> MemoryEventId:
    if not isinstance(event.id, str) or not event.id:
        raise StaticAdapterError("memory events require a non-empty legacy id")
    if not isinstance(event.pc, int) or isinstance(event.pc, bool) or event.pc < 0:
        raise StaticAdapterError(f"memory event {event.id!r} has an invalid PC")
    operand_index = event.operand_index if event.operand_index is not None else 0
    if not isinstance(operand_index, int) or isinstance(operand_index, bool) or operand_index < 0:
        raise StaticAdapterError(f"memory event {event.id!r} has an invalid operand index")
    role_label = event.thread_role or "legacy-unknown-thread-role"
    module_id = _module_for_event(event, refs)
    instruction = InstructionId.from_parts(module_id, event.pc)
    operand = MemoryOperandId.from_parts(instruction, operand_index, event.kind.value)
    return MemoryEventId.from_parts(
        operand,
        ThreadRoleId.from_legacy(role_label),
        event.kind.value,
        event.id,
    )


def _event_sources(report: ProgramSliceReport) -> tuple[tuple[str, MemoryEvent], ...]:
    sources: list[tuple[str, MemoryEvent]] = []
    if report.memory_events is not None:
        sources.extend(("memory_events", event) for event in report.memory_events.events)
    if report.shared_slice is not None:
        sources.extend(("shared_slice", event) for event in report.shared_slice.events)
    return tuple(
        sorted(
            sources,
            key=lambda item: (
                item[1].id,
                item[1].module_sha256,
                item[1].pc,
                item[1].kind.value,
                item[0],
            ),
        )
    )


def _unique_events(
    sources: Iterable[tuple[str, MemoryEvent]],
) -> tuple[tuple[str, MemoryEvent], ...]:
    by_id: dict[str, tuple[MemoryEvent, set[str]]] = {}
    for origin, event in sources:
        previous = by_id.get(event.id)
        if previous is not None and previous[0] != event:
            raise StaticAdapterError(
                f"legacy event id {event.id!r} has conflicting payloads"
            )
        if previous is None:
            by_id[event.id] = (event, {origin})
        else:
            previous[1].add(origin)
    return tuple(
        (origin, event)
        for event, origins in sorted(by_id.values(), key=lambda item: item[0].id)
        for origin in sorted(origins)
    )


def _unknown_sources(report: ProgramSliceReport) -> tuple[_LegacyUnknownSource, ...]:
    recovery = report.recovery
    sources: list[_LegacyUnknownSource] = []

    def add(origin: str, facts: Iterable[LegacyUnknownFact]) -> None:
        sources.extend(_LegacyUnknownSource(origin, fact) for fact in facts)

    add("recovery.manifest", recovery.manifest.unknowns)
    add("recovery", recovery.unknowns)
    if recovery.control_flow is not None:
        add("recovery.control_flow", recovery.control_flow.unknowns)
    if recovery.thread_roles is not None:
        add("recovery.thread_roles", recovery.thread_roles.unknowns)
    for synchronization in recovery.synchronization:
        sync_origin = (
            "recovery.synchronization:"
            f"{synchronization.library_sha256}:{synchronization.contract_version}"
        )
        add(sync_origin, synchronization.unknowns)
        for summary in synchronization.summaries:
            add(
                f"{sync_origin}:summary:{summary.function_pc:#x}",
                summary.unknowns,
            )
    if report.memory_events is not None:
        add("memory_events", report.memory_events.unknowns)
    if report.shared_state is not None:
        add("shared_state", report.shared_state.unknowns)
    if report.shared_slice is not None:
        add("shared_slice", report.shared_slice.unknowns)
    add("slice", report.unknowns)
    return tuple(
        sorted(
            sources,
            key=lambda item: (item.origin, _legacy_unknown_key(item.fact)),
        )
    )


def _legacy_unknown_key(fact: LegacyUnknownFact) -> str:
    return _legacy_key(
        LegacyFactType.UNKNOWN_FACT,
        {
            "details": fact.details,
            "function": fact.function,
            "impact": fact.impact,
            "kind": fact.kind.value,
            "module": fact.module,
            "pc": fact.pc,
            "reason": fact.reason,
        },
    )


def _unknown_context(fact: LegacyUnknownFact) -> tuple[str, ...]:
    context = [f"legacy.impact={fact.impact}", f"legacy.kind={fact.kind.value}"]
    if fact.module is not None:
        context.append(f"legacy.module={fact.module}")
    if fact.pc is not None:
        context.append(f"legacy.pc={fact.pc:#x}")
    if fact.function is not None:
        context.append(f"legacy.function={fact.function}")
    for key in sorted(fact.details):
        if not isinstance(key, str):
            raise StaticAdapterError("legacy UnknownFact details keys must be strings")
        detail = _canonical_json(fact.details[key], what=f"detail {key}")
        context.append(
            f"legacy.detail.{key}={detail}"
        )
    return tuple(sorted(context))


def _canonical_unknown_kind(fact: LegacyUnknownFact) -> CanonicalUnknownKind:
    try:
        return CanonicalUnknownKind(fact.kind.value)
    except ValueError:
        # 旧 producer 可能使用 core 尚未登记的 kind；这里保守归入根因未知，
        # 原始 kind 仍保存在 link context，不能把它当作已知证明。
        return CanonicalUnknownKind.UNKNOWN_ROOT_CAUSE


def _unknown_subject(
    fact: LegacyUnknownFact,
    *,
    refs: tuple[_ModuleRef, ...],
    event_ids: dict[str, MemoryEventId],
    events: dict[str, MemoryEvent],
) -> StableId | None:
    direct_event_id = fact.details.get("event_id")
    if isinstance(direct_event_id, str) and direct_event_id in event_ids:
        return event_ids[direct_event_id]
    event_id_list = fact.details.get("event_ids")
    if isinstance(event_id_list, list) and len(event_id_list) == 1:
        only_event = event_id_list[0]
        if isinstance(only_event, str) and only_event in event_ids:
            return event_ids[only_event]
    if fact.module is None or fact.pc is None:
        return None
    matches = tuple(
        event_ids[event_id]
        for event_id, event in events.items()
        if event.module == fact.module and event.pc == fact.pc
    )
    if len(matches) == 1:
        return matches[0]
    module_matches = tuple(ref for ref in refs if ref.path == fact.module)
    if len(module_matches) == 1 and isinstance(fact.pc, int) and fact.pc >= 0:
        return InstructionId.from_parts(module_matches[0].module_id, fact.pc)
    return None


def _proof_sources(report: ProgramSliceReport) -> tuple[_LegacyProofSource, ...]:
    sources: list[_LegacyProofSource] = []
    if report.shared_state is not None:
        sources.extend(
            _LegacyProofSource("shared_state", proof)
            for proof in report.shared_state.proofs
        )
    if report.shared_slice is not None:
        sources.extend(
            _LegacyProofSource("shared_slice", proof)
            for proof in report.shared_slice.proof_objects
        )
    return tuple(sorted(sources, key=lambda item: (item.fact.id, item.origin)))


def adapt_static_report(
    report: ProgramSliceReport,
    *,
    scope: str = "static",
) -> StaticEvidenceSnapshot:
    """转换一份旧 report，不修改 report，也不进入旧 verdict 路径。"""

    if not isinstance(report, ProgramSliceReport):
        raise StaticAdapterError("adapt_static_report expects ProgramSliceReport")
    if not isinstance(scope, str) or not scope:
        raise StaticAdapterError("static evidence scope must be non-empty")

    refs = _module_refs(report)
    event_sources = _event_sources(report)
    unique_events = _unique_events(event_sources)
    event_ids: dict[str, MemoryEventId] = {}
    event_models: dict[str, MemoryEvent] = {}
    event_links: list[LegacyEvidenceLink] = []
    for origin, event in unique_events:
        canonical_id = _memory_event_id(event, refs)
        event_ids.setdefault(event.id, canonical_id)
        event_models.setdefault(event.id, event)
        event_links.append(
            LegacyEvidenceLink(
                source_type=LegacyFactType.MEMORY_EVENT,
                legacy_id=event.id,
                canonical_id=canonical_id,
                origin=origin,
                context=(f"legacy.kind={event.kind.value}", f"legacy.pc={event.pc:#x}"),
            )
        )

    ledger = EvidenceLedger()
    unknown_links: list[LegacyEvidenceLink] = []
    for source in _unknown_sources(report):
        fact = source.fact
        subject = _unknown_subject(
            fact,
            refs=refs,
            event_ids=event_ids,
            events=event_models,
        )
        canonical = CanonicalUnknownFact.create(
            schema_version="legacy-static-1",
            producer=ProducerId("bmo_check_static.legacy", "c4"),
            kind=_canonical_unknown_kind(fact),
            reason=fact.reason,
            subject=subject,
            scope=scope,
            supporting_context=_unknown_context(fact),
        )
        ledger.add(canonical)
        unknown_links.append(
            LegacyEvidenceLink(
                source_type=LegacyFactType.UNKNOWN_FACT,
                legacy_id=_legacy_unknown_key(fact),
                canonical_id=canonical.id,
                origin=source.origin,
                context=_unknown_context(fact),
            )
        )

    proof_sources = _proof_sources(report)
    proof_links: list[LegacyEvidenceLink] = []
    seen_proofs: dict[str, ProofObject] = {}
    for source in proof_sources:
        proof = source.fact
        previous = seen_proofs.get(proof.id)
        if previous is not None and previous != proof:
            raise StaticAdapterError(
                f"legacy proof id {proof.id!r} has conflicting payloads"
            )
        seen_proofs[proof.id] = proof
    for source in sorted(
        proof_sources,
        key=lambda item: (item.fact.id, item.origin),
    ):
        proof = source.fact
        if not proof.id:
            raise StaticAdapterError("proof objects require a non-empty legacy id")
        missing_events = tuple(
            event_id for event_id in proof.event_ids if event_id not in event_ids
        )
        if missing_events:
            raise StaticAdapterError(
                f"proof {proof.id!r} references missing events: {sorted(missing_events)}"
            )
        covered_events = tuple(
            sorted(
                {event_ids[event_id] for event_id in proof.event_ids},
                key=lambda item: item.value,
            )
        )
        if not covered_events:
            raise StaticAdapterError(
                f"proof {proof.id!r} has no covered events in the legacy report"
            )
        canonical = ProofFact.create(
            schema_version="legacy-static-1",
            producer=ProducerId("bmo_check_static.legacy", "c4"),
            subject=covered_events[0] if len(covered_events) == 1 else None,
            rule=proof.reason.value,
            scope=scope,
            covered_events=covered_events,
        )
        ledger.add(canonical)
        proof_links.append(
            LegacyEvidenceLink(
                source_type=LegacyFactType.PROOF_OBJECT,
                legacy_id=proof.id,
                canonical_id=canonical.id,
                origin=source.origin,
                context=tuple(sorted(proof.supporting_facts)),
            )
        )

    return StaticEvidenceSnapshot(
        ledger=ledger,
        event_links=tuple(sorted(event_links, key=lambda item: (item.legacy_id, item.origin))),
        proof_links=tuple(sorted(proof_links, key=lambda item: (item.legacy_id, item.origin))),
        unknown_links=tuple(sorted(unknown_links, key=lambda item: (item.legacy_id, item.origin))),
    )


__all__ = [
    "LegacyEvidenceLink",
    "LegacyFactType",
    "StaticAdapterError",
    "StaticEvidenceSnapshot",
    "adapt_static_report",
]
