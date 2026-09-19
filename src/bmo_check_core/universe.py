"""分析阶段之间的 event universe 对账值对象。

这里不决定 SAFE，也不替代 proof obligation。它只记录一个阶段收到的事件
是否在输出中被保留、被有 ProofFact 地移除，或带着 UnknownFact 留下。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .identity import EvidenceId, MemoryEventId


class CompletenessStatus(StrEnum):
    """universe 对账的闭合状态。"""

    # 所有输入事件都有唯一 disposition，且没有发现未记录项。
    COMPLETE = "COMPLETE"
    # 仍有事件或边界没有被当前 producer 唯一归类。
    INCOMPLETE = "INCOMPLETE"
    # 输入超出该阶段支持集，不能把缺失记录当成没有事件。
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class CompletenessState:
    """带 scope/reason 的显式完整性状态。"""

    # status 不能用 bool 表达，因为 unsupported 与 incomplete 的后续策略不同。
    status: CompletenessStatus
    # scope 说明这个状态覆盖哪个 producer 阶段或分析范围。
    scope: str
    # 非 COMPLETE 必须说明缺口，防止失败状态被静默吞掉。
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, CompletenessStatus):
            raise ValueError("status must be a CompletenessStatus")
        if not isinstance(self.scope, str) or not self.scope or "\x00" in self.scope:
            raise ValueError("scope must be a non-empty string")
        if self.status is CompletenessStatus.COMPLETE:
            if self.reason is not None:
                raise ValueError("complete state cannot carry a failure reason")
        elif not isinstance(self.reason, str) or not self.reason or "\x00" in self.reason:
            raise ValueError("incomplete or unsupported state requires a reason")


class EventDisposition(StrEnum):
    """每个输入 MemoryEvent 在阶段输出中的唯一去向。"""

    # retained 事件继续进入下一阶段，不能仅因出现于列表就视为已证明。
    RETAINED = "retained"
    # removed_with_proof 只能引用可回查的 ProofFact。
    REMOVED_WITH_PROOF = "removed_with_proof"
    # unresolved 事件必须绑定 UnknownFact，等待后续分析闭合。
    UNRESOLVED = "unresolved"


def _ids(name: str, values: tuple[MemoryEventId, ...] | tuple[EvidenceId, ...]):
    raw = tuple(values)
    if any(not isinstance(item, (MemoryEventId, EvidenceId)) for item in raw):
        raise ValueError(f"{name} contains an invalid stable identity")
    normalized = tuple(sorted(raw, key=lambda item: item.value))
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{name} contains duplicate identities")
    return normalized


@dataclass(frozen=True, slots=True)
class EventUniverseEntry:
    """一个输入 event 的 disposition 和对应证据。"""

    # event_id 是稳定 MemoryEventId，不是一次运行的列表下标。
    event_id: MemoryEventId
    # disposition 明确 event 是保留、证明移除还是 unresolved。
    disposition: EventDisposition
    # removed_with_proof 必须列出覆盖它的 ProofFact identity。
    proof_ids: tuple[EvidenceId, ...] = ()
    # unresolved 必须列出阻塞该 event 的 UnknownFact identity。
    unknown_ids: tuple[EvidenceId, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, MemoryEventId):
            raise ValueError("event_id must be a MemoryEventId")
        if not isinstance(self.disposition, EventDisposition):
            raise ValueError("disposition must be an EventDisposition")
        object.__setattr__(self, "proof_ids", _ids("proof_ids", self.proof_ids))
        object.__setattr__(self, "unknown_ids", _ids("unknown_ids", self.unknown_ids))
        if self.disposition is EventDisposition.RETAINED and (
            self.proof_ids or self.unknown_ids
        ):
            raise ValueError("retained event cannot carry removal or unknown evidence")
        if self.disposition is EventDisposition.REMOVED_WITH_PROOF and not self.proof_ids:
            raise ValueError("removed event requires at least one ProofFact")
        if self.disposition is EventDisposition.REMOVED_WITH_PROOF and self.unknown_ids:
            raise ValueError("removed event cannot also be unresolved")
        if self.disposition is EventDisposition.UNRESOLVED and not self.unknown_ids:
            raise ValueError("unresolved event requires at least one UnknownFact")
        if self.disposition is EventDisposition.UNRESOLVED and self.proof_ids:
            raise ValueError("unresolved event cannot use proof_ids as a substitute")


@dataclass(frozen=True, slots=True)
class EventUniverseLedger:
    """一个 producer stage 的输入/输出 event universe 对账。"""

    # stage 让同一 event 在 recovery、slice、proof 等阶段有可审计边界。
    stage: str
    # input_event_ids 是该阶段必须逐项对账的完整输入集合。
    input_event_ids: tuple[MemoryEventId, ...]
    # entries 给每个已识别输入 event 一个且仅一个 disposition。
    entries: tuple[EventUniverseEntry, ...]
    # completeness 记录是否仍有无法列入 entries 的输入或不支持项。
    completeness: CompletenessState

    def __post_init__(self) -> None:
        if not isinstance(self.stage, str) or not self.stage or "\x00" in self.stage:
            raise ValueError("stage must be a non-empty string")
        normalized_input = _ids("input_event_ids", self.input_event_ids)
        object.__setattr__(self, "input_event_ids", normalized_input)
        if any(not isinstance(item, EventUniverseEntry) for item in self.entries):
            raise ValueError("entries must contain EventUniverseEntry values")
        normalized_entries = tuple(
            sorted(self.entries, key=lambda item: item.event_id.value)
        )
        entry_ids = tuple(item.event_id for item in normalized_entries)
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("entries contain duplicate event identities")
        object.__setattr__(self, "entries", normalized_entries)
        if not isinstance(self.completeness, CompletenessState):
            raise ValueError("completeness must be a CompletenessState")
        input_set = set(normalized_input)
        entry_set = set(entry_ids)
        if not entry_set.issubset(input_set):
            raise ValueError("entries contain events outside input_event_ids")
        if self.completeness.status is CompletenessStatus.COMPLETE and entry_set != input_set:
            raise ValueError("complete ledger must account for every input event")

    @property
    def retained_event_ids(self) -> tuple[MemoryEventId, ...]:
        return tuple(
            item.event_id
            for item in self.entries
            if item.disposition is EventDisposition.RETAINED
        )

    @property
    def removed_event_ids(self) -> tuple[MemoryEventId, ...]:
        return tuple(
            item.event_id
            for item in self.entries
            if item.disposition is EventDisposition.REMOVED_WITH_PROOF
        )

    @property
    def unresolved_event_ids(self) -> tuple[MemoryEventId, ...]:
        return tuple(
            item.event_id
            for item in self.entries
            if item.disposition is EventDisposition.UNRESOLVED
        )

    @property
    def missing_event_ids(self) -> tuple[MemoryEventId, ...]:
        """返回尚未有 entry 的输入事件；非空时不能进入确定 verdict。"""

        accounted = {item.event_id for item in self.entries}
        return tuple(item for item in self.input_event_ids if item not in accounted)


__all__ = [
    "CompletenessState",
    "CompletenessStatus",
    "EventDisposition",
    "EventUniverseEntry",
    "EventUniverseLedger",
]
