from __future__ import annotations

from enum import StrEnum
from hashlib import sha256

from pydantic import model_validator

from .event import EventKind, TraceEvent
from .manifest import StrictModel


class SliceObligationKind(StrEnum):
    """当前窗口 checker 可能依赖的事实类别。"""

    EVENT_PRESENCE = "event_presence"
    COMMUNICATION_EDGE = "communication_edge"
    SOURCE_PPO = "source_ppo"
    TARGET_PPO = "target_ppo"
    READ_FROM_DOMAIN = "read_from_domain"
    COHERENCE_DOMAIN = "coherence_domain"
    BOUNDARY = "boundary"


class SliceCandidateStatus(StrEnum):
    """候选切片状态；只有 PROVEN 才允许未来生成实际缩减窗口。"""

    CANDIDATE_ONLY = "candidate-only"
    PROVEN = "proven"
    REJECTED = "rejected"


class SlicePlanStatus(StrEnum):
    """obligation 图分解的决定；不会直接改变分析窗口。"""

    NO_SAFE_SPLIT = "no-safe-split"
    SPLIT_PROVEN = "split-proven"


class SliceObligation(StrictModel):
    """必须由保留事件或独立 ProofFact 覆盖的关系命题。"""

    obligation_id: str
    kind: SliceObligationKind
    event_ids: tuple[str, ...]
    detail: str

    @model_validator(mode="after")
    def _nonempty(self) -> "SliceObligation":
        if not self.obligation_id or not self.event_ids:
            raise ValueError("slice obligations need an id and at least one event")
        return self


class SliceRemovalLedgerEntry(StrictModel):
    """记录候选删除及覆盖它的 proof fact。"""

    event_id: str
    obligation_ids: tuple[str, ...]
    reason: str
    proof_fact_id: str | None = None
    approved: bool = False

    @model_validator(mode="after")
    def _approval_requires_proof(self) -> "SliceRemovalLedgerEntry":
        if self.approved and not self.proof_fact_id:
            raise ValueError("approved removal requires proof_fact_id")
        if not self.event_id or not self.obligation_ids:
            raise ValueError("removal ledger entry needs event and obligations")
        return self


class SliceCandidateGroup(StrictModel):
    """一组结构相似的事件以及阻止删除的事实。"""

    group_id: str
    thread_id: int
    address: int
    size: int
    kind: str
    event_count: int
    communication_endpoint_count: int
    boundary_count: int
    proposed_event_ids: tuple[str, ...] = ()
    blocked_event_ids: tuple[str, ...] = ()
    reason: str

    @model_validator(mode="after")
    def _counts_are_valid(self) -> "SliceCandidateGroup":
        if self.event_count < 1 or self.size < 1:
            raise ValueError("candidate group must contain positive-sized events")
        if self.communication_endpoint_count < 0 or self.boundary_count < 0:
            raise ValueError("candidate group counts cannot be negative")
        if set(self.proposed_event_ids) & set(self.blocked_event_ids):
            raise ValueError("an event cannot be both proposed and blocked")
        return self


class CandidateSlice(StrictModel):
    """P3 候选结果；它不能作为 proof 或 verdict 的输入。"""

    schema_version: str = "candidate-slice-v1"
    window_id: str
    status: SliceCandidateStatus = SliceCandidateStatus.CANDIDATE_ONLY
    source_event_count: int
    source_event_ids: tuple[str, ...]
    retained_event_ids: tuple[str, ...]
    proposed_event_ids: tuple[str, ...] = ()
    removed_event_ids: tuple[str, ...] = ()
    obligations: tuple[SliceObligation, ...] = ()
    removal_ledger: tuple[SliceRemovalLedgerEntry, ...] = ()
    groups: tuple[SliceCandidateGroup, ...] = ()
    complete: bool = False

    @model_validator(mode="after")
    def _preserve_inventory(self) -> "CandidateSlice":
        source = set(self.source_event_ids)
        retained = set(self.retained_event_ids)
        removed = set(self.removed_event_ids)
        proposed = set(self.proposed_event_ids)
        if self.source_event_count != len(self.source_event_ids):
            raise ValueError("source_event_count does not match event inventory")
        if len(source) != len(self.source_event_ids):
            raise ValueError("source event ids must be unique")
        if not retained <= source or not removed <= source:
            raise ValueError("slice event ids must come from source inventory")
        if retained & removed or retained | removed != source:
            raise ValueError("retained and removed events must partition source")
        if not proposed <= source:
            raise ValueError("proposed events must come from source inventory")
        ledger_events = {entry.event_id for entry in self.removal_ledger}
        if not ledger_events <= proposed:
            raise ValueError("removal ledger may only describe proposed events")
        if self.complete:
            if self.status is not SliceCandidateStatus.PROVEN:
                raise ValueError("only a proven slice may be complete")
            if removed - ledger_events:
                raise ValueError("every removed event needs a removal ledger entry")
            if any(
                entry.event_id in removed
                and (not entry.approved or not entry.proof_fact_id)
                for entry in self.removal_ledger
            ):
                raise ValueError("every removed event needs an approved proof fact")
        elif self.status is SliceCandidateStatus.PROVEN:
            raise ValueError("an uncomplete slice cannot be marked proven")
        return self


class SliceCandidateReport(StrictModel):
    """窗口候选切片报告；不会声称 trace 或窗口已安全缩减。"""

    schema_version: str = "slice-candidate-report-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[CandidateSlice, ...] = ()
    reasons: tuple[str, ...] = ()


class SlicePartition(StrictModel):
    """一个不跨 obligation 的候选求解分区。"""

    partition_id: str
    event_ids: tuple[str, ...]
    obligation_ids: tuple[str, ...]


class SlicePlan(StrictModel):
    """P4 的保守分解结果；分区尚未接入现有 checker。"""

    schema_version: str = "slice-plan-v1"
    window_id: str
    status: SlicePlanStatus
    source_event_count: int
    partition_count: int
    partitions: tuple[SlicePartition, ...] = ()
    largest_partition_event_count: int = 0
    cross_partition_obligation_ids: tuple[str, ...] = ()
    reason: str
    complete: bool = False

    @model_validator(mode="after")
    def _validate_plan(self) -> "SlicePlan":
        if self.source_event_count < 0 or self.partition_count < 0:
            raise ValueError("slice plan counts cannot be negative")
        if self.partition_count != len(self.partitions):
            raise ValueError("partition_count does not match partitions")
        if self.complete and self.status is not SlicePlanStatus.SPLIT_PROVEN:
            raise ValueError("only a proven split may be complete")
        if self.status is SlicePlanStatus.NO_SAFE_SPLIT and self.partition_count > 1:
            raise ValueError("no-safe-split cannot contain multiple partitions")
        return self


class SlicePlanReport(StrictModel):
    """整条 trace 的保守分解计划；不含 checker verdict。"""

    schema_version: str = "slice-plan-report-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    plans: tuple[SlicePlan, ...] = ()
    reasons: tuple[str, ...] = ()


def stable_obligation_id(
    kind: SliceObligationKind,
    event_ids: tuple[str, ...],
    detail: str,
) -> str:
    """用窗口事实生成稳定 ID，避免依赖遍历顺序或 Python 对象地址。"""

    material = "|".join((kind.value, *event_ids, detail))
    return f"ob-{sha256(material.encode('utf-8')).hexdigest()[:24]}"


__all__ = [
    "CandidateSlice",
    "SliceCandidateGroup",
    "SliceCandidateReport",
    "SliceCandidateStatus",
    "SlicePlanStatus",
    "SliceObligation",
    "SliceObligationKind",
    "SliceRemovalLedgerEntry",
    "SlicePartition",
    "SlicePlan",
    "SlicePlanReport",
    "stable_obligation_id",
]
