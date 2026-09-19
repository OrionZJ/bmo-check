"""把旧共享切片的删除关系转换为 canonical proof sidecar。"""

from __future__ import annotations

from dataclasses import dataclass

from bmo_check_core import (
    CompletenessState,
    CompletenessStatus,
    EventDisposition,
    EventUniverseEntry,
    EventUniverseLedger,
    EvidenceId,
    EvidenceLedger,
    MemoryEventId,
    ProducerId,
    ProofFact,
    RemovalDecision,
)
from bmo_check_static.analysis.evidence import StaticMemoryEventEvidence
from bmo_check_static.analysis.shared_state_evidence import StaticSharedStateEvidence
from bmo_check_static.model import SharedMemorySlice
from bmo_check_static.threading.evidence import StaticThreadEvidence

from .slice_builder import build_shared_memory_slice


class SliceEvidenceError(ValueError):
    """旧切片无法无损绑定到 canonical 事件或 proof 时抛出的错误。"""


@dataclass(frozen=True, slots=True)
class SliceProofLink:
    # legacy_id 保留旧 SharedMemorySlice 中 ProofObject 的回查键。
    legacy_id: str
    # canonical_id 指向 ledger 中真正可进入 proof closure 的 ProofFact。
    canonical_id: EvidenceId

    def __post_init__(self) -> None:
        if not self.legacy_id:
            raise SliceEvidenceError("legacy proof id must be non-empty")
        if not isinstance(self.canonical_id, EvidenceId):
            raise SliceEvidenceError("slice proof link must contain EvidenceId")


@dataclass(frozen=True, slots=True)
class StaticSliceEvidence:
    # report 保留旧切片事件、冲突和 proof object，供差分测试使用。
    report: SharedMemorySlice
    # ledger 合并输入 sidecar，并追加本次切片生成的 ProofFact。
    ledger: EvidenceLedger
    # proof_links 显式保留旧 proof id 到 canonical proof 的映射。
    proof_links: tuple[SliceProofLink, ...] = ()
    # removal_decisions 逐事件记录删除依据，不能由批量计数推导。
    removal_decisions: tuple[RemovalDecision, ...] = ()
    # event_universe 是新 producer 的逐事件对账；None 只允许旧 bridge 使用。
    event_universe: EventUniverseLedger | None = None

    @property
    def proof_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            sorted(
                {link.canonical_id for link in self.proof_links},
                key=lambda item: item.value,
            )
        )


def build_shared_memory_slice_with_evidence(
    memory_events: StaticMemoryEventEvidence,
    shared_state: StaticSharedStateEvidence,
    threads: StaticThreadEvidence,
    *,
    scope: str = "static.slice",
) -> StaticSliceEvidence:
    """在保留旧切片结果的同时建立 ProofFact/RemovalDecision 旁路。"""

    if not scope:
        raise SliceEvidenceError("slice evidence scope must be non-empty")
    report = build_shared_memory_slice(
        memory_events.report,
        shared_state.report,
        threads.report,
    )
    ledger = EvidenceLedger()
    for source in (memory_events.ledger, shared_state.ledger, threads.ledger):
        for node in source.nodes():
            ledger.add(node)

    event_ids = {
        link.legacy_id: link.canonical_id for link in memory_events.event_links
    }
    if len(event_ids) != len(memory_events.event_links):
        raise SliceEvidenceError("memory event identity links contain duplicate IDs")

    proof_links: list[SliceProofLink] = []
    proof_by_legacy: dict[str, EvidenceId] = {}
    for proof in report.proof_objects:
        covered: list[MemoryEventId] = []
        for legacy_event_id in proof.event_ids:
            event_id = event_ids.get(legacy_event_id)
            if event_id is None:
                raise SliceEvidenceError(
                    f"proof {proof.id!r} references an unmapped event {legacy_event_id!r}"
                )
            covered.append(event_id)
        canonical = ProofFact.create(
            schema_version="static-slice-1",
            producer=ProducerId("bmo_check_static.slicing", "c6"),
            subject=None,
            rule=proof.reason.value,
            scope=scope,
            covered_events=tuple(covered),
        )
        ledger.add(canonical)
        link = SliceProofLink(proof.id, canonical.id)
        proof_links.append(link)
        if proof.id in proof_by_legacy:
            raise SliceEvidenceError(f"duplicate legacy proof id {proof.id!r}")
        proof_by_legacy[proof.id] = canonical.id

    decisions: list[RemovalDecision] = []
    for legacy_event_id in shared_state.report.removed_event_ids:
        event_id = event_ids.get(legacy_event_id)
        if event_id is None:
            raise SliceEvidenceError(
                f"removed event {legacy_event_id!r} has no canonical identity"
            )
        covering = tuple(
            link.canonical_id
            for link, proof in zip(proof_links, report.proof_objects)
            if legacy_event_id in proof.event_ids
        )
        if not covering:
            raise SliceEvidenceError(
                f"removed event {legacy_event_id!r} has no canonical proof"
            )
        decisions.append(
            RemovalDecision(
                event_id=event_id,
                proof_id=covering[0],
                scope=scope,
            )
        )

    removed_by_event = {
        decision.event_id: decision.proof_id
        for decision in decisions
    }
    legacy_by_canonical = {
        link.canonical_id: link.legacy_id for link in memory_events.event_links
    }
    retained_legacy = {event.id for event in report.events}
    unknown_legacy: set[str] = set()
    for unknown in memory_events.report.unknowns:
        event_id = unknown.details.get("event_id")
        if isinstance(event_id, str):
            unknown_legacy.add(event_id)
        event_ids = unknown.details.get("event_ids")
        if isinstance(event_ids, list):
            unknown_legacy.update(
                value for value in event_ids if isinstance(value, str)
            )

    universe_entries: list[EventUniverseEntry] = []
    missing_reasons: set[str] = set()
    for canonical_id in memory_events.event_ids:
        legacy_id = legacy_by_canonical[canonical_id]
        if legacy_id in unknown_legacy:
            # canonical UnknownFact 当前没有 event subject；省略 entry 比猜一个
            # UnknownFact 更安全，ledger 会把它暴露为 missing event。
            missing_reasons.add("legacy Unknown lacks a unique canonical event subject")
            continue
        if canonical_id in removed_by_event:
            universe_entries.append(
                EventUniverseEntry(
                    canonical_id,
                    EventDisposition.REMOVED_WITH_PROOF,
                    proof_ids=(removed_by_event[canonical_id],),
                )
            )
        elif legacy_id in retained_legacy:
            universe_entries.append(
                EventUniverseEntry(canonical_id, EventDisposition.RETAINED)
            )
        else:
            missing_reasons.add("producer output omitted an unremoved event")

    if memory_events.unknown_ids or shared_state.unknown_ids or missing_reasons:
        reasons = set(missing_reasons)
        if memory_events.unknown_ids:
            reasons.add("memory-event producer has unresolved UnknownFact")
        if shared_state.unknown_ids:
            reasons.add("shared-state producer has unresolved UnknownFact")
        completeness = CompletenessState(
            CompletenessStatus.INCOMPLETE,
            scope,
            reason="; ".join(sorted(reasons)),
        )
    else:
        completeness = CompletenessState(CompletenessStatus.COMPLETE, scope)
    event_universe = EventUniverseLedger(
        stage=scope,
        input_event_ids=memory_events.event_ids,
        entries=tuple(universe_entries),
        completeness=completeness,
    )

    return StaticSliceEvidence(
        report=report,
        ledger=ledger,
        proof_links=tuple(sorted(proof_links, key=lambda item: item.legacy_id)),
        removal_decisions=tuple(
            sorted(
                decisions,
                key=lambda item: (item.event_id.value, item.proof_id.value),
            )
        ),
        event_universe=event_universe,
    )


__all__ = [
    "SliceEvidenceError",
    "SliceProofLink",
    "StaticSliceEvidence",
    "build_shared_memory_slice_with_evidence",
]
