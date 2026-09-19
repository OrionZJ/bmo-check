"""投影阶段的关系 universe 与完整性账本。

事件被移出切片后，仍可能带走 program-order、conflict 或 synchronization
关系。这个模块只记录这些关系是否逐项被保留、由 proof 移除或仍未闭合；它
不把账本本身当成 legality proof，也不直接产生任何 verdict。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .evidence import RegisteredProofRule
from .identity import EvidenceId, RelationId
from .universe import CompletenessState, CompletenessStatus


class ProjectionRelationKind(StrEnum):
    """当前静态切片需要逐项对账的关系类型。"""

    PROGRAM_ORDER = "program_order"
    CONFLICT = "conflict"
    SYNCHRONIZATION = "synchronization"


class ProjectionRelationDisposition(StrEnum):
    """一个输入关系在投影后的唯一去向。"""

    RETAINED = "retained"
    REMOVED_WITH_PROOF = "removed_with_proof"
    UNRESOLVED = "unresolved"


def _evidence_ids(name: str, values: tuple[EvidenceId, ...]) -> tuple[EvidenceId, ...]:
    raw = tuple(values)
    if any(not isinstance(item, EvidenceId) for item in raw):
        raise ValueError(f"{name} must contain EvidenceId values")
    normalized = tuple(sorted(raw, key=lambda item: item.value))
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{name} contains duplicate identities")
    return normalized


@dataclass(frozen=True, slots=True)
class ProjectionRelationEntry:
    """一个输入关系及其证明或未闭合依据。"""

    relation_id: RelationId
    disposition: ProjectionRelationDisposition
    proof_ids: tuple[EvidenceId, ...] = ()
    unknown_ids: tuple[EvidenceId, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.relation_id, RelationId):
            raise ValueError("relation_id must be a RelationId")
        if not isinstance(self.disposition, ProjectionRelationDisposition):
            raise ValueError("disposition must be a ProjectionRelationDisposition")
        object.__setattr__(self, "proof_ids", _evidence_ids("proof_ids", self.proof_ids))
        object.__setattr__(self, "unknown_ids", _evidence_ids("unknown_ids", self.unknown_ids))
        if self.disposition is ProjectionRelationDisposition.RETAINED and (
            self.proof_ids or self.unknown_ids
        ):
            raise ValueError("retained relation cannot carry removal or unknown evidence")
        if self.disposition is ProjectionRelationDisposition.REMOVED_WITH_PROOF and not self.proof_ids:
            raise ValueError("removed relation requires at least one ProofFact")
        if self.disposition is ProjectionRelationDisposition.REMOVED_WITH_PROOF and self.unknown_ids:
            raise ValueError("removed relation cannot also be unresolved")
        if self.disposition is ProjectionRelationDisposition.UNRESOLVED and not self.unknown_ids:
            raise ValueError("unresolved relation requires at least one UnknownFact")
        if self.disposition is ProjectionRelationDisposition.UNRESOLVED and self.proof_ids:
            raise ValueError("unresolved relation cannot use proof_ids as a substitute")


@dataclass(frozen=True, slots=True)
class ProjectionLedger:
    """投影输入/输出关系 universe 的独立对账值对象。"""

    stage: str
    input_relation_ids: tuple[RelationId, ...]
    entries: tuple[ProjectionRelationEntry, ...]
    preservation_rule: RegisteredProofRule | None
    completeness: CompletenessState

    def __post_init__(self) -> None:
        if not isinstance(self.stage, str) or not self.stage or "\x00" in self.stage:
            raise ValueError("stage must be a non-empty string")
        raw_input_ids = tuple(self.input_relation_ids)
        if any(not isinstance(item, RelationId) for item in raw_input_ids):
            raise ValueError("input_relation_ids must contain RelationId values")
        input_ids = tuple(sorted(raw_input_ids, key=lambda item: item.value))
        if len(input_ids) != len(set(input_ids)):
            raise ValueError("input_relation_ids contains duplicate identities")
        object.__setattr__(self, "input_relation_ids", input_ids)
        if any(not isinstance(item, ProjectionRelationEntry) for item in self.entries):
            raise ValueError("entries must contain ProjectionRelationEntry values")
        entries = tuple(sorted(self.entries, key=lambda item: item.relation_id.value))
        entry_ids = tuple(item.relation_id for item in entries)
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("entries contain duplicate relation identities")
        if not set(entry_ids).issubset(set(input_ids)):
            raise ValueError("entries contain relations outside input_relation_ids")
        object.__setattr__(self, "entries", entries)
        if self.preservation_rule is not None and not isinstance(
            self.preservation_rule, RegisteredProofRule
        ):
            raise ValueError("preservation_rule must be a RegisteredProofRule")
        if any(
            item.disposition is ProjectionRelationDisposition.REMOVED_WITH_PROOF
            for item in entries
        ) and self.preservation_rule is None:
            raise ValueError("removed relations require a preservation rule")
        if not isinstance(self.completeness, CompletenessState):
            raise ValueError("completeness must be a CompletenessState")
        if (
            self.completeness.status is CompletenessStatus.COMPLETE
            and set(entry_ids) != set(input_ids)
        ):
            raise ValueError("complete ledger must account for every input relation")

    @property
    def retained_relation_ids(self) -> tuple[RelationId, ...]:
        return tuple(
            item.relation_id
            for item in self.entries
            if item.disposition is ProjectionRelationDisposition.RETAINED
        )

    @property
    def removed_relation_ids(self) -> tuple[RelationId, ...]:
        return tuple(
            item.relation_id
            for item in self.entries
            if item.disposition is ProjectionRelationDisposition.REMOVED_WITH_PROOF
        )

    @property
    def unresolved_relation_ids(self) -> tuple[RelationId, ...]:
        return tuple(
            item.relation_id
            for item in self.entries
            if item.disposition is ProjectionRelationDisposition.UNRESOLVED
        )

    @property
    def missing_relation_ids(self) -> tuple[RelationId, ...]:
        accounted = {item.relation_id for item in self.entries}
        return tuple(item for item in self.input_relation_ids if item not in accounted)


__all__ = [
    "ProjectionLedger",
    "ProjectionRelationDisposition",
    "ProjectionRelationEntry",
    "ProjectionRelationKind",
]
