"""proof obligation 的 canonical inventory。

obligation 不是 ProofFact，也不是 verdict。它只列出当前 checker 必须闭合的
命题；是否被静态规则证明由后续 evidence/closure 层决定。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .identity import ObligationId, PropositionId, StableId
from .universe import CompletenessState, CompletenessStatus


class ObligationKind(StrEnum):
    """当前 portability checker 的三类最小 obligation。"""

    # conflict obligation 要求通信候选的 object/range 关系闭合。
    CONFLICT = "conflict"
    # execution obligation 要求固定或枚举的 memory relations 可回放。
    EXECUTION = "execution"
    # projection obligation 要求删除事件保持 source/target legality。
    PROJECTION = "projection"


def _subjects(values: tuple[StableId, ...]) -> tuple[StableId, ...]:
    if any(not isinstance(value, StableId) for value in values):
        raise ValueError("obligation subjects must be StableId values")
    normalized = tuple(sorted(values, key=lambda item: item.value))
    if len(normalized) != len(set(normalized)):
        raise ValueError("obligation subjects contain duplicates")
    return normalized


@dataclass(frozen=True, slots=True)
class ProofObligation:
    """一个需要静态规则闭合的命题。"""

    # id 必须由 create() 按下面字段重算，不能使用遍历序号。
    id: ObligationId
    # proposition_id 指向具体命题；不能用 event identity 代替它。
    proposition_id: PropositionId
    # kind 决定后续 proof rule 应检查冲突、执行还是投影。
    kind: ObligationKind
    # scope 限定 obligation 可以被哪个 binary/slice 关闭。
    scope: str
    # subjects 是稳定 event/object/thread 等实体集合。
    subjects: tuple[StableId, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.id, ObligationId):
            raise ValueError("id must be an ObligationId")
        if not isinstance(self.proposition_id, PropositionId):
            raise ValueError("proposition_id must be a PropositionId")
        if not isinstance(self.kind, ObligationKind):
            raise ValueError("kind must be an ObligationKind")
        if not isinstance(self.scope, str) or not self.scope or "\x00" in self.scope:
            raise ValueError("scope must be a non-empty string")
        object.__setattr__(self, "subjects", _subjects(self.subjects))
        if self.id != self.expected_id():
            raise ValueError("obligation id does not match its canonical content")

    @classmethod
    def create(
        cls,
        *,
        proposition_id: PropositionId,
        kind: ObligationKind,
        scope: str,
        subjects: tuple[StableId, ...] = (),
    ) -> "ProofObligation":
        normalized = _subjects(subjects)
        if not isinstance(proposition_id, PropositionId):
            raise ValueError("proposition_id must be a PropositionId")
        if not isinstance(kind, ObligationKind):
            raise ValueError("kind must be an ObligationKind")
        if not isinstance(scope, str) or not scope or "\x00" in scope:
            raise ValueError("scope must be a non-empty string")
        return cls(
            id=ObligationId.from_parts(
                kind.value,
                scope,
                (proposition_id.value, *(subject.value for subject in normalized)),
            ),
            proposition_id=proposition_id,
            kind=kind,
            scope=scope,
            subjects=normalized,
        )

    def expected_id(self) -> ObligationId:
        return ObligationId.from_parts(
            self.kind.value,
            self.scope,
            (self.proposition_id.value, *(subject.value for subject in self.subjects)),
        )


@dataclass(frozen=True, slots=True)
class ObligationInventory:
    """一个分析阶段必须闭合的 obligation 集合。"""

    # scope 防止不同分析范围的 obligation 被拼在同一份证书中。
    scope: str
    # obligations 是 canonical proposition 的集合，不包含 proof 结论。
    obligations: tuple[ProofObligation, ...]
    # completeness 表示 producer 是否枚举完整，而不是 obligation 是否已证明。
    completeness: CompletenessState

    def __post_init__(self) -> None:
        if not isinstance(self.scope, str) or not self.scope or "\x00" in self.scope:
            raise ValueError("scope must be a non-empty string")
        if not isinstance(self.completeness, CompletenessState):
            raise ValueError("completeness must be a CompletenessState")
        if self.completeness.scope != self.scope:
            raise ValueError("obligation completeness scope must match inventory scope")
        if any(not isinstance(item, ProofObligation) for item in self.obligations):
            raise ValueError("obligations must contain ProofObligation values")
        normalized = tuple(sorted(self.obligations, key=lambda item: item.id.value))
        if len(normalized) != len(set(item.id for item in normalized)):
            raise ValueError("obligations contain duplicate identities")
        if any(item.scope != self.scope for item in normalized):
            raise ValueError("obligation scope does not match inventory scope")
        object.__setattr__(self, "obligations", normalized)

    @property
    def ids(self) -> tuple[ObligationId, ...]:
        return tuple(item.id for item in self.obligations)

    @property
    def is_enumerated(self) -> bool:
        """只说明 inventory producer 完成枚举，不说明命题已经被证明。"""

        return self.completeness.status is CompletenessStatus.COMPLETE


__all__ = ["ObligationInventory", "ObligationKind", "ProofObligation"]
