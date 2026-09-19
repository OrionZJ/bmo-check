"""proof obligation 的 canonical inventory。

obligation 不是 ProofFact，也不是 verdict。它只列出当前 checker 必须闭合的
命题；是否被静态规则证明由后续 evidence/closure 层决定。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from .contracts.semantics import (
    ExecutionRelations,
    MemoryAccessKind,
    MemoryOperation,
    MemoryRelation,
    RelationKind,
)
from .identity import EvidenceId, MemoryEventId, ObligationId, PropositionId, StableId
from .universe import (
    CompletenessState,
    CompletenessStatus,
    EventDisposition,
    EventUniverseLedger,
)


class ObligationKind(StrEnum):
    """当前 portability checker 的三类最小 obligation。"""

    # conflict obligation 要求通信候选的 object/range 关系闭合。
    CONFLICT = "conflict"
    # execution obligation 要求固定或枚举的 memory relations 可回放。
    EXECUTION = "execution"
    # projection obligation 要求删除事件保持 source/target legality。
    PROJECTION = "projection"


class ObligationMatchStatus(StrEnum):
    """Unknown 与 obligation 的 identity 绑定结果。"""

    # proposition 和 scope 都相同，可以进入后续显式 discharge 检查。
    MATCH = "match"
    # 旧 Unknown 缺少 proposition，只能保留为 incomplete。
    INCOMPLETE = "incomplete"
    # 两个 typed identity 明确指向不同命题，不能互相关闭。
    MISMATCH = "mismatch"


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
class UnknownObligationMatch:
    """记录 Unknown 和 obligation 是否绑定到同一稳定命题。"""

    # status 是 identity 检查结果，不是 SAFE/UNKNOWN verdict。
    status: ObligationMatchStatus
    # reason 说明 legacy 缺失还是 typed identity 冲突。
    reason: str


def match_unknown_to_obligation(
    unknown: object,
    obligation: ProofObligation,
) -> UnknownObligationMatch:
    """只按 proposition_id 和 scope 匹配 Unknown，不从旧字段猜命题。

    这是 evidence/obligation 的桥接检查，不执行 proof discharge，也不接受
    ObservedFact 或 DiagnosticHint 作为替代命题。
    """

    from .evidence import UnknownFact

    if not isinstance(unknown, UnknownFact):
        return UnknownObligationMatch(
            ObligationMatchStatus.MISMATCH,
            "binding subject is not an UnknownFact",
        )
    if unknown.proposition is None:
        return UnknownObligationMatch(
            ObligationMatchStatus.INCOMPLETE,
            "legacy UnknownFact has no typed proposition",
        )
    if unknown.scope != obligation.scope or unknown.proposition.scope != obligation.scope:
        return UnknownObligationMatch(
            ObligationMatchStatus.MISMATCH,
            "Unknown and obligation scopes differ",
        )
    if unknown.proposition.id != obligation.proposition_id:
        return UnknownObligationMatch(
            ObligationMatchStatus.MISMATCH,
            "Unknown proposition does not match obligation proposition",
        )
    return UnknownObligationMatch(ObligationMatchStatus.MATCH, "stable proposition matches")


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


def build_execution_obligation_inventory(
    operations: Mapping[str, MemoryOperation],
    relations: ExecutionRelations,
    *,
    event_ids: Mapping[str, MemoryEventId],
    scope: str,
) -> ObligationInventory:
    """按同一规则枚举 fixed execution 的 RF/CO/FR obligations。

    static 与 dynamic 只能把自己的事件归一化为 ``MemoryOperation``，不能各自
    发明一套 relation completeness 规则。缺少稳定 event identity、RF/CO/FR
    任一端点或完整 relation universe 时，inventory 保留为 INCOMPLETE；这里
    不根据一次执行的值或 covered event 数量猜测缺失命题。
    """

    issues: set[str] = set()
    if not isinstance(relations, ExecutionRelations):
        issues.add("execution relations are not typed")
        relations = ExecutionRelations()

    normalized_operations: dict[str, MemoryOperation] = {}
    for key, operation in operations.items():
        if not isinstance(key, str) or not isinstance(operation, MemoryOperation):
            issues.add("operation universe contains an untyped entry")
            continue
        if key != operation.event_id:
            issues.add(f"operation key does not match event id {key!r}")
            continue
        if operation.event_id in normalized_operations:
            issues.add(f"duplicate operation identity {operation.event_id!r}")
            continue
        normalized_operations[key] = operation

    stable_subjects: dict[str, MemoryEventId] = {}
    for event_id in normalized_operations:
        subject = event_ids.get(event_id)
        if not isinstance(subject, MemoryEventId):
            issues.add(f"missing canonical subject for {event_id!r}")
        elif subject in stable_subjects.values():
            issues.add(f"duplicate canonical subject for {event_id!r}")
        else:
            stable_subjects[event_id] = subject

    if not relations.all_exact_width:
        issues.add("relation set contains a non-exact-width proposition")

    reads = {
        event_id
        for event_id, operation in normalized_operations.items()
        if operation.kind in {MemoryAccessKind.LOAD, MemoryAccessKind.RMW}
    }
    writes = {
        event_id
        for event_id, operation in normalized_operations.items()
        if operation.kind in {MemoryAccessKind.STORE, MemoryAccessKind.RMW}
    }
    object_by_event = {
        event_id: operation.access.object_id
        for event_id, operation in normalized_operations.items()
    }
    obligations: list[ProofObligation] = []
    obligation_propositions: set[PropositionId] = set()

    def add_obligation(relation: MemoryRelation) -> None:
        if relation.proposition_id in obligation_propositions:
            return
        subject_ids: list[MemoryEventId] = []
        if relation.source is not None:
            source = normalized_operations.get(relation.source.event_id)
            if source != relation.source:
                issues.add(
                    f"relation source is outside operation universe: {relation.source.event_id!r}"
                )
            source_id = stable_subjects.get(relation.source.event_id)
            if source_id is None:
                issues.add(f"missing canonical subject for {relation.source.event_id!r}")
            else:
                subject_ids.append(source_id)
        target = normalized_operations.get(relation.target.event_id)
        if target != relation.target:
            issues.add(
                f"relation target is outside operation universe: {relation.target.event_id!r}"
            )
        target_id = stable_subjects.get(relation.target.event_id)
        if target_id is None:
            issues.add(f"missing canonical subject for {relation.target.event_id!r}")
        else:
            subject_ids.append(target_id)
        expected_subjects = 1 if relation.source is None else 2
        if len(subject_ids) == expected_subjects:
            obligations.append(
                ProofObligation.create(
                    proposition_id=relation.proposition_id,
                    kind=ObligationKind.EXECUTION,
                    scope=scope,
                    subjects=tuple(subject_ids),
                )
            )
            obligation_propositions.add(relation.proposition_id)

    for relation in (*relations.read_from, *relations.coherence, *relations.from_read):
        add_obligation(relation)

    rf_targets = {relation.target.event_id for relation in relations.read_from}
    if rf_targets != reads:
        issues.add("read_from obligations do not cover every load/RMW")

    stores_by_object: dict[str, set[str]] = {}
    for event_id in writes:
        stores_by_object.setdefault(object_by_event[event_id], set()).add(event_id)
    co_pairs = {
        (relation.source.event_id, relation.target.event_id)
        for relation in relations.coherence
        if relation.source is not None
    }
    expected_co_count = sum(
        len(store_ids) * (len(store_ids) - 1) // 2
        for store_ids in stores_by_object.values()
    )
    if len(co_pairs) != expected_co_count:
        issues.add("coherence obligations do not cover every store pair")
    if any(
        left not in writes
        or right not in writes
        or object_by_event[left] != object_by_event[right]
        for left, right in co_pairs
    ):
        issues.add("coherence obligation references a wrong or unknown object")

    expected_from_read: set[tuple[str, str]] = set()
    if not issues:
        for object_id, store_ids in stores_by_object.items():
            incoming = {store_id: 0 for store_id in store_ids}
            outgoing: dict[str, set[str]] = {store_id: set() for store_id in store_ids}
            for before, after in co_pairs:
                if before in store_ids and after in store_ids:
                    outgoing[before].add(after)
                    incoming[after] += 1
            order: list[str] = []
            ready = sorted(store_id for store_id, degree in incoming.items() if degree == 0)
            while ready:
                current = ready.pop(0)
                order.append(current)
                for successor in sorted(outgoing[current]):
                    incoming[successor] -= 1
                    if incoming[successor] == 0:
                        ready.append(successor)
                        ready.sort()
            if len(order) != len(store_ids):
                issues.add(f"coherence relation is not a total order for {object_id!r}")
                continue
            for relation in relations.read_from:
                target = relation.target.event_id
                if target not in reads or object_by_event.get(target) != object_id:
                    continue
                source = relation.source.event_id if relation.source is not None else None
                if source is not None and source not in order:
                    issues.add(f"read_from source is outside coherence order for {object_id!r}")
                    continue
                later = order[order.index(source) + 1 :] if source is not None else order
                expected_from_read.update((target, store_id) for store_id in later)

    actual_from_read = {
        (relation.source.event_id, relation.target.event_id)
        for relation in relations.from_read
        if relation.source is not None
    }
    if not issues:
        if actual_from_read and actual_from_read != expected_from_read:
            issues.add("from_read obligations do not match the RF/CO assignment")
        else:
            # FR 是由 RF/CO 唯一导出的 execution obligation；调用者可以省略
            # 它的 legacy 输入，但不能因此让 verifier 看不见这些命题。
            for read_id, store_id in sorted(expected_from_read):
                add_obligation(
                    MemoryRelation(
                        RelationKind.FROM_READ,
                        normalized_operations[read_id],
                        normalized_operations[store_id],
                    )
                )

    completeness = (
        CompletenessState(CompletenessStatus.COMPLETE, scope)
        if not issues
        else CompletenessState(
            CompletenessStatus.INCOMPLETE,
            scope,
            reason="; ".join(sorted(issues)),
        )
    )
    return ObligationInventory(
        scope=scope,
        obligations=tuple(obligations),
        completeness=completeness,
    )


def build_conflict_obligation_inventory(
    pairs: Iterable[tuple[MemoryEventId, MemoryEventId]],
    *,
    event_universe: EventUniverseLedger,
    candidate_completeness: CompletenessState,
    scope: str,
) -> ObligationInventory:
    """为通信候选建立 conflict obligations，并保留候选枚举完整性。

    Conflict candidate 是对称命题，端点按稳定 ID 规范化；它不能因为一侧
    没有出现在当前列表而被解释为不存在。候选扫描或输入 event universe
    未闭合时，已看到的 obligations 仍可保留，但 inventory 必须是 INCOMPLETE。
    """

    issues: set[str] = set()
    if not isinstance(event_universe, EventUniverseLedger):
        issues.add("conflict event universe is not typed")
        universe_ids: set[MemoryEventId] = set()
    else:
        universe_ids = set(event_universe.input_event_ids)
        if event_universe.completeness.status is not CompletenessStatus.COMPLETE:
            issues.add(
                "conflict event universe is "
                f"{event_universe.completeness.status.value.lower()}"
            )
    if not isinstance(candidate_completeness, CompletenessState):
        issues.add("conflict candidate completeness is not typed")
    elif candidate_completeness.status is not CompletenessStatus.COMPLETE:
        issues.add(
            "conflict candidate enumeration is "
            f"{candidate_completeness.status.value.lower()}"
        )

    obligations: list[ProofObligation] = []
    seen_pairs: set[tuple[str, str]] = set()
    for pair in pairs:
        if (
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not all(isinstance(endpoint, MemoryEventId) for endpoint in pair)
        ):
            issues.add("conflict candidate contains an untyped endpoint")
            continue
        first, second = pair
        if first not in universe_ids or second not in universe_ids:
            issues.add("conflict candidate references an event outside its universe")
        key = tuple(sorted((first.value, second.value)))
        if key in seen_pairs:
            issues.add("conflict candidate universe contains a duplicate pair")
            continue
        seen_pairs.add(key)
        ordered = tuple(sorted((first, second), key=lambda item: item.value))
        obligations.append(
            ProofObligation.create(
                proposition_id=PropositionId.from_parts("conflict", key),
                kind=ObligationKind.CONFLICT,
                scope=scope,
                subjects=ordered if first != second else (first,),
            )
        )

    completeness = (
        CompletenessState(CompletenessStatus.COMPLETE, scope)
        if not issues
        else CompletenessState(
            CompletenessStatus.INCOMPLETE,
            scope,
            reason="; ".join(sorted(issues)),
        )
    )
    return ObligationInventory(
        scope=scope,
        obligations=tuple(obligations),
        completeness=completeness,
    )


def build_projection_obligation_inventory(
    event_universe: EventUniverseLedger,
    *,
    scope: str,
) -> ObligationInventory:
    """把 event-universe 中的 removed-with-proof 逐项变成 projection obligation。"""

    issues: set[str] = set()
    if not isinstance(event_universe, EventUniverseLedger):
        issues.add("projection event universe is not typed")
        entries = ()
    else:
        entries = event_universe.entries
        if event_universe.completeness.status is not CompletenessStatus.COMPLETE:
            issues.add(
                "projection event universe is "
                f"{event_universe.completeness.status.value.lower()}"
            )

    obligations: list[ProofObligation] = []
    for entry in entries:
        if entry.disposition is not EventDisposition.REMOVED_WITH_PROOF:
            continue
        if not entry.proof_ids:
            issues.add(f"removed event {entry.event_id.value!r} has no proof")
            continue
        proof_terms = tuple(proof.value for proof in entry.proof_ids)
        obligations.append(
            ProofObligation.create(
                proposition_id=PropositionId.from_parts(
                    "projection",
                    (entry.event_id.value, *proof_terms),
                ),
                kind=ObligationKind.PROJECTION,
                scope=scope,
                subjects=(entry.event_id, *entry.proof_ids),
            )
        )

    completeness = (
        CompletenessState(CompletenessStatus.COMPLETE, scope)
        if not issues
        else CompletenessState(
            CompletenessStatus.INCOMPLETE,
            scope,
            reason="; ".join(sorted(issues)),
        )
    )
    return ObligationInventory(
        scope=scope,
        obligations=tuple(obligations),
        completeness=completeness,
    )


__all__ = [
    "ObligationInventory",
    "ObligationKind",
    "ObligationMatchStatus",
    "ProofObligation",
    "UnknownObligationMatch",
    "match_unknown_to_obligation",
    "build_execution_obligation_inventory",
    "build_conflict_obligation_inventory",
    "build_projection_obligation_inventory",
]
