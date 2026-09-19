"""把旧静态切片的关系集合转换成保守的投影账本。"""

from __future__ import annotations

from collections.abc import Mapping

from bmo_check_core import (
    CompletenessState,
    CompletenessStatus,
    MemoryEventId,
    ProjectionLedger,
    ProjectionRelationDisposition,
    ProjectionRelationEntry,
    ProjectionRelationKind,
    RelationId,
)
from bmo_check_static.model import SharedMemorySlice

from .evidence import SliceEvidenceError


def _endpoint(
    legacy_id: str,
    event_identities: Mapping[str, MemoryEventId],
) -> MemoryEventId:
    identity = event_identities.get(legacy_id)
    if identity is None:
        raise SliceEvidenceError(
            f"projection relation references unmapped event {legacy_id!r}"
        )
    return identity


def _relation_ids(
    shared_slice: SharedMemorySlice,
    event_identities: Mapping[str, MemoryEventId],
) -> tuple[tuple[RelationId, ...], tuple[RelationId, ...]]:
    """返回关系 identity 和输入中的重复 identity。"""

    relation_ids: list[RelationId] = []
    duplicates: list[RelationId] = []

    def add(relation_id: RelationId) -> None:
        if relation_id in relation_ids:
            duplicates.append(relation_id)
        else:
            relation_ids.append(relation_id)

    for edge in shared_slice.program_order:
        add(
            RelationId.from_parts(
                ProjectionRelationKind.PROGRAM_ORDER.value,
                (
                    _endpoint(edge.source_event, event_identities),
                    _endpoint(edge.target_event, event_identities),
                ),
                discriminator=f"{edge.thread_role}:{edge.evidence}",
            )
        )
    for conflict in shared_slice.conflicts:
        add(
            RelationId.from_parts(
                ProjectionRelationKind.CONFLICT.value,
                (
                    _endpoint(conflict.first_event, event_identities),
                    _endpoint(conflict.second_event, event_identities),
                ),
                symmetric=True,
                discriminator=(
                    f"{conflict.first_role}:{conflict.second_role}:"
                    f"{conflict.alias.value}:{conflict.same_role_instances}"
                ),
            )
        )
    for edge in shared_slice.synchronization:
        add(
            RelationId.from_parts(
                ProjectionRelationKind.SYNCHRONIZATION.value,
                (
                    _endpoint(edge.source_event, event_identities),
                    _endpoint(edge.target_event, event_identities),
                ),
                discriminator=(
                    f"{edge.kind}:{edge.complete}:"
                    f"{','.join(edge.evidence)}:{edge.reason or ''}"
                ),
            )
        )
    return tuple(relation_ids), tuple(duplicates)


def build_projection_ledger(
    source: SharedMemorySlice,
    projected: SharedMemorySlice,
    *,
    event_identities: Mapping[str, MemoryEventId],
    scope: str,
) -> ProjectionLedger:
    """为一次静态切片投影建立保守的 relation universe。

    旧切片只保存被保留的关系，无法证明被删除的 PO、冲突或同步边仍保持
    source/target legality。因此这一步只登记仍可回查的 retained 关系，
    将其余输入关系留在 ``missing_relation_ids``，而不是猜成
    ``removed_with_proof``。后续 preservation rule 生成后才能闭合这些边。
    """

    if not isinstance(source, SharedMemorySlice) or not isinstance(
        projected, SharedMemorySlice
    ):
        raise SliceEvidenceError("projection ledger expects two SharedMemorySlice values")
    if not isinstance(scope, str) or not scope or "\x00" in scope:
        raise SliceEvidenceError("projection ledger scope must be non-empty")

    source_ids, source_duplicates = _relation_ids(source, event_identities)
    projected_ids, projected_duplicates = _relation_ids(projected, event_identities)
    source_set = set(source_ids)
    projected_set = set(projected_ids)
    retained = source_set & projected_set
    extra = projected_set - source_set
    missing = source_set - projected_set

    reasons: list[str] = []
    if source_duplicates or projected_duplicates:
        reasons.append("relation identity is duplicated")
    if extra:
        reasons.append("projected slice contains a relation outside the source universe")
    if missing:
        reasons.append("projection removed relations without relation-level proof")
    completeness = (
        CompletenessState(CompletenessStatus.COMPLETE, scope)
        if not reasons
        else CompletenessState(
            CompletenessStatus.INCOMPLETE,
            scope,
            reason="; ".join(reasons),
        )
    )
    entries = tuple(
        ProjectionRelationEntry(
            relation_id,
            ProjectionRelationDisposition.RETAINED,
        )
        for relation_id in sorted(retained, key=lambda item: item.value)
    )
    return ProjectionLedger(
        stage=scope,
        input_relation_ids=source_ids,
        entries=entries,
        preservation_rule=None,
        completeness=completeness,
    )


__all__ = ["build_projection_ledger"]
