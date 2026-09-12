"""为 E2.5 固定执行检查建立只读的 critical-event 投影。

真实 ELF 的完整 shared slice 必须保留 harness、未知 effect 和所有静态证据。
这里仅把 manifest 已经逐一对齐的事件复制成一个小模型输入，方便回答
``po/rf/co`` 的表征问题；投影不回写 recovery，也不能进入 SAFE 证明闭包。
"""

from __future__ import annotations

from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    MemoryEvent,
    ProgramOrderEdge,
    ProgramSliceReport,
    PruningCoverage,
    SharedMemorySlice,
)

from .conformance import ConformanceResult, ConformanceStatus
from .model import CriticalEvent, LitmusCase


class CriticalProjectionError(ValueError):
    """critical 事件无法形成封闭的 evaluation-only 固定执行输入。"""


def _project_event(event: MemoryEvent, critical: CriticalEvent) -> MemoryEvent:
    address = event.address
    if critical.object_label is not None:
        # 地址标签只为这次关系检查提供同一对象的规范名字；它不是从运行时
        # 地址推导出的静态别名证明，原始事件仍保留在完整 recovery 报告里。
        address = AbstractAddress(
            kind=AddressKind.GLOBAL,
            base=f"e2.5-object:{critical.object_label}",
            offset=0,
            provenance={
                "evaluation_only": True,
                "original_address_kind": (
                    event.address.kind.value if event.address is not None else None
                ),
                "original_event_id": event.id,
            },
        )
    provenance = dict(event.provenance)
    provenance.update(
        {
            "evaluation_only": True,
            "fixture_label": critical.label,
            "original_event_id": event.id,
        }
    )
    return event.model_copy(update={"address": address, "provenance": provenance})


def project_critical_slice(
    case: LitmusCase,
    conformance: ConformanceResult,
    report: ProgramSliceReport,
) -> SharedMemorySlice:
    """复制已匹配 critical events，并用 fixture 关系建立最小求解窗口。

    `conformance` 必须已经确认每个标签只对应一个恢复事件。投影只用于
    execution-legality characterization；任何缺失、角色冲突或悬空关系都
    抛出错误，由上层把该 case 保持为 `UNKNOWN`。
    """

    if conformance.status is not ConformanceStatus.MATCHED:
        raise CriticalProjectionError("cannot project a non-matched conformance")
    if report.shared_slice is None:
        raise CriticalProjectionError("recovery report has no shared slice")
    matched = {match.label: match.event_id for match in conformance.matches}
    event_by_id = {event.id: event for event in report.shared_slice.events}
    critical_by_label = {event.label: event for event in case.critical_events}
    if set(matched) != set(critical_by_label):
        missing = sorted(set(critical_by_label) - set(matched))
        extra = sorted(set(matched) - set(critical_by_label))
        raise CriticalProjectionError(
            f"critical match set differs from fixture (missing={missing}, extra={extra})"
        )

    projected: list[MemoryEvent] = []
    for critical in case.critical_events:
        event_id = matched[critical.label]
        event = event_by_id.get(event_id)
        if event is None:
            raise CriticalProjectionError(
                f"matched event is absent from shared slice: {event_id}"
            )
        projected.append(_project_event(event, critical))

    projected_by_label = {
        critical.label: event
        for critical, event in zip(case.critical_events, projected, strict=True)
    }
    edges: dict[tuple[str, str], ProgramOrderEdge] = {}

    def add_edge(source: CriticalEvent, target: CriticalEvent, evidence: str) -> None:
        if source.thread != target.thread:
            raise CriticalProjectionError(
                f"program-order relation crosses fixture threads: {source.label} -> {target.label}"
            )
        source_event = projected_by_label[source.label]
        target_event = projected_by_label[target.label]
        if source_event.thread_role != target_event.thread_role:
            raise CriticalProjectionError(
                f"critical events map to different recovered roles: {source.label} -> {target.label}"
            )
        key = (source_event.id, target_event.id)
        edges.setdefault(
            key,
            ProgramOrderEdge(
                source_event=source_event.id,
                target_event=target_event.id,
                thread_role=source_event.thread_role or "<unknown>",
                evidence=evidence,
            ),
        )

    by_thread: dict[int, list[CriticalEvent]] = {}
    for critical in case.critical_events:
        by_thread.setdefault(critical.thread, []).append(critical)
    for thread_events in by_thread.values():
        ordered = sorted(thread_events, key=lambda event: event.ordinal)
        for source, target in zip(ordered, ordered[1:], strict=False):
            add_edge(source, target, "fixture ordinal order (evaluation only)")
    for relation in case.program_order:
        add_edge(
            critical_by_label[relation.source],
            critical_by_label[relation.target],
            "fixture program order (evaluation only)",
        )

    coverage = PruningCoverage(
        total_events=len(projected),
        remaining_shared_events=len(projected),
        unknown_events=0,
    )
    return SharedMemorySlice(
        events=tuple(projected),
        program_order=tuple(edges.values()),
        conflicts=(),
        synchronization=(),
        proof_objects=(),
        coverage=coverage,
        unknowns=(),
    )


__all__ = ["CriticalProjectionError", "project_critical_slice"]
