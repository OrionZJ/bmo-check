"""真实 ELF 的 critical-event conformance 检查。

fixture 只声明要验证的事件；恢复报告仍由普通 static pipeline 产生。对齐器
不按 benchmark 名称筛选事件，找不到唯一的线程、指令或对象时明确返回
``UNKNOWN``，避免把 harness 访问误当成 litmus 本体。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from bmo_check_static.model import EventKind, MemoryEvent, Ordering, ProgramSliceReport

from .model import CriticalEvent, LitmusCase


class ConformanceStatus(StrEnum):
    MATCHED = "MATCHED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class CriticalEventMatch:
    """一个 fixture event 与恢复事件的稳定对应关系。"""

    label: str
    event_id: str
    thread_role: str
    pc: int


@dataclass(frozen=True, slots=True)
class ConformanceResult:
    """ELF recovery 是否覆盖 fixture 声明的 critical event。"""

    case_id: str
    status: ConformanceStatus
    matches: tuple[CriticalEventMatch, ...] = ()
    missing_labels: tuple[str, ...] = ()
    ambiguous_labels: tuple[str, ...] = ()
    ordering_errors: tuple[str, ...] = ()
    object_errors: tuple[str, ...] = ()
    recovery_unknowns: tuple[str, ...] = ()
    extra_event_count: int = 0
    extra_event_ids: tuple[str, ...] = ()

    @property
    def critical_events_aligned(self) -> bool:
        """指令、线程和程序顺序已封闭，独立于对象身份缺口。"""

        return not (
            self.missing_labels
            or self.ambiguous_labels
            or self.ordering_errors
        ) and bool(self.matches)

    @property
    def critical_events_complete(self) -> bool:
        """critical 对齐和静态对象身份都已封闭。"""

        return self.critical_events_aligned and not self.object_errors

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(
            [
                *(f"missing critical event: {label}" for label in self.missing_labels),
                *(
                    f"ambiguous critical event: {label}"
                    for label in self.ambiguous_labels
                ),
                *self.ordering_errors,
                *self.object_errors,
                *self.recovery_unknowns,
            ]
        )


_EVENT_KINDS = {
    "Load": EventKind.LOAD,
    "Store": EventKind.STORE,
    "AtomicRMW": EventKind.ATOMIC_RMW,
    "LFENCE": EventKind.FENCE,
    "SFENCE": EventKind.FENCE,
    "MFENCE": EventKind.FENCE,
}


def _kind_matches(critical: CriticalEvent, event: MemoryEvent) -> bool:
    expected = _EVENT_KINDS[critical.kind.value]
    if event.kind != expected:
        return False
    fence_ordering = {
        "LFENCE": Ordering.FENCE_RR,
        "SFENCE": Ordering.FENCE_WW,
        "MFENCE": Ordering.FULL,
    }.get(critical.kind.value)
    return fence_ordering is None or event.source_ordering == fence_ordering


def _address_identity(event: MemoryEvent) -> tuple[object, ...] | None:
    address = event.address
    if address is None:
        return None
    return (
        event.module_sha256,
        address.kind.value,
        address.base,
        address.offset,
        address.expression,
        address.thread_coefficient,
        address.index_coefficient,
        address.index_lower,
        address.index_upper,
        address.thread_lower,
        address.thread_upper,
    )


def _reachable(graph: dict[str, set[str]], source: str, target: str) -> bool:
    pending = [source]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == target:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(graph.get(current, ()))
    return False


def _candidate_events(
    critical: CriticalEvent,
    events: tuple[MemoryEvent, ...],
    role_ids: tuple[str, ...],
    role_entry_pcs: dict[str, frozenset[int]],
) -> tuple[MemoryEvent, ...]:
    if critical.thread_entry_pc is None:
        if critical.thread >= len(role_ids):
            return ()
        candidate_roles = (role_ids[critical.thread],)
    else:
        # 线程角色的列表顺序会因 CFG 新增或恢复差异而变化。用已经恢复的
        # ELF 入口 PC 绑定角色，避免把 harness 线程按列表位置误认成 worker。
        candidate_roles = tuple(
            role_id
            for role_id in role_ids
            if critical.thread_entry_pc in role_entry_pcs.get(role_id, frozenset())
        )
    return tuple(
        event
        for event in events
        if event.thread_role in candidate_roles
        and _kind_matches(critical, event)
        and (
            critical.width is None
            or event.size == critical.width
        )
        and (
            critical.instruction_pc is None
            or event.pc == critical.instruction_pc
        )
        and (
            critical.operand_index is None
            or event.operand_index == critical.operand_index
        )
    )


def align_critical_events(
    case: LitmusCase,
    report: ProgramSliceReport,
    *,
    max_extra_event_ids: int = 32,
) -> ConformanceResult:
    """在普通 static recovery 结果中寻找 fixture 声明的 critical events。"""

    recovery = report.recovery
    thread_report = recovery.thread_roles
    if thread_report is None:
        return ConformanceResult(
            case_id=case.case_id,
            status=ConformanceStatus.UNKNOWN,
            recovery_unknowns=("thread recovery report is missing",),
        )
    role_ids = tuple(role.id for role in thread_report.roles)
    role_entry_pcs = {
        role.id: frozenset(target.pc for target in role.start_targets.known_targets)
        for role in thread_report.roles
    }
    events = report.shared_slice.events
    matches: dict[str, MemoryEvent] = {}
    missing: list[str] = []
    ambiguous: list[str] = []
    for critical in case.critical_events:
        candidates = _candidate_events(critical, events, role_ids, role_entry_pcs)
        if len(candidates) == 1:
            matches[critical.label] = candidates[0]
        elif not candidates:
            missing.append(critical.label)
        else:
            ambiguous.append(critical.label)

    ordering_errors: list[str] = []
    graph: dict[str, set[str]] = {}
    for edge in report.shared_slice.program_order:
        graph.setdefault(edge.source_event, set()).add(edge.target_event)
    for edge in case.program_order:
        source = matches.get(edge.source)
        target = matches.get(edge.target)
        if source is None or target is None:
            continue
        if source.thread_role != target.thread_role or not _reachable(
            graph, source.id, target.id
        ):
            ordering_errors.append(
                f"program-order edge is not recovered: {edge.source} -> {edge.target}"
            )
    for thread in sorted({event.thread for event in case.critical_events}):
        ordered = sorted(
            (event for event in case.critical_events if event.thread == thread),
            key=lambda event: event.ordinal,
        )
        for first, second in zip(ordered, ordered[1:], strict=False):
            source = matches.get(first.label)
            target = matches.get(second.label)
            if source is None or target is None:
                continue
            if source.thread_role != target.thread_role or not _reachable(
                graph, source.id, target.id
            ):
                ordering_errors.append(
                    f"ordinal order is not recovered: {first.label} -> {second.label}"
                )

    object_errors: list[str] = []
    object_identities: dict[str, tuple[object, ...]] = {}
    reverse_objects: dict[tuple[object, ...], str] = {}
    for critical in case.critical_events:
        event = matches.get(critical.label)
        if event is None or critical.object_label is None:
            continue
        identity = _address_identity(event)
        if identity is None:
            object_errors.append(
                f"critical event has no recoverable object address: {critical.label}"
            )
            continue
        previous = object_identities.get(critical.object_label)
        if previous is not None and previous != identity:
            object_errors.append(
                f"object label maps to multiple recovered objects: {critical.object_label}"
            )
        other_label = reverse_objects.get(identity)
        if other_label is not None and other_label != critical.object_label:
            object_errors.append(
                f"different object labels alias one recovered object: "
                f"{other_label}, {critical.object_label}"
            )
        object_identities[critical.object_label] = identity
        reverse_objects[identity] = critical.object_label

    matched_ids = {event.id for event in matches.values()}
    if len(matched_ids) != len(matches):
        duplicate_ids = tuple(
            sorted(
                event_id
                for event_id in matched_ids
                if sum(value.id == event_id for value in matches.values()) > 1
            )
        )
        ambiguous.extend(
            label
            for label, event in matches.items()
            if event.id in duplicate_ids
        )
        for label in tuple(ambiguous):
            matches.pop(label, None)
        matched_ids = {event.id for event in matches.values()}
    extra = tuple(event.id for event in events if event.id not in matched_ids)
    recovery_unknowns = tuple(
        f"{unknown.kind.value}: {unknown.reason}"
        for unknown in (*recovery.unknowns, *report.unknowns)
    )
    status = (
        ConformanceStatus.MATCHED
        if not missing
        and not ambiguous
        and not ordering_errors
        and not object_errors
        and not recovery_unknowns
        else ConformanceStatus.UNKNOWN
    )
    ordered_matches = tuple(
        CriticalEventMatch(
            label=critical.label,
            event_id=matches[critical.label].id,
            thread_role=matches[critical.label].thread_role or "<unknown>",
            pc=matches[critical.label].pc,
        )
        for critical in case.critical_events
        if critical.label in matches
    )
    return ConformanceResult(
        case_id=case.case_id,
        status=status,
        matches=ordered_matches,
        missing_labels=tuple(missing),
        ambiguous_labels=tuple(ambiguous),
        ordering_errors=tuple(dict.fromkeys(ordering_errors)),
        object_errors=tuple(dict.fromkeys(object_errors)),
        recovery_unknowns=tuple(dict.fromkeys(recovery_unknowns)),
        extra_event_count=len(extra),
        extra_event_ids=extra[:max_extra_event_ids],
    )


__all__ = [
    "ConformanceResult",
    "ConformanceStatus",
    "CriticalEventMatch",
    "align_critical_events",
]
