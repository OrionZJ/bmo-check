from __future__ import annotations

from collections import Counter

from bmo_check_dynamic.model import EventKind, SymbolicEncodingStats, TraceEvent
from bmo_check_dynamic.model.manifest import StrictModel
from bmo_check_dynamic.model import TraceManifest

from .communication import CompactCommunicationEdges, CommunicationEdge, CommunicationScanStats
from .windows import AnalysisWindow
from bmo_check_dynamic.proof.relations import (
    source_preserved_order,
    target_preserved_order,
)


class WindowEventInclusion(StrictModel):
    """窗口诊断中一个事件的稳定身份和纳入原因。"""

    event_id: str
    thread_id: int
    sequence: int
    kind: str
    reasons: tuple[str, ...]


class WindowDiagnostics(StrictModel):
    """只读记录一个窗口为什么昂贵；它不参与任何 verdict。"""

    schema_version: str = "window-diagnostics-v2"
    window_id: str
    event_count: int
    memory_event_count: int
    load_count: int
    store_count: int
    atomic_rmw_count: int
    fence_count: int
    futex_wait_count: int
    thread_count: int
    page_count: int
    address_class_count: int
    max_thread_events: int
    max_address_class_events: int
    communication_edge_count: int
    source_ppo_edge_count: int
    target_ppo_edge_count: int
    overlap_pair_count: int
    overlap_write_pair_count: int
    overlap_read_write_pair_count: int
    fence_edge_count: int
    atomic_edge_count: int
    rf_candidate_count: int
    max_rf_candidates: int
    p95_rf_candidates: int
    coherence_candidate_pair_count: int
    event_inclusions: tuple[WindowEventInclusion, ...] = ()


class WindowCharacterizationReport(StrictModel):
    """窗口构造阶段的机器可读快照，不包含任何 proof/verdict。"""

    schema_version: str = "window-characterization-v3"
    trace_id: str
    trace_complete: bool
    event_count: int
    raw_event_count: int | None = None
    thread_count: int
    candidate_page_count: int
    candidate_event_count: int
    scanned_event_count: int | None
    filtered_event_count: int
    communication_edge_count: int
    scoped_edge_count: int
    external_edge_count: int
    communication_complete: bool
    analysis_reached_windows: bool
    window_unknowns: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    windows: tuple[WindowDiagnostics, ...] = ()
    symbolic: tuple[SymbolicEncodingStats, ...] = ()


def characterize_window(window: AnalysisWindow) -> WindowDiagnostics:
    """统计窗口的结构和潜在关系规模，不创建或修改求解约束。"""

    events = tuple(window.events)
    memory = tuple(event for event in events if event.kind.is_memory)
    reads = tuple(event for event in memory if event.kind.is_read)
    writes = tuple(event for event in memory if event.kind.is_write)
    by_thread = Counter(event.thread_id for event in events)
    by_address = Counter((event.address, event.size) for event in memory)
    pages = {
        page
        for event in memory
        for page in range(event.address >> 12, (event.end_address - 1 >> 12) + 1)
        if event.size > 0
    }

    source_ppo = source_preserved_order(events)
    target_ppo = target_preserved_order(events)
    fence_ids = {
        event.event_id
        for event in events
        if event.kind in {EventKind.LFENCE, EventKind.SFENCE, EventKind.MFENCE}
    }
    atomic_ids = {
        event.event_id for event in events if event.kind == EventKind.ATOMIC_RMW
    }
    fence_edge_count = sum(
        1
        for left, right in source_ppo | target_ppo
        if left in fence_ids or right in fence_ids
    )
    atomic_edge_count = sum(
        1
        for left, right in source_ppo | target_ppo
        if left in atomic_ids or right in atomic_ids
    )

    overlap_pair_count = 0
    overlap_write_pair_count = 0
    overlap_read_write_pair_count = 0
    # 地址排序后只需和仍可能延伸到当前地址的事件比较；这避免诊断本身
    # 无条件构造完整的 event^2 矩阵，但仍精确统计每个实际重叠对。
    active: list[TraceEvent] = []
    for event in sorted(memory, key=lambda item: (item.address, item.end_address)):
        active = [candidate for candidate in active if candidate.end_address > event.address]
        for candidate in active:
            if not candidate.overlaps(event):
                continue
            overlap_pair_count += 1
            if candidate.kind.is_write and event.kind.is_write:
                overlap_write_pair_count += 1
            elif candidate.kind.is_write != event.kind.is_write:
                overlap_read_write_pair_count += 1
        active.append(event)

    rf_counts = []
    for read in reads:
        count = sum(
            1
            for write in writes
            if write.address <= read.address
            and write.end_address >= read.end_address
            and not (
                write.thread_id == read.thread_id
                and write.sequence >= read.sequence
            )
        )
        rf_counts.append(count)
    rf_counts.sort()
    p95_index = max(0, (95 * len(rf_counts) + 99) // 100 - 1)
    events_by_id = {event.event_id: event for event in events}
    event_inclusions = tuple(
        WindowEventInclusion(
            event_id=inclusion.event_id,
            thread_id=events_by_id[inclusion.event_id].thread_id,
            sequence=events_by_id[inclusion.event_id].sequence,
            kind=events_by_id[inclusion.event_id].kind.name,
            reasons=tuple(str(reason.value) for reason in inclusion.reasons),
        )
        for inclusion in window.event_inclusions
        if inclusion.event_id in events_by_id
    )

    return WindowDiagnostics(
        window_id=window.window_id,
        event_count=len(events),
        memory_event_count=len(memory),
        load_count=sum(event.kind == EventKind.LOAD for event in memory),
        store_count=sum(event.kind == EventKind.STORE for event in memory),
        atomic_rmw_count=sum(event.kind == EventKind.ATOMIC_RMW for event in memory),
        fence_count=sum(
            event.kind in {EventKind.LFENCE, EventKind.SFENCE, EventKind.MFENCE}
            for event in events
        ),
        futex_wait_count=sum(event.kind == EventKind.FUTEX_WAIT for event in memory),
        thread_count=len(by_thread),
        page_count=len(pages),
        address_class_count=len(by_address),
        max_thread_events=max(by_thread.values(), default=0),
        max_address_class_events=max(by_address.values(), default=0),
        communication_edge_count=len(window.communication_edges),
        source_ppo_edge_count=len(source_ppo),
        target_ppo_edge_count=len(target_ppo),
        overlap_pair_count=overlap_pair_count,
        overlap_write_pair_count=overlap_write_pair_count,
        overlap_read_write_pair_count=overlap_read_write_pair_count,
        fence_edge_count=fence_edge_count,
        atomic_edge_count=atomic_edge_count,
        rf_candidate_count=sum(rf_counts),
        max_rf_candidates=max(rf_counts, default=0),
        p95_rf_candidates=rf_counts[p95_index] if rf_counts else 0,
        coherence_candidate_pair_count=overlap_write_pair_count,
        event_inclusions=event_inclusions,
    )


def characterize_windows(
    manifest: TraceManifest,
    validation: object,
    stored_event_count: int,
    scan_stats: CommunicationScanStats,
    edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
    windows: tuple[AnalysisWindow, ...],
    window_unknowns: tuple[str, ...],
    symbolic: tuple[SymbolicEncodingStats, ...] = (),
) -> WindowCharacterizationReport:
    """把同一条 pipeline 的窗口阶段输出保存为诊断快照。"""

    edge_count = edges.edge_count if isinstance(edges, CompactCommunicationEdges) else len(edges)
    raw_event_count = int(getattr(validation, "event_count", 0))
    thread_ids = tuple(getattr(validation, "thread_ids", ()))
    return WindowCharacterizationReport(
        trace_id=manifest.trace_id,
        trace_complete=bool(getattr(validation, "structurally_complete", False)),
        event_count=stored_event_count,
        raw_event_count=raw_event_count,
        thread_count=len(thread_ids),
        candidate_page_count=scan_stats.candidate_page_count,
        candidate_event_count=scan_stats.candidate_event_count,
        scanned_event_count=scan_stats.scanned_event_count,
        filtered_event_count=scan_stats.filtered_event_count,
        communication_edge_count=scan_stats.total_edges,
        scoped_edge_count=edge_count,
        external_edge_count=scan_stats.external_edges,
        communication_complete=scan_stats.complete,
        analysis_reached_windows=True,
        window_unknowns=tuple(window_unknowns),
        windows=tuple(characterize_window(window) for window in windows),
        symbolic=tuple(symbolic),
    )


__all__ = [
    "WindowCharacterizationReport",
    "WindowDiagnostics",
    "WindowEventInclusion",
    "characterize_window",
    "characterize_windows",
]
