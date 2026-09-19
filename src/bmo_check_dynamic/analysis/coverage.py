from __future__ import annotations

import hashlib

from bmo_check_core import TraceImportLayer, TraceImportLedger, TraceImportState
from bmo_check_dynamic.model import (
    CommunicationCoverage,
    CoverageState,
    TraceCoverage,
    WindowCoverage,
)
from bmo_check_dynamic.storage import TraceStore, TraceStoreError

from .communication import CompactCommunicationEdges, CommunicationEdge, CommunicationScanStats


def build_trace_coverage(
    store: TraceStore,
    *,
    import_ledger: TraceImportLedger | None,
    communication_edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
    scan_stats: CommunicationScanStats,
    windows: tuple[object, ...],
    window_unknowns: tuple[str, ...],
) -> TraceCoverage:
    """把通信扫描和窗口切分的输入/输出全集写成可回放的 coverage。"""

    if import_ledger is None or import_ledger.state is not TraceImportState.COMPLETE:
        raise TraceStoreError("coverage requires a complete trace import ledger")
    event_layer = next(
        (
            layer
            for layer in import_ledger.layers
            if layer.layer is TraceImportLayer.DECODED_EVENT
        ),
        None,
    )
    if event_layer is None:
        raise TraceStoreError("trace import has no decoded event inventory")

    edges = tuple(iter_edges(communication_edges))
    edge_digest = digest_edges(edges)
    assigned_edges = tuple(
        edge
        for window in windows
        for edge in getattr(window, "communication_edges", ())
    )
    assigned_digest = digest_edges(assigned_edges)
    communication_state = coverage_state(
        scan_stats.complete,
        () if scan_stats.complete else ("communication edge scan is incomplete",),
    )
    window_state = coverage_state(not window_unknowns, window_unknowns)
    return TraceCoverage(
        trace_subject=import_ledger.subject.value,
        trace_sha256=import_ledger.trace_digest,
        config_sha256=import_ledger.config_digest,
        event_count=event_layer.count,
        event_sha256=event_layer.sha256,
        communication=CommunicationCoverage(
            input_event_count=event_layer.count,
            input_event_sha256=event_layer.sha256,
            candidate_edge_count=scan_stats.total_edges,
            scoped_edge_count=len(edges),
            scoped_edge_sha256=edge_digest,
            external_edge_count=scan_stats.external_edges,
            state=communication_state,
            reason=(
                None
                if communication_state is CoverageState.COMPLETE
                else "communication edge scan is incomplete"
            ),
        ),
        windows=WindowCoverage(
            input_edge_count=len(edges),
            input_edge_sha256=edge_digest,
            assigned_edge_count=len(assigned_edges),
            assigned_edge_sha256=assigned_digest,
            window_count=len(windows),
            window_event_count=sum(
                len(getattr(window, "events", ())) for window in windows
            ),
            state=window_state,
            reason=None if window_state is CoverageState.COMPLETE else "; ".join(window_unknowns),
        ),
    )


def coverage_state(complete: bool, reasons: tuple[str, ...]) -> CoverageState:
    if complete:
        return CoverageState.COMPLETE
    joined = " ".join(reasons).lower()
    if any(term in joined for term in ("limit", "budget", "resource", "exceed")):
        return CoverageState.RESOURCE_LIMITED
    return CoverageState.INCOMPLETE


def iter_edges(
    edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
) -> tuple[CommunicationEdge, ...]:
    if isinstance(edges, CompactCommunicationEdges):
        return tuple(edges.edge(index) for index in range(edges.edge_count))
    return tuple(edges)


def digest_edges(edges: tuple[CommunicationEdge, ...]) -> str:
    rows = []
    for edge in edges:
        first = edge.first_endpoint
        second = edge.second_endpoint
        rows.append(
            (
                edge.first_event,
                edge.second_event,
                edge.address,
                edge.size,
                None if first is None else first.thread_id,
                None if first is None else first.sequence,
                None if first is None else int(first.kind),
                None if second is None else second.thread_id,
                None if second is None else second.sequence,
                None if second is None else int(second.kind),
            )
        )
    digest = hashlib.sha256()
    for row in sorted(rows):
        digest.update(
            "\x1f".join(
                "<null>" if value is None else str(value) for value in row
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


__all__ = [
    "build_trace_coverage",
    "coverage_state",
    "digest_edges",
    "iter_edges",
]
