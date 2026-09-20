from __future__ import annotations

from bmo_check_dynamic.model import DynamicCertificate, TraceVerdict


def explain_certificate(certificate: DynamicCertificate) -> str:
    lines = [
        f"Verdict: {certificate.verdict.value}",
        f"Trace scope: {', '.join(certificate.scope.trace_ids)}",
        f"Analysis scope: {certificate.scope.analysis_scope}",
        f"Events/threads/raw communication edges: {certificate.event_count}/"
        f"{certificate.thread_count}/{certificate.communication_edge_count}",
        f"Objects/unique PCs: {certificate.object_count}/{certificate.unique_pc_count}",
    ]
    partition = certificate.application_partition
    if partition is not None:
        lines.append(
            "Application partition: "
            f"{partition.status} (workers={len(partition.worker_threads)}, "
            f"worker conflicts={partition.worker_conflicting_ranges}, "
            f"concurrent main conflicts={partition.concurrent_main_conflicts}, "
            f"read-only shared ranges={partition.readonly_shared_ranges})"
        )
    if certificate.external_runtime_edge_count:
        lines.append(
            "External runtime edges excluded: "
            f"{certificate.external_runtime_edge_count}"
        )
    if certificate.coverage is not None:
        communication = certificate.coverage.communication
        scanned = (
            "unknown"
            if communication.scanned_event_count is None
            else str(communication.scanned_event_count)
        )
        lines.append(
            "Communication scan coverage: "
            f"{communication.candidate_page_count} candidate pages, "
            f"{communication.candidate_event_count} candidate events, "
            f"{scanned} unique events scanned, "
            f"{communication.scanned_event_page_records} page records read"
        )
        if communication.filtered_event_count:
            reasons = ", ".join(
                f"{reason}={count}"
                for reason, count in communication.filtered_event_reasons
            )
            lines.append(
                "Communication scan filtered events: "
                f"{communication.filtered_event_count} ({reasons})"
            )
        if communication.resource_limited_event_count is not None:
            lines.append(
                "Communication scan resource-limited candidate events: "
                f"{communication.resource_limited_event_count}"
            )
    if not certificate.communication_edges_complete:
        lines.append("Communication edges: enumeration incomplete")
        if certificate.coverage is not None:
            reason = certificate.coverage.communication.reason
            if reason:
                lines.append(f"Communication scan reason: {reason}")
    if certificate.verdict == TraceVerdict.TRACE_SAFE:
        lines.append(
            "Meaning: no RVWMO-only execution was found for the recorded event skeleton."
        )
        lines.append(f"Limit: {certificate.scope.limitation}")
    elif certificate.verdict == TraceVerdict.UNKNOWN:
        lines.append("Unknown reasons:")
        lines.extend(f"  - {reason}" for reason in certificate.unknown_reasons)
    else:
        witness = next(
            window.witness
            for window in certificate.windows
            if window.witness is not None and window.witness.validated
        )
        lines.append(f"Witness window: {witness.window_id}")
        lines.append(f"x86-TSO rejection cycle: {' -> '.join(witness.source_cycle)}")
    return "\n".join(lines)
