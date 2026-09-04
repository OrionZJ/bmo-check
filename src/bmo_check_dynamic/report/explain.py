from __future__ import annotations

from bmo_check_dynamic.model import DynamicCertificate, TraceVerdict


def explain_certificate(certificate: DynamicCertificate) -> str:
    lines = [
        f"Verdict: {certificate.verdict.value}",
        f"Trace scope: {', '.join(certificate.scope.trace_ids)}",
        f"Events/threads/communication edges: {certificate.event_count}/"
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
