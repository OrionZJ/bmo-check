"""把 canonical static certificate 暴露为只读诊断输入。

静态证书和诊断快照的职责不同：证书决定 proof closure 是否闭合，快照只让
诊断层回查 Unknown 和稳定身份。这里保留一条单向边界，诊断不会拿到静态
ledger 的可变对象，也不能把动态观察混进静态快照。
"""

from __future__ import annotations

from bmo_check_core import (
    DiagnosticHint,
    EvidenceSnapshot,
    ObservedFact,
    ProofFact,
    SnapshotError,
    StableId,
    StaticDiagnosticSnapshot,
    UnknownFact,
    verify_static_certificate,
)

from ..proof.certificate_bridge import StaticCertificateEvidence


class DiagnosticSnapshotAdapterError(ValueError):
    """证书不能安全地转换为静态诊断快照时抛出。"""


def _snapshot_subjects(
    nodes: tuple[ProofFact | UnknownFact, ...],
) -> tuple[StableId, ...]:
    """收集回查所需的身份，不用节点遍历顺序或临时编号。"""

    subjects: set[StableId] = set()
    for node in nodes:
        if node.subject is not None:
            subjects.add(node.subject)
        if isinstance(node, ProofFact):
            subjects.update(node.covered_events)
    return tuple(sorted(subjects, key=lambda item: item.value))


def static_snapshot_from_certificate(
    evidence: StaticCertificateEvidence,
    *,
    schema_version: str = "static-diagnostic-v1",
) -> StaticDiagnosticSnapshot:
    """将静态证书的完整证据转换成只读诊断快照。

    replay 在适配边界再次执行，因为 ``EvidenceLedger`` 是迁移期间仍可追加的
    对象；如果调用者在证书构造后改动它，快照不能继续沿用旧的 verification。
    """

    if not isinstance(evidence, StaticCertificateEvidence):
        raise DiagnosticSnapshotAdapterError(
            "static_snapshot_from_certificate expects StaticCertificateEvidence"
        )
    try:
        verification = verify_static_certificate(
            evidence.certificate,
            evidence.ledger,
            expected_binding=evidence.certificate.binding,
        )
    except ValueError as error:
        raise DiagnosticSnapshotAdapterError(
            f"static certificate replay failed before diagnostics: {error}"
        ) from error
    if verification.certificate != evidence.certificate:
        raise DiagnosticSnapshotAdapterError(
            "static certificate verification does not match the supplied certificate"
        )

    nodes = evidence.ledger.nodes()
    if any(isinstance(node, (ObservedFact, DiagnosticHint)) for node in nodes):
        raise DiagnosticSnapshotAdapterError(
            "static diagnostic snapshot cannot contain observations or hints"
        )
    static_nodes = tuple(
        node for node in nodes if isinstance(node, (ProofFact, UnknownFact))
    )
    try:
        return StaticDiagnosticSnapshot(
            schema_version=schema_version,
            scope=evidence.certificate.binding.scope,
            verdict=evidence.certificate.verdict,
            evidence=EvidenceSnapshot(
                nodes=static_nodes,
                discharges=evidence.ledger.discharges(),
            ),
            binary_closure=evidence.certificate.binding.binary_closure,
            subject_ids=_snapshot_subjects(static_nodes),
        )
    except (TypeError, ValueError, SnapshotError) as error:
        raise DiagnosticSnapshotAdapterError(
            f"static evidence cannot form a diagnostic snapshot: {error}"
        ) from error


__all__ = [
    "DiagnosticSnapshotAdapterError",
    "static_snapshot_from_certificate",
]
