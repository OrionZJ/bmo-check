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
    verify_static_certificate_v2,
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
    schema_version: str = "static-diagnostic-v2",
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
        if evidence.certificate.schema_version == "static-certificate-v2":
            if (
                evidence.event_universe is None
                or evidence.obligation_inventory is None
                or evidence.projection_ledger is None
                or evidence.projection_obligations is None
            ):
                raise DiagnosticSnapshotAdapterError(
                    "static v2 certificate is missing completeness sidecars"
                )
            verification = verify_static_certificate_v2(
                evidence.certificate,
                evidence.ledger,
                event_universe=evidence.event_universe,
                obligation_inventory=evidence.obligation_inventory,
                projection_ledger=evidence.projection_ledger,
                projection_obligations=evidence.projection_obligations,
                expected_binding=evidence.certificate.binding,
            )
        else:
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

    proof_closure_ids = {item.id for item in verification.proof_closure}
    for discharge in evidence.ledger.discharges():
        if discharge.proof_id not in proof_closure_ids:
            raise DiagnosticSnapshotAdapterError(
                "static evidence contains an Unknown discharge outside the certificate proof closure"
            )
    replay_blocking_ids = set(evidence.certificate.relevant_unknowns) - set(
        verification.discharged_unknowns
    )
    unresolved_ids = {
        item.id
        for item in evidence.ledger.unresolved_unknowns(
            evidence.certificate.binding.scope
        )
    }
    if replay_blocking_ids != unresolved_ids:
        raise DiagnosticSnapshotAdapterError(
            "certificate replay obligation set differs from unresolved static evidence"
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
            blocking_unknown_ids=tuple(replay_blocking_ids),
        )
    except (TypeError, ValueError, SnapshotError) as error:
        raise DiagnosticSnapshotAdapterError(
            f"static evidence cannot form a diagnostic snapshot: {error}"
        ) from error


__all__ = [
    "DiagnosticSnapshotAdapterError",
    "static_snapshot_from_certificate",
]
