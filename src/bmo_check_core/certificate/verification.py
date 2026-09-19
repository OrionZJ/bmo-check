from __future__ import annotations

from dataclasses import dataclass

from ..evidence import EvidenceLedger, LedgerError, ObservedFact, ProofFact, UnknownFact
from ..identity import EvidenceId, MemoryEventId
from .model import (
    CertificateBinding,
    CertificateError,
    CertificateVerdict,
    StaticCertificate,
    TraceCertificate,
    TraceVerdict,
)


@dataclass(frozen=True, slots=True)
class StaticVerification:
    # certificate 是已通过 replay 的静态证书输入。
    certificate: StaticCertificate
    # proof_closure 是从 roots 回溯得到的完整 ProofFact 顺序。
    proof_closure: tuple[ProofFact, ...]
    # discharged_unknowns 记录本次 scope 中真正被 ProofFact 关闭的 Unknown。
    discharged_unknowns: tuple[EvidenceId, ...]
    # unknown_propositions 只报告 typed/legacy/missing 分布，不改变 verdict。
    unknown_propositions: "UnknownPropositionAudit"


@dataclass(frozen=True, slots=True)
class UnknownPropositionAudit:
    """certificate replay 对 relevant Unknown 的 proposition 字段盘点。"""

    # typed_ids 可以进入后续 proposition/obligation identity 检查。
    typed_ids: tuple[EvidenceId, ...]
    # legacy_ids 没有 proposition，只能作为 explain-only/incomplete view。
    legacy_ids: tuple[EvidenceId, ...]
    # missing_ids 指向证书声明但 ledger 没有提供的 Unknown；不能静默补齐。
    missing_ids: tuple[EvidenceId, ...]


@dataclass(frozen=True, slots=True)
class TraceVerification:
    # certificate 是已通过 trace/category/binding 检查的输入。
    certificate: TraceCertificate
    # observed_roots 是与 trace_id 相同的动态事实。
    observed_roots: tuple[ObservedFact, ...]


def audit_unknown_propositions(
    ledger: EvidenceLedger,
    unknown_ids: tuple[EvidenceId, ...],
) -> UnknownPropositionAudit:
    """区分 typed、legacy 和 missing Unknown，不从旧字段合成 proposition。"""

    typed: list[EvidenceId] = []
    legacy: list[EvidenceId] = []
    missing: list[EvidenceId] = []
    for evidence_id in unknown_ids:
        node = ledger.get(evidence_id)
        if not isinstance(node, UnknownFact):
            missing.append(evidence_id)
        elif node.proposition is None:
            legacy.append(evidence_id)
        else:
            typed.append(evidence_id)
    return UnknownPropositionAudit(
        typed_ids=tuple(sorted(set(typed), key=lambda item: item.value)),
        legacy_ids=tuple(sorted(set(legacy), key=lambda item: item.value)),
        missing_ids=tuple(sorted(set(missing), key=lambda item: item.value)),
    )


def _check_binding(
    actual: CertificateBinding,
    expected: CertificateBinding | None,
) -> None:
    if expected is not None and actual != expected:
        raise CertificateError("certificate binding does not match the current subject")


def _proof_covers_event(proof: ProofFact, event_id: MemoryEventId) -> bool:
    return event_id in proof.covered_events or proof.subject == event_id


def _reject_legacy_determinate_schema(
    schema_version: str,
    *,
    kind: str,
    verdict: CertificateVerdict | TraceVerdict,
) -> None:
    """旧证书只能解释，不能借空字段通过新的 replay 门禁。"""

    if verdict in {
        CertificateVerdict.SAFE,
        CertificateVerdict.COUNTEREXAMPLE,
        TraceVerdict.TRACE_SAFE,
        TraceVerdict.COUNTEREXAMPLE,
    }:
        expected = f"{kind}-certificate-v2"
        if schema_version != expected:
            raise CertificateError(
                f"legacy {kind} certificate schema is explain-only; "
                f"replay requires {expected} with completeness ledgers"
            )
        # C0.4 只建立拒绝门；universe/obligation/window ledger 会在 RU2/RU5/RU6
        # 引入。现在不能用一个空 digest 或空列表冒充 v2 completeness。
        raise CertificateError(
            f"{kind} certificate v2 replay is unavailable until completeness "
            "ledgers are bound"
        )


def verify_static_certificate(
    certificate: StaticCertificate,
    ledger: EvidenceLedger,
    *,
    expected_binding: CertificateBinding | None = None,
) -> StaticVerification:
    """验证静态证书的 proof closure、Unknown 保存和 binary/DBT 绑定。"""

    if not isinstance(certificate, StaticCertificate):
        raise CertificateError("verify_static_certificate expects StaticCertificate")
    if not isinstance(ledger, EvidenceLedger):
        raise CertificateError("verify_static_certificate expects EvidenceLedger")
    _check_binding(certificate.binding, expected_binding)

    # ledger 只允许 ProofFact premise；若 root 是 ObservedFact、DiagnosticHint
    # 或缺失节点，proof_closure 会拒绝，不能把动态事实伪装成 SAFE 依据。
    try:
        closure = ledger.proof_closure(certificate.proof_roots)
    except LedgerError as error:
        raise CertificateError(f"static proof closure is invalid: {error}") from error
    closure_ids = {fact.id for fact in closure}

    for decision in certificate.removal_decisions:
        if decision.scope != certificate.binding.scope:
            raise CertificateError("removal decision scope does not match certificate")
        if decision.proof_id not in closure_ids:
            raise CertificateError("removed event proof is outside proof closure")
        proof = ledger.get(decision.proof_id)
        if not isinstance(proof, ProofFact):
            raise CertificateError("removal decision does not reference a ProofFact")
        if not _proof_covers_event(proof, decision.event_id):
            raise CertificateError("removed event is not covered by its ProofFact")

    unresolved = ledger.unresolved_unknowns(certificate.binding.scope)
    unresolved_ids = {fact.id for fact in unresolved}
    declared_unknown_ids = set(certificate.relevant_unknowns)
    if not unresolved_ids.issubset(declared_unknown_ids):
        omitted = sorted(
            (item.value for item in unresolved_ids - declared_unknown_ids)
        )
        raise CertificateError(f"relevant UnknownFact was omitted: {omitted}")

    unknown_propositions = audit_unknown_propositions(
        ledger,
        certificate.relevant_unknowns,
    )

    discharged: list[EvidenceId] = []
    for unknown_id in certificate.relevant_unknowns:
        unknown = ledger.get(unknown_id)
        if not isinstance(unknown, UnknownFact):
            raise CertificateError("relevant_unknowns must reference UnknownFact nodes")
        if unknown.scope != certificate.binding.scope:
            raise CertificateError("UnknownFact scope does not match certificate")
        discharge = next(
            (
                item
                for item in ledger.discharges()
                if item.unknown_id == unknown_id
            ),
            None,
        )
        if discharge is None:
            if certificate.verdict == CertificateVerdict.SAFE:
                raise CertificateError("SAFE certificate contains an unresolved UnknownFact")
            continue
        if discharge.proof_id not in closure_ids:
            raise CertificateError("UnknownFact discharge proof is outside proof closure")
        discharged.append(unknown_id)

    if certificate.verdict == CertificateVerdict.SAFE and certificate.bounded:
        raise CertificateError("bounded checker result cannot produce SAFE")
    if certificate.verdict == CertificateVerdict.COUNTEREXAMPLE and certificate.relevant_unknowns:
        raise CertificateError("COUNTEREXAMPLE cannot contain relevant UnknownFacts")

    _reject_legacy_determinate_schema(
        certificate.schema_version,
        kind="static",
        verdict=certificate.verdict,
    )

    return StaticVerification(
        certificate=certificate,
        proof_closure=closure,
        discharged_unknowns=tuple(sorted(discharged, key=lambda item: item.value)),
        unknown_propositions=unknown_propositions,
    )


def verify_trace_certificate(
    certificate: TraceCertificate,
    ledger: EvidenceLedger,
    *,
    expected_binding: CertificateBinding | None = None,
) -> TraceVerification:
    """验证 trace certificate 只引用同一 trace 的 ObservedFact。"""

    if not isinstance(certificate, TraceCertificate):
        raise CertificateError("verify_trace_certificate expects TraceCertificate")
    if not isinstance(ledger, EvidenceLedger):
        raise CertificateError("verify_trace_certificate expects EvidenceLedger")
    _check_binding(certificate.binding, expected_binding)
    observed_roots: list[ObservedFact] = []
    for evidence_id in certificate.observed_roots:
        node = ledger.get(evidence_id)
        if not isinstance(node, ObservedFact):
            raise CertificateError("trace certificate root is not an ObservedFact")
        if node.trace_id != certificate.trace_id:
            raise CertificateError("ObservedFact belongs to another trace")
        observed_roots.append(node)
    if certificate.verdict == TraceVerdict.TRACE_SAFE and not certificate.complete:
        raise CertificateError("incomplete trace cannot produce TRACE_SAFE")
    _reject_legacy_determinate_schema(
        certificate.schema_version,
        kind="trace",
        verdict=certificate.verdict,
    )
    return TraceVerification(certificate, tuple(observed_roots))


__all__ = [
    "StaticVerification",
    "TraceVerification",
    "UnknownPropositionAudit",
    "audit_unknown_propositions",
    "verify_static_certificate",
    "verify_trace_certificate",
]
