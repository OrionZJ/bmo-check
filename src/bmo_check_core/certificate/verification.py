from __future__ import annotations

from dataclasses import dataclass

from ..evidence import EvidenceLedger, LedgerError, ObservedFact, ProofFact, UnknownFact
from ..evidence import (
    ProofRuleRegistry,
    ProofRuleReplayStatus,
    replay_proof_rule,
)
from ..identity import EvidenceId, MemoryEventId
from ..obligations import (
    ObligationInventory,
    ObligationMatchStatus,
    ProofObligation,
    match_proof_to_obligation,
    match_unknown_to_obligation,
)
from ..projection import (
    ProjectionError,
    ProjectionLedger,
    ProjectionRelationDisposition,
    verify_projection_ledger,
)
from ..universe import (
    CompletenessStatus,
    EventDisposition,
    EventUniverseLedger,
)
from .digests import (
    digest_event_universe,
    digest_obligation_inventory,
    digest_projection_ledger,
    digest_unknown_ids,
)
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
class TypedDischargeVerification:
    """一个已写入 ledger 的 typed discharge 的只读 replay 结果。"""

    # unknown_id 和 proof_id 让 certificate report 可以回到原始 ledger 节点。
    unknown_id: EvidenceId
    proof_id: EvidenceId
    # obligation_id 绑定本次检查使用的 canonical obligation。
    obligation_id: "ObligationId"


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


def verify_typed_discharge(
    ledger: EvidenceLedger,
    discharge: "UnknownDischarge",
    obligation: ProofObligation,
    registry: ProofRuleRegistry,
) -> TypedDischargeVerification:
    """只读复核 typed discharge，供新 certificate replay gate 调用。"""

    from ..evidence import UnknownDischarge

    if not isinstance(discharge, UnknownDischarge):
        raise CertificateError("typed discharge verification expects UnknownDischarge")
    if not isinstance(obligation, ProofObligation):
        raise CertificateError("typed discharge verification expects ProofObligation")
    if not isinstance(registry, ProofRuleRegistry):
        raise CertificateError("typed discharge verification expects ProofRuleRegistry")
    if discharge not in ledger.discharges():
        raise CertificateError("typed discharge is not present in the evidence ledger")
    unknown = ledger.get(discharge.unknown_id)
    proof = ledger.get(discharge.proof_id)
    unknown_match = match_unknown_to_obligation(unknown, obligation)
    if unknown_match.status is not ObligationMatchStatus.MATCH:
        raise CertificateError(f"typed Unknown binding is not closed: {unknown_match.reason}")
    proof_match = match_proof_to_obligation(proof, obligation)
    if proof_match.status is not ObligationMatchStatus.MATCH:
        raise CertificateError(f"typed proof binding is not closed: {proof_match.reason}")
    if not isinstance(proof, ProofFact):
        raise CertificateError("typed discharge proof is not a ProofFact")
    replay = replay_proof_rule(proof, ledger, registry)
    if replay.status is not ProofRuleReplayStatus.VALID:
        raise CertificateError(f"typed proof rule is not replayable: {replay.reason}")
    return TypedDischargeVerification(
        unknown_id=discharge.unknown_id,
        proof_id=discharge.proof_id,
        obligation_id=obligation.id,
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
    _allow_v2: bool = False,
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

    if not _allow_v2:
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


def _verify_event_universe_v2(
    certificate: StaticCertificate,
    ledger: EvidenceLedger,
    universe: EventUniverseLedger,
    closure_ids: set[EvidenceId],
    *,
    require_typed_proof: bool,
) -> None:
    """核对 event ledger 的逐项去向，不把 digest 当成完整性证明。"""

    if universe.stage != certificate.binding.scope:
        raise CertificateError("static event universe scope does not match certificate")
    input_ids = set(universe.input_event_ids)
    entry_ids = {entry.event_id for entry in universe.entries}
    if not entry_ids.issubset(input_ids):
        raise CertificateError("static event universe contains an out-of-scope event")
    for entry in universe.entries:
        if entry.disposition is EventDisposition.REMOVED_WITH_PROOF:
            for proof_id in entry.proof_ids:
                if proof_id not in closure_ids:
                    raise CertificateError("event removal proof is outside proof closure")
                proof = ledger.get(proof_id)
                if not isinstance(proof, ProofFact):
                    raise CertificateError("event removal proof is not a ProofFact")
                if proof.scope != certificate.binding.scope:
                    raise CertificateError("event removal proof scope does not match certificate")
                if entry.event_id not in proof.covered_events and proof.subject != entry.event_id:
                    raise CertificateError("event removal proof does not cover the event")
                if require_typed_proof and (
                    proof.registered_rule is None or proof.conclusion is None
                ):
                    raise CertificateError("event removal proof is not typed")
        elif entry.disposition is EventDisposition.UNRESOLVED:
            for unknown_id in entry.unknown_ids:
                unknown = ledger.get(unknown_id)
                if not isinstance(unknown, UnknownFact):
                    raise CertificateError("event universe Unknown is missing from the ledger")
                if unknown.scope != certificate.binding.scope:
                    raise CertificateError("event universe Unknown scope does not match certificate")
                if unknown_id not in certificate.relevant_unknowns:
                    raise CertificateError("event universe Unknown is missing from the certificate")

    removed_by_universe = {
        entry.event_id
        for entry in universe.entries
        if entry.disposition is EventDisposition.REMOVED_WITH_PROOF
    }
    removed_by_certificate = {decision.event_id for decision in certificate.removal_decisions}
    if removed_by_universe != removed_by_certificate:
        raise CertificateError("event universe and removal decisions disagree")


def _verify_projection_sidecars_v2(
    certificate: StaticCertificate,
    ledger: EvidenceLedger,
    projection_ledger: ProjectionLedger,
    projection_obligations: ObligationInventory,
    *,
    proof_registry: ProofRuleRegistry | None,
) -> None:
    """核对 relation ledger 和其 obligation inventory 的同一输入。"""

    if projection_ledger.stage != certificate.binding.scope:
        raise CertificateError("projection ledger scope does not match certificate")
    from ..obligations import build_projection_relation_obligation_inventory

    expected = build_projection_relation_obligation_inventory(
        projection_ledger,
        scope=certificate.binding.scope,
    )
    if projection_obligations != expected:
        raise CertificateError("projection obligation inventory does not match its ledger")

    for entry in projection_ledger.entries:
        if entry.disposition is ProjectionRelationDisposition.REMOVED_WITH_PROOF:
            for proof_id in entry.proof_ids:
                proof = ledger.get(proof_id)
                if not isinstance(proof, ProofFact):
                    raise CertificateError("projection removal proof is missing")
                if proof.scope != certificate.binding.scope:
                    raise CertificateError("projection proof scope does not match certificate")
        elif entry.disposition is ProjectionRelationDisposition.UNRESOLVED:
            for unknown_id in entry.unknown_ids:
                unknown = ledger.get(unknown_id)
                if not isinstance(unknown, UnknownFact):
                    raise CertificateError("projection Unknown is missing from the ledger")

    if projection_ledger.completeness.status is CompletenessStatus.COMPLETE:
        try:
            verify_projection_ledger(
                projection_ledger,
                ledger,
                expected_scope=certificate.binding.scope,
            )
        except ProjectionError as error:
            raise CertificateError(f"projection sidecar replay failed: {error}") from error
    if projection_obligations.obligations and proof_registry is None:
        raise CertificateError("projection proof rule registry is missing")
    if proof_registry is not None:
        for entry in projection_ledger.entries:
            for proof_id in entry.proof_ids:
                proof = ledger.get(proof_id)
                if not isinstance(proof, ProofFact):
                    raise CertificateError("projection proof is missing")
                replay = replay_proof_rule(proof, ledger, proof_registry)
                if replay.status is not ProofRuleReplayStatus.VALID:
                    raise CertificateError(f"projection proof rule is not replayable: {replay.reason}")


def _verify_obligation_closure_v2(
    certificate: StaticCertificate,
    ledger: EvidenceLedger,
    inventory: ObligationInventory,
    closure: tuple[ProofFact, ...],
    *,
    proof_registry: ProofRuleRegistry | None,
) -> None:
    """对确定性 SAFE 要求每个 proposition 有 typed、可回放的 proof。"""

    if inventory.scope != certificate.binding.scope:
        raise CertificateError("static obligation inventory scope does not match certificate")
    if not inventory.is_enumerated:
        raise CertificateError("static obligation inventory is incomplete")
    if not inventory.obligations:
        return
    if proof_registry is None:
        raise CertificateError("static proof rule registry is missing")

    for obligation in inventory.obligations:
        matches = [
            proof
            for proof in closure
            if match_proof_to_obligation(proof, obligation).status
            is ObligationMatchStatus.MATCH
        ]
        if not matches:
            raise CertificateError(
                "deterministic static certificate has an unclosed obligation"
            )
        # A typed conclusion is necessary before the immutable rule registry can
        # replay this obligation. Legacy proofs therefore remain explain-only.
        if any(
            proof.registered_rule is None or proof.conclusion is None
            for proof in matches
        ):
            raise CertificateError("static obligation proof is not typed")
        if all(
            replay_proof_rule(proof, ledger, proof_registry).status
            is not ProofRuleReplayStatus.VALID
            for proof in matches
        ):
            raise CertificateError("static obligation proof rule is not replayable")


def _verify_discharges_v2(
    certificate: StaticCertificate,
    ledger: EvidenceLedger,
    inventory: ObligationInventory,
    *,
    proof_registry: ProofRuleRegistry | None,
) -> None:
    """UnknownDischarge 必须同时绑定同一 proposition 的 obligation。"""

    for discharge in ledger.discharges():
        unknown = ledger.get(discharge.unknown_id)
        proof = ledger.get(discharge.proof_id)
        if not isinstance(unknown, UnknownFact) or not isinstance(proof, ProofFact):
            raise CertificateError("static discharge references missing evidence")
        if not any(
            match_unknown_to_obligation(unknown, obligation).status
            is ObligationMatchStatus.MATCH
            and match_proof_to_obligation(proof, obligation).status
            is ObligationMatchStatus.MATCH
            for obligation in inventory.obligations
        ):
            raise CertificateError("static discharge does not match an obligation")
        if proof_registry is None:
            raise CertificateError("static discharge proof rule registry is missing")
        replay = replay_proof_rule(proof, ledger, proof_registry)
        if replay.status is not ProofRuleReplayStatus.VALID:
            raise CertificateError(f"static discharge proof rule is not replayable: {replay.reason}")


def verify_static_certificate_v2(
    certificate: StaticCertificate,
    ledger: EvidenceLedger,
    *,
    event_universe: EventUniverseLedger,
    obligation_inventory: ObligationInventory,
    projection_ledger: ProjectionLedger,
    projection_obligations: ObligationInventory,
    expected_binding: CertificateBinding | None = None,
    proof_registry: ProofRuleRegistry | None = None,
) -> StaticVerification:
    """独立重放 static v2 的 universe、obligation 和 projection 完整性。

    v2 不相信 producer 提交的 digest 或 ``complete`` 标记。先走旧的
    proof/Unknown 边界，再从 typed sidecar 重算内容；不能闭合的确定性
    SAFE/COUNTEREXAMPLE 仍保守失败，不能把缺失输入解释成没有义务。
    """

    if certificate.schema_version != "static-certificate-v2":
        raise CertificateError("static v2 replay requires static-certificate-v2")
    if not isinstance(event_universe, EventUniverseLedger):
        raise CertificateError("static v2 replay requires an event universe")
    if not isinstance(obligation_inventory, ObligationInventory):
        raise CertificateError("static v2 replay requires an obligation inventory")
    if not isinstance(projection_ledger, ProjectionLedger):
        raise CertificateError("static v2 replay requires a projection ledger")
    if not isinstance(projection_obligations, ObligationInventory):
        raise CertificateError("static v2 replay requires projection obligations")
    completeness = certificate.completeness
    if completeness is None:
        raise CertificateError("static v2 replay requires completeness digests")

    # The base verifier deliberately keeps v1 behavior unchanged.  Calling it
    # with a v2 certificate would hit the legacy gate, so replay its structural
    # checks locally and suppress only that one gate.
    base = verify_static_certificate(
        certificate,
        ledger,
        expected_binding=expected_binding,
        _allow_v2=True,
    )
    _verify_event_universe_v2(
        certificate,
        ledger,
        event_universe,
        {fact.id for fact in base.proof_closure},
        require_typed_proof=certificate.verdict is not CertificateVerdict.UNKNOWN,
    )
    _verify_projection_sidecars_v2(
        certificate,
        ledger,
        projection_ledger,
        projection_obligations,
        proof_registry=proof_registry,
    )
    if obligation_inventory.scope != certificate.binding.scope:
        raise CertificateError("static obligation inventory scope does not match certificate")
    if certificate.verdict in {
        CertificateVerdict.SAFE,
        CertificateVerdict.COUNTEREXAMPLE,
    }:
        if event_universe.completeness.status is not CompletenessStatus.COMPLETE:
            raise CertificateError("deterministic static certificate has an incomplete event universe")
        if projection_ledger.completeness.status is not CompletenessStatus.COMPLETE:
            raise CertificateError("deterministic static certificate has an incomplete projection ledger")
        if projection_obligations.completeness.status is not CompletenessStatus.COMPLETE:
            raise CertificateError("deterministic static certificate has incomplete projection obligations")
        if obligation_inventory.completeness.status is not CompletenessStatus.COMPLETE:
            raise CertificateError("deterministic static certificate has incomplete obligations")
    expected_unknowns = tuple(node.id for node in ledger.unresolved_unknowns(certificate.binding.scope))
    if set(certificate.relevant_unknowns) != set(expected_unknowns):
        raise CertificateError("static Unknown inventory is not independently closed")
    if completeness.event_universe_sha256 != digest_event_universe(event_universe):
        raise CertificateError("event universe digest does not match certificate")
    if completeness.obligation_sha256 != digest_obligation_inventory(obligation_inventory):
        raise CertificateError("obligation digest does not match certificate")
    if completeness.unknown_sha256 != digest_unknown_ids(
        certificate.binding.scope,
        expected_unknowns,
    ):
        raise CertificateError("Unknown digest does not match certificate")
    if completeness.projection_sha256 != digest_projection_ledger(projection_ledger):
        raise CertificateError("projection digest does not match certificate")
    _verify_discharges_v2(
        certificate,
        ledger,
        obligation_inventory,
        proof_registry=proof_registry,
    )
    if certificate.verdict is CertificateVerdict.SAFE:
        _verify_obligation_closure_v2(
            certificate,
            ledger,
            obligation_inventory,
            base.proof_closure,
            proof_registry=proof_registry,
        )
    elif certificate.verdict is CertificateVerdict.COUNTEREXAMPLE:
        raise CertificateError("static v2 counterexample witness replay is not implemented")
    return base


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
    "TypedDischargeVerification",
    "verify_typed_discharge",
    "verify_static_certificate",
    "verify_static_certificate_v2",
    "verify_trace_certificate",
]
