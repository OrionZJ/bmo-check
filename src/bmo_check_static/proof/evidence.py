"""静态 portability checker 的 canonical Unknown 旁路。"""

from __future__ import annotations

from dataclasses import dataclass

from bmo_check_core import EvidenceId, EvidenceLedger, ObligationInventory, UnknownFact
from bmo_check_static.binary.evidence import emit_static_unknown
from bmo_check_static.model import (
    CheckerLimits,
    PortabilityCertificate,
    ProgramSliceReport,
)

from .verifier import verify_portability


@dataclass(frozen=True, slots=True)
class StaticPortabilityEvidence:
    # certificate 保留现有 CLI 和 JSON 行为；sidecar 不替换旧 verdict。
    certificate: PortabilityCertificate
    # ledger 保存 portability 入口确认仍未闭合的静态 Unknown。
    ledger: EvidenceLedger
    # obligation_inventory 是 checker 枚举的完整命题集合；旧 producer 缺失时不能补空。
    obligation_inventory: ObligationInventory | None = None

    @property
    def unknown_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            sorted(
                {
                    node.id
                    for node in self.ledger.nodes()
                    if isinstance(node, UnknownFact)
                },
                key=lambda item: item.value,
            )
        )


def verify_portability_with_evidence(
    report: ProgramSliceReport,
    limits: CheckerLimits | None = None,
    analysis_options: dict[str, object] | None = None,
    *,
    scope: str = "static.portability",
) -> StaticPortabilityEvidence:
    """复用旧 verdict，并把其 relevant Unknown 映射到 canonical ledger。"""

    ledger = EvidenceLedger()
    certificate = verify_portability(report, limits, analysis_options)
    for unknown in certificate.relevant_unknowns:
        emit_static_unknown(
            unknown.kind,
            unknown.reason,
            unknown.impact,
            module=unknown.module,
            pc=unknown.pc,
            function=unknown.function,
            details=unknown.details,
            canonical_ledger=ledger,
            canonical_scope=scope,
        )
    return StaticPortabilityEvidence(certificate=certificate, ledger=ledger)


__all__ = ["StaticPortabilityEvidence", "verify_portability_with_evidence"]
