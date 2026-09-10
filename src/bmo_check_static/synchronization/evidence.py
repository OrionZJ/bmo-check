"""pthread 同步摘要的 canonical evidence 旁路。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bmo_check_core import EvidenceId, EvidenceLedger, UnknownFact
from bmo_check_static.model import ModuleFingerprint, SynchronizationReport

from .pthread import analyze_pthread_synchronization


@dataclass(frozen=True, slots=True)
class StaticSynchronizationEvidence:
    # report 保留旧同步摘要格式，现有 proof 仍按原字段消费它。
    report: SynchronizationReport
    # ledger 保存反汇编和同步摘要 pass 发现的静态 Unknown。
    ledger: EvidenceLedger

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


def analyze_pthread_synchronization_with_evidence(
    library: ModuleFingerprint,
    pthread_spec_path: Path,
    dbt_contract_path: Path,
    requested_apis: set[str] | None = None,
    *,
    scope: str = "static.synchronization",
) -> StaticSynchronizationEvidence:
    """运行同步摘要并返回旧报告与 canonical Unknown 的并行结果。"""

    ledger = EvidenceLedger()
    report = analyze_pthread_synchronization(
        library,
        pthread_spec_path,
        dbt_contract_path,
        requested_apis,
        canonical_ledger=ledger,
        canonical_scope=scope,
    )
    return StaticSynchronizationEvidence(report=report, ledger=ledger)


__all__ = [
    "StaticSynchronizationEvidence",
    "analyze_pthread_synchronization_with_evidence",
]
