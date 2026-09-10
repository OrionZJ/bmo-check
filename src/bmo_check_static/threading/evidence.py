"""线程角色恢复的 canonical evidence 旁路。"""

from __future__ import annotations

from dataclasses import dataclass

from bmo_check_core import EvidenceId, EvidenceLedger, UnknownFact
from bmo_check_static.model import (
    ControlFlowReport,
    ModuleFingerprint,
    ProgramManifest,
    ThreadDiscoveryReport,
)

from .pthread import discover_pthread_threads


@dataclass(frozen=True, slots=True)
class StaticThreadEvidence:
    # report 继续给现有 shared-state 和 proof consumer 使用，避免旁路迁移改变旧模型。
    report: ThreadDiscoveryReport
    # ledger 只保存线程恢复 pass 产生的静态 Unknown，不接受动态观察。
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


def discover_pthread_threads_with_evidence(
    module: ModuleFingerprint,
    manifest: ProgramManifest,
    control_flow: ControlFlowReport,
    *,
    scope: str = "static.threading",
) -> StaticThreadEvidence:
    """运行线程恢复并返回旧报告与 canonical Unknown 的并行结果。"""

    ledger = EvidenceLedger()
    report = discover_pthread_threads(
        module,
        manifest,
        control_flow,
        canonical_ledger=ledger,
        canonical_scope=scope,
    )
    return StaticThreadEvidence(report=report, ledger=ledger)


__all__ = ["StaticThreadEvidence", "discover_pthread_threads_with_evidence"]
