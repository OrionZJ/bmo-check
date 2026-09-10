"""共享对象/逃逸分类的 canonical evidence 旁路。"""

from __future__ import annotations

from dataclasses import dataclass

from bmo_check_core import EvidenceId, EvidenceLedger, UnknownFact
from bmo_check_static.model import (
    ControlFlowReport,
    MemoryEventReport,
    ModuleFingerprint,
    SharedStateReport,
    SynchronizationReport,
    ThreadDiscoveryReport,
)

from .lifecycle_symbolic import SymbolicLifecycleProof
from .partition_symbolic import SymbolicPartitionProof
from .shared_state import analyze_shared_state


@dataclass(frozen=True, slots=True)
class StaticSharedStateEvidence:
    # report 保留旧 slicing/proof consumer 使用的 SharedStateReport。
    report: SharedStateReport
    # ledger 保存共享对象分类 pass 产生的 canonical UnknownFact。
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


def analyze_shared_state_with_evidence(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    threads: ThreadDiscoveryReport,
    memory_events: MemoryEventReport,
    partition_proofs: tuple[SymbolicPartitionProof, ...] = (),
    lifecycle_proof: SymbolicLifecycleProof | None = None,
    normal_completion_only: bool = False,
    *,
    scope: str = "static.shared_state",
) -> StaticSharedStateEvidence:
    """运行共享对象分类并返回旧报告与 canonical Unknown 的并行结果。"""

    ledger = EvidenceLedger()
    report = analyze_shared_state(
        module,
        control_flow,
        threads,
        memory_events,
        partition_proofs,
        lifecycle_proof,
        normal_completion_only,
        canonical_ledger=ledger,
        canonical_scope=scope,
    )
    return StaticSharedStateEvidence(report=report, ledger=ledger)


__all__ = [
    "StaticSharedStateEvidence",
    "analyze_shared_state_with_evidence",
]
