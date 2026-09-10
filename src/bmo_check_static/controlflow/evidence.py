"""CFG producer 的 canonical evidence 旁路结果。"""

from __future__ import annotations

from dataclasses import dataclass

from bmo_check_core import EvidenceId, EvidenceLedger, UnknownFact
from bmo_check_static.model import ControlFlowReport


@dataclass(frozen=True, slots=True)
class StaticControlFlowEvidence:
    # report 保留旧 CFG consumers 使用的控制流事实。
    report: ControlFlowReport
    # ledger 保存 CFG producer 同步生成的 canonical UnknownFact。
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


__all__ = ["StaticControlFlowEvidence"]
