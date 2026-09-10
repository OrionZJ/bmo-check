"""依赖闭包 producer 的 canonical evidence 旁路结果。

这个旁路 API 让 C6 可以先迁移一个 producer，而不改变旧的
``build_program_manifest`` 返回类型。旧 manifest 仍由调用者负责消费，ledger
只保存同一 producer 同步生成的静态 Unknown；没有动态观察入口。
"""

from __future__ import annotations

from dataclasses import dataclass

from bmo_check_core import EvidenceId, EvidenceLedger, UnknownFact
from bmo_check_static.model import ProgramManifest


@dataclass(frozen=True, slots=True)
class StaticRecoveryEvidence:
    # manifest 保留旧 CLI 和后续恢复阶段需要的 Pydantic 闭包结果。
    manifest: ProgramManifest
    # ledger 保存依赖闭包 producer 同步产生的 canonical UnknownFact。
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


__all__ = ["StaticRecoveryEvidence"]
