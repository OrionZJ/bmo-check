"""依赖闭包 producer 的 canonical evidence 旁路结果。

这个旁路 API 让 C6 可以先迁移一个 producer，而不改变旧的
``build_program_manifest`` 返回类型。旧 manifest 仍由调用者负责消费，ledger
只保存同一 producer 同步生成的静态 Unknown；没有动态观察入口。
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from bmo_check_core import (
    EvidenceId,
    EvidenceLedger,
    ProducerId,
    UnknownFact as CanonicalUnknownFact,
    UnknownKind as CanonicalUnknownKind,
)
from bmo_check_static.model import (
    ProgramManifest,
    UnknownFact as LegacyUnknownFact,
    UnknownKind as LegacyUnknownKind,
)


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
                    if isinstance(node, CanonicalUnknownFact)
                },
                key=lambda item: item.value,
            )
        )


def emit_static_unknown(
    kind: LegacyUnknownKind,
    reason: str,
    impact: str,
    *,
    module: str | None = None,
    pc: int | None = None,
    function: str | None = None,
    details: dict[str, object] | None = None,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.recovery",
) -> LegacyUnknownFact:
    """同时生成旧 Unknown 和可选的 canonical Unknown。

    旧报告仍需要 Pydantic 事实；传入 ledger 时，producer 还会把同一个缺口
    写入 canonical 图。两个结果来自同一组字段，调用者不会自行拼出第二套原因。
    """

    legacy = LegacyUnknownFact(
        kind=kind,
        reason=reason,
        impact=impact,
        module=module,
        pc=pc,
        function=function,
        details=details or {},
    )
    if canonical_ledger is None:
        return legacy
    try:
        canonical_kind = CanonicalUnknownKind(kind.value)
    except ValueError:
        canonical_kind = CanonicalUnknownKind.UNKNOWN_ROOT_CAUSE
    context = [
        f"legacy.impact={impact}",
        f"legacy.kind={kind.value}",
    ]
    if module is not None:
        context.append(f"legacy.module={module}")
    if pc is not None:
        context.append(f"legacy.pc={pc:#x}")
    if function is not None:
        context.append(f"legacy.function={function}")
    for key in sorted(legacy.details):
        if not isinstance(key, str):
            raise ValueError("legacy recovery details keys must be strings")
        try:
            value = json.dumps(
                legacy.details[key],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"legacy recovery detail {key!r} is not canonical JSON"
            ) from error
        context.append(f"legacy.detail.{key}={value}")
    canonical_ledger.add(
        CanonicalUnknownFact.create(
            schema_version="static-recovery-1",
            producer=ProducerId("bmo_check_static.recovery", "c6"),
            kind=canonical_kind,
            reason=reason,
            subject=None,
            scope=canonical_scope,
            supporting_context=tuple(sorted(context)),
        )
    )
    return legacy


__all__ = ["StaticRecoveryEvidence", "emit_static_unknown"]
