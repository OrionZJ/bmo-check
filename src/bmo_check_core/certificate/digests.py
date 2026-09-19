"""Certificate completeness 的稳定内容摘要。

这些摘要只绑定 typed ledger 的内容，不把摘要本身当作 proof。verifier 仍需
先重建 ledger，再比较摘要；少字段、改字段或换 scope 都不能靠提交新的空摘要
恢复确定性结论。
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from ..identity import EvidenceId
from ..obligations import ObligationInventory
from ..projection import ProjectionLedger
from ..universe import EventUniverseLedger


def _digest(material: object) -> str:
    encoded = json.dumps(
        material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def digest_event_universe(ledger: EventUniverseLedger) -> str:
    """摘要 event universe、每项 disposition 以及 completeness 状态。"""

    if not isinstance(ledger, EventUniverseLedger):
        raise TypeError("digest_event_universe expects an EventUniverseLedger")
    return _digest(
        {
            "stage": ledger.stage,
            "input_event_ids": [item.value for item in ledger.input_event_ids],
            "entries": [
                {
                    "event_id": entry.event_id.value,
                    "disposition": entry.disposition.value,
                    "proof_ids": [item.value for item in entry.proof_ids],
                    "unknown_ids": [item.value for item in entry.unknown_ids],
                }
                for entry in ledger.entries
            ],
            "completeness": {
                "status": ledger.completeness.status.value,
                "scope": ledger.completeness.scope,
                "reason": ledger.completeness.reason,
            },
        }
    )


def digest_obligation_inventory(inventory: ObligationInventory) -> str:
    """摘要 obligation identity、proposition、subjects 和枚举状态。"""

    if not isinstance(inventory, ObligationInventory):
        raise TypeError("digest_obligation_inventory expects an ObligationInventory")
    return _digest(
        {
            "scope": inventory.scope,
            "obligations": [
                {
                    "id": item.id.value,
                    "proposition_id": item.proposition_id.value,
                    "kind": item.kind.value,
                    "scope": item.scope,
                    "subjects": [subject.value for subject in item.subjects],
                }
                for item in inventory.obligations
            ],
            "completeness": {
                "status": inventory.completeness.status.value,
                "scope": inventory.completeness.scope,
                "reason": inventory.completeness.reason,
            },
        }
    )


def digest_projection_ledger(ledger: ProjectionLedger) -> str:
    """摘要 relation universe、preservation disposition 和 rule identity。"""

    if not isinstance(ledger, ProjectionLedger):
        raise TypeError("digest_projection_ledger expects a ProjectionLedger")
    return _digest(
        {
            "stage": ledger.stage,
            "input_relation_ids": [item.value for item in ledger.input_relation_ids],
            "entries": [
                {
                    "relation_id": entry.relation_id.value,
                    "disposition": entry.disposition.value,
                    "proof_ids": [item.value for item in entry.proof_ids],
                    "unknown_ids": [item.value for item in entry.unknown_ids],
                }
                for entry in ledger.entries
            ],
            "preservation_rule": (
                ledger.preservation_rule.value
                if ledger.preservation_rule is not None
                else None
            ),
            "completeness": {
                "status": ledger.completeness.status.value,
                "scope": ledger.completeness.scope,
                "reason": ledger.completeness.reason,
            },
        }
    )


def digest_unknown_ids(scope: str, ids: Iterable[EvidenceId]) -> str:
    """摘要 scope 与 relevant Unknown identity，不把数量当作完整性证明。"""

    if not isinstance(scope, str) or not scope or "\x00" in scope:
        raise ValueError("Unknown digest scope must be a non-empty string")
    normalized = tuple(sorted({item.value for item in ids}))
    return _digest({"scope": scope, "unknown_ids": normalized})


__all__ = [
    "digest_event_universe",
    "digest_obligation_inventory",
    "digest_projection_ledger",
    "digest_unknown_ids",
]
