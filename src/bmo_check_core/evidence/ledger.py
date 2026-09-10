from __future__ import annotations

from dataclasses import dataclass, field

from ..identity import EvidenceId
from .model import (
    DiagnosticHint,
    EvidenceNode,
    ObservedFact,
    ProofFact,
    UnknownDischarge,
    UnknownFact,
)


class LedgerError(ValueError):
    """证据图违反父节点、类别或内容约束时抛出的错误。"""


@dataclass(slots=True)
class EvidenceLedger:
    """保存不可变证据节点，并在进入图时检查跨类别边界。"""

    # _nodes 是追加式事实表；删除节点会破坏已有证书的可追溯性。
    _nodes: dict[EvidenceId, EvidenceNode] = field(default_factory=dict, init=False)
    # _discharges 单独记录 Unknown 的关闭依据，不能把 Unknown 从节点表抹掉。
    _discharges: dict[EvidenceId, UnknownDischarge] = field(
        default_factory=dict, init=False
    )

    def add(self, node: EvidenceNode) -> EvidenceId:
        if not isinstance(node, (ProofFact, ObservedFact, DiagnosticHint, UnknownFact)):
            raise LedgerError("unsupported evidence node type")
        expected = node.expected_id()
        if node.id != expected:
            raise LedgerError(
                f"evidence id/content mismatch for {node.id.value}; expected {expected.value}"
            )
        existing = self._nodes.get(node.id)
        if existing is not None:
            if existing != node:
                raise LedgerError(f"duplicate evidence id has different content: {node.id.value}")
            return node.id
        self._validate_edges(node)
        self._nodes[node.id] = node
        return node.id

    def add_discharge(self, discharge: UnknownDischarge) -> None:
        unknown = self._nodes.get(discharge.unknown_id)
        proof = self._nodes.get(discharge.proof_id)
        if not isinstance(unknown, UnknownFact):
            raise LedgerError("discharge must reference an existing UnknownFact")
        if not isinstance(proof, ProofFact):
            raise LedgerError("discharge must reference an existing ProofFact")
        if discharge.scope != unknown.scope or discharge.scope != proof.scope:
            raise LedgerError("discharge scope must match both UnknownFact and ProofFact")
        existing = self._discharges.get(discharge.unknown_id)
        if existing is not None and existing != discharge:
            raise LedgerError("an UnknownFact cannot have conflicting discharges")
        self._discharges[discharge.unknown_id] = discharge

    def get(self, evidence_id: EvidenceId) -> EvidenceNode | None:
        return self._nodes.get(evidence_id)

    def nodes(self) -> tuple[EvidenceNode, ...]:
        return tuple(self._nodes[key] for key in sorted(self._nodes, key=lambda item: item.value))

    def discharges(self) -> tuple[UnknownDischarge, ...]:
        return tuple(
            self._discharges[key]
            for key in sorted(self._discharges, key=lambda item: item.value)
        )

    def unresolved_unknowns(self, scope: str | None = None) -> tuple[UnknownFact, ...]:
        unknowns = (
            node
            for node in self._nodes.values()
            if isinstance(node, UnknownFact)
            and (scope is None or node.scope == scope)
            and node.id not in self._discharges
        )
        return tuple(sorted(unknowns, key=lambda item: item.id.value))

    def proof_closure(self, roots: tuple[EvidenceId, ...]) -> tuple[ProofFact, ...]:
        """只沿 ProofFact 前提回溯；观察或提示不能伪装成静态证明。"""

        visited: set[EvidenceId] = set()
        ordered: list[ProofFact] = []

        def visit(evidence_id: EvidenceId) -> None:
            if evidence_id in visited:
                return
            visited.add(evidence_id)
            node = self._nodes.get(evidence_id)
            if not isinstance(node, ProofFact):
                raise LedgerError("static proof closure reached non-ProofFact evidence")
            for premise in node.premises:
                visit(premise)
            ordered.append(node)

        for root in roots:
            visit(root)
        return tuple(ordered)

    def _validate_edges(self, node: EvidenceNode) -> None:
        if isinstance(node, ProofFact):
            for premise in node.premises:
                parent = self._nodes.get(premise)
                if parent is None:
                    raise LedgerError(f"missing proof premise: {premise.value}")
                if not isinstance(parent, ProofFact):
                    raise LedgerError("ProofFact premises may reference only ProofFact")
            return
        if isinstance(node, UnknownFact):
            for parent_id in node.provenance:
                parent = self._nodes.get(parent_id)
                if parent is None:
                    raise LedgerError(f"missing Unknown provenance: {parent_id.value}")
                if isinstance(parent, (ObservedFact, DiagnosticHint)):
                    raise LedgerError(
                        "UnknownFact provenance cannot depend on dynamic observations or hints"
                    )
            return
        if isinstance(node, ObservedFact):
            return
        for unknown_id in node.unknown_ids:
            parent = self._nodes.get(unknown_id)
            if parent is None:
                raise LedgerError(f"missing diagnostic UnknownFact: {unknown_id.value}")
            if not isinstance(parent, UnknownFact):
                raise LedgerError("DiagnosticHint unknown_ids must reference UnknownFact")
        for observed_id in node.observed_ids:
            parent = self._nodes.get(observed_id)
            if parent is None:
                raise LedgerError(f"missing diagnostic ObservedFact: {observed_id.value}")
            if not isinstance(parent, ObservedFact):
                raise LedgerError("DiagnosticHint observed_ids must reference ObservedFact")
