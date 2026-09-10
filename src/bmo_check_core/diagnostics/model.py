"""dynamic-assisted diagnostics 使用的只读 evidence snapshot。"""

from __future__ import annotations

from dataclasses import dataclass

from ..certificate import CertificateVerdict
from ..evidence import (
    DiagnosticHint,
    EvidenceLedger,
    EvidenceNode,
    ObservedFact,
    ProofFact,
    UnknownDischarge,
    UnknownFact,
)
from ..identity import BinaryClosureId, EvidenceId, StableId, TraceId


class SnapshotError(ValueError):
    """snapshot 混入错误证据类别、scope 或 trace 时抛出的错误。"""


def _non_empty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SnapshotError(f"{name} must be a non-empty string without NUL")


def _replay(
    nodes: tuple[EvidenceNode, ...],
    discharges: tuple[UnknownDischarge, ...],
) -> EvidenceLedger:
    """按依赖顺序重放 immutable tuple，避免暴露内部可变 ledger。"""

    ledger = EvidenceLedger()
    pending = {node.id: node for node in nodes}
    while pending:
        progressed = False
        for evidence_id in sorted(pending, key=lambda item: item.value):
            node = pending[evidence_id]
            try:
                ledger.add(node)
            except ValueError:
                continue
            del pending[evidence_id]
            progressed = True
        if not progressed:
            raise SnapshotError("evidence snapshot contains an invalid dependency graph")
    for discharge in sorted(
        discharges,
        key=lambda item: (item.unknown_id.value, item.proof_id.value),
    ):
        try:
            ledger.add_discharge(discharge)
        except ValueError as error:
            raise SnapshotError(f"invalid evidence discharge: {error}") from error
    return ledger


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    """可序列化的 immutable evidence 视图；每次查询都生成新的 ledger。"""

    # nodes 保留完整事实，不允许诊断层只接收一个丢失 Unknown 的摘要。
    nodes: tuple[EvidenceNode, ...] = ()
    # discharges 保留 Unknown 的关闭记录，不能因快照而删除 Unknown 节点。
    discharges: tuple[UnknownDischarge, ...] = ()

    def __post_init__(self) -> None:
        if any(not isinstance(node, (ProofFact, ObservedFact, DiagnosticHint, UnknownFact))
               for node in self.nodes):
            raise SnapshotError("evidence snapshot contains an unsupported node")
        _replay(tuple(self.nodes), tuple(self.discharges))
        object.__setattr__(
            self,
            "nodes",
            tuple(sorted(self.nodes, key=lambda node: node.id.value)),
        )
        object.__setattr__(
            self,
            "discharges",
            tuple(
                sorted(
                    self.discharges,
                    key=lambda item: (item.unknown_id.value, item.proof_id.value),
                )
            ),
        )

    def ledger(self) -> EvidenceLedger:
        """返回独立副本；调用者修改它不会改变 snapshot。"""

        return _replay(self.nodes, self.discharges)

    def ids(self) -> tuple[EvidenceId, ...]:
        return tuple(node.id for node in self.nodes)


@dataclass(frozen=True, slots=True)
class StaticDiagnosticSnapshot:
    # schema_version 绑定诊断输入字段，不能由 trace 版本代替。
    schema_version: str
    # scope 限定 Unknown 与 proof 可以被哪个静态结论消费。
    scope: str
    # verdict 只描述已经完成的静态分析，不因诊断观察而变化。
    verdict: CertificateVerdict
    # evidence 只允许 ProofFact/UnknownFact，拒绝动态观察混入静态域。
    evidence: EvidenceSnapshot
    # binary_closure 用实际 ELF/库 hash 绑定相关范围；缺失时只能模糊匹配。
    binary_closure: BinaryClosureId | None = None
    # subject_ids 让报告回查指令、事件和对象，不依赖临时数组序号。
    subject_ids: tuple[StableId, ...] = ()

    def __post_init__(self) -> None:
        _non_empty("snapshot schema_version", self.schema_version)
        _non_empty("static snapshot scope", self.scope)
        if not isinstance(self.verdict, CertificateVerdict):
            raise SnapshotError("static snapshot verdict must be CertificateVerdict")
        if not isinstance(self.evidence, EvidenceSnapshot):
            raise SnapshotError("static snapshot evidence is invalid")
        if self.binary_closure is not None and not isinstance(
            self.binary_closure, BinaryClosureId
        ):
            raise SnapshotError("static snapshot binary_closure is invalid")
        if any(not isinstance(item, StableId) for item in self.subject_ids):
            raise SnapshotError("static snapshot subjects must be StableId values")
        for node in self.evidence.nodes:
            if not isinstance(node, (ProofFact, UnknownFact)):
                raise SnapshotError(
                    "static diagnostic snapshot cannot contain observations or hints"
                )
            if node.scope != self.scope:
                raise SnapshotError("static evidence scope does not match snapshot")
        object.__setattr__(
            self,
            "subject_ids",
            tuple(sorted(set(self.subject_ids), key=lambda item: item.value)),
        )

    @property
    def unknown_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            node.id
            for node in self.evidence.nodes
            if isinstance(node, UnknownFact)
        )

    @property
    def proof_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            node.id
            for node in self.evidence.nodes
            if isinstance(node, ProofFact)
        )

    def ledger(self) -> EvidenceLedger:
        """返回静态证据副本，报告层不能修改 snapshot 内部。"""

        return self.evidence.ledger()


@dataclass(frozen=True, slots=True)
class DynamicDiagnosticSnapshot:
    # schema_version 与静态 snapshot 分开，避免混用不同 trace 事件格式。
    schema_version: str
    # trace_id 把每个 ObservedFact 限定在一条实际执行。
    trace_id: TraceId
    # scope 限定动态 Unknown 的采集范围和资源预算。
    scope: str
    # complete=False 时诊断只能解释缺口，不能生成 TRACE_SAFE。
    complete: bool
    # evidence 允许 ObservedFact/UnknownFact，不允许静态 ProofFact。
    evidence: EvidenceSnapshot
    # binary_closure 必须与静态 snapshot 相同，才能把 stable subject 当作 Exact。
    binary_closure: BinaryClosureId | None = None

    def __post_init__(self) -> None:
        _non_empty("snapshot schema_version", self.schema_version)
        if not isinstance(self.trace_id, TraceId):
            raise SnapshotError("dynamic snapshot trace_id is invalid")
        _non_empty("dynamic snapshot scope", self.scope)
        if not isinstance(self.complete, bool):
            raise SnapshotError("dynamic snapshot complete must be boolean")
        if not isinstance(self.evidence, EvidenceSnapshot):
            raise SnapshotError("dynamic snapshot evidence is invalid")
        if self.binary_closure is not None and not isinstance(
            self.binary_closure, BinaryClosureId
        ):
            raise SnapshotError("dynamic snapshot binary_closure is invalid")
        for node in self.evidence.nodes:
            if not isinstance(node, (ObservedFact, UnknownFact)):
                raise SnapshotError(
                    "dynamic diagnostic snapshot cannot contain static proof or hint"
                )
            if isinstance(node, ObservedFact) and node.trace_id != self.trace_id:
                raise SnapshotError("ObservedFact belongs to another trace")
            if isinstance(node, UnknownFact) and node.scope != self.scope:
                raise SnapshotError("dynamic evidence scope does not match snapshot")

    @property
    def observed_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            node.id
            for node in self.evidence.nodes
            if isinstance(node, ObservedFact)
        )

    @property
    def unknown_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            node.id
            for node in self.evidence.nodes
            if isinstance(node, UnknownFact)
        )

    def ledger(self) -> EvidenceLedger:
        """返回动态证据副本，后续诊断不得回写采集结果。"""

        return self.evidence.ledger()


__all__ = [
    "DynamicDiagnosticSnapshot",
    "EvidenceSnapshot",
    "SnapshotError",
    "StaticDiagnosticSnapshot",
]
