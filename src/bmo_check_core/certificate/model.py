from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from ..identity import BinaryClosureId, EvidenceId, MemoryEventId, StableId, TraceId


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CertificateError(ValueError):
    """证书或证书绑定无法满足 canonical 契约时抛出的错误。"""


class CertificateVerdict(StrEnum):
    # SAFE 只允许 proof closure 完整且不是 bounded 结果。
    SAFE = "SAFE"
    # COUNTEREXAMPLE 表示已有 target-only witness；具体 witness 由 route 保存。
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    # UNKNOWN 表示仍有未闭合的 proof obligation 或输入限制。
    UNKNOWN = "UNKNOWN"


class TraceVerdict(StrEnum):
    # TRACE_SAFE 只覆盖绑定的单条执行轨迹。
    TRACE_SAFE = "TRACE_SAFE"
    # COUNTEREXAMPLE 仍必须绑定同一条 trace，不能外推到其他输入。
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    # UNKNOWN 表示轨迹不完整、模型不支持或资源预算耗尽。
    UNKNOWN = "UNKNOWN"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CertificateError(f"{name} must be a non-empty string without NUL")
    return value


def _sha256(name: str, value: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise CertificateError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _evidence_ids(name: str, values: tuple[EvidenceId, ...]) -> tuple[EvidenceId, ...]:
    normalized: list[EvidenceId] = []
    for value in values:
        if not isinstance(value, EvidenceId):
            raise CertificateError(f"{name} must contain EvidenceId values")
        normalized.append(value)
    return tuple(sorted(set(normalized), key=lambda item: item.value))


@dataclass(frozen=True, slots=True)
class CertificateBinding:
    # binary_closure 绑定 executable、库集合和 ABI，不能只比较主程序路径。
    binary_closure: BinaryClosureId
    # dbt_contract_version 绑定实际 lowering 契约的字段解释。
    dbt_contract_version: str
    # dbt_revision 绑定实现提交，防止同一契约名指向不同代码。
    dbt_revision: str
    # scope 限定证书可以覆盖的静态或应用范围。
    scope: str

    def __post_init__(self) -> None:
        if not isinstance(self.binary_closure, BinaryClosureId):
            raise CertificateError("certificate binary_closure must be a BinaryClosureId")
        _text("DBT contract version", self.dbt_contract_version)
        _text("DBT revision", self.dbt_revision)
        _text("certificate scope", self.scope)


@dataclass(frozen=True, slots=True)
class RemovalDecision:
    # event_id 指向被剪除的静态访存事件。
    event_id: MemoryEventId
    # proof_id 指向覆盖该事件的 ProofFact。
    proof_id: EvidenceId
    # scope 防止把另一证书范围的证明拼进当前证书。
    scope: str

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, MemoryEventId):
            raise CertificateError("removal event_id must be a MemoryEventId")
        if not isinstance(self.proof_id, EvidenceId):
            raise CertificateError("removal proof_id must be an EvidenceId")
        _text("removal scope", self.scope)


@dataclass(frozen=True, slots=True)
class CertificateCompleteness:
    """v2 certificate 必须绑定的四类 universe/obligation 摘要。"""

    # event_universe_sha256 对账静态输入 event 的完整集合和 disposition。
    event_universe_sha256: str
    # obligation_sha256 对账 checker 实际需要闭合的 proposition 集合。
    obligation_sha256: str
    # unknown_sha256 对账 scope 内所有 relevant Unknown identity。
    unknown_sha256: str
    # projection_sha256 对账 relation projection 及其 preservation disposition。
    projection_sha256: str

    def __post_init__(self) -> None:
        _sha256("event universe digest", self.event_universe_sha256)
        _sha256("obligation digest", self.obligation_sha256)
        _sha256("Unknown digest", self.unknown_sha256)
        _sha256("projection digest", self.projection_sha256)


@dataclass(frozen=True, slots=True)
class StaticCertificate:
    # schema_version 让 replay verifier 可以拒绝未知证书格式。
    schema_version: str
    # verdict 只表达静态域的结论，不复用 trace verdict。
    verdict: CertificateVerdict
    # binding 固定 binary、DBT 实现和分析范围。
    binding: CertificateBinding
    # proof_roots 是 SAFE closure 的入口，所有可达节点必须是 ProofFact。
    proof_roots: tuple[EvidenceId, ...] = ()
    # removal_decisions 把每个被移除 event 绑定到一个 proof root/closure。
    removal_decisions: tuple[RemovalDecision, ...] = ()
    # relevant_unknowns 必须逐项保留，直到被显式 proof discharge。
    relevant_unknowns: tuple[EvidenceId, ...] = ()
    # bounded=True 的有限搜索不能伪装成 SAFE。
    bounded: bool = False
    # v2 才允许携带 completeness；v1 缺字段只能走 legacy/UNKNOWN 边界。
    completeness: CertificateCompleteness | None = None

    def __post_init__(self) -> None:
        _text("certificate schema version", self.schema_version)
        if not isinstance(self.verdict, CertificateVerdict):
            raise CertificateError("static certificate verdict must be CertificateVerdict")
        if not isinstance(self.binding, CertificateBinding):
            raise CertificateError("static certificate binding is invalid")
        object.__setattr__(
            self,
            "proof_roots",
            _evidence_ids("proof_roots", self.proof_roots),
        )
        object.__setattr__(
            self,
            "relevant_unknowns",
            _evidence_ids("relevant_unknowns", self.relevant_unknowns),
        )
        decisions = tuple(self.removal_decisions)
        if any(not isinstance(item, RemovalDecision) for item in decisions):
            raise CertificateError("removal_decisions must contain RemovalDecision values")
        object.__setattr__(
            self,
            "removal_decisions",
            tuple(
                sorted(
                    set(decisions),
                    key=lambda item: (item.event_id.value, item.proof_id.value, item.scope),
                )
            ),
        )
        if not isinstance(self.bounded, bool):
            raise CertificateError("certificate bounded must be boolean")
        if self.schema_version == "static-certificate-v2" and self.completeness is None:
            raise CertificateError("static-certificate-v2 requires completeness")
        if self.schema_version != "static-certificate-v2" and self.completeness is not None:
            raise CertificateError(
                "certificate completeness requires static-certificate-v2"
            )


@dataclass(frozen=True, slots=True)
class TraceCertificate:
    # schema_version 让 trace certificate 的字段解释可以独立演进。
    schema_version: str
    # verdict 使用独立枚举，防止 TRACE_SAFE 被误当静态 SAFE。
    verdict: TraceVerdict
    # binding 绑定执行所用 binary、DBT 和 scope。
    binding: CertificateBinding
    # trace_id 限定这份证书只适用于一条实际轨迹。
    trace_id: TraceId
    # observed_roots 只能指向该 trace 的 ObservedFact。
    observed_roots: tuple[EvidenceId, ...] = ()
    # complete=False 时任何 trace 结论都不能升级为 TRACE_SAFE。
    complete: bool = False

    def __post_init__(self) -> None:
        _text("trace certificate schema version", self.schema_version)
        if not isinstance(self.verdict, TraceVerdict):
            raise CertificateError("trace certificate verdict must be TraceVerdict")
        if not isinstance(self.binding, CertificateBinding):
            raise CertificateError("trace certificate binding is invalid")
        if not isinstance(self.trace_id, TraceId):
            raise CertificateError("trace certificate trace_id must be a TraceId")
        object.__setattr__(
            self,
            "observed_roots",
            _evidence_ids("observed_roots", self.observed_roots),
        )
        if not isinstance(self.complete, bool):
            raise CertificateError("trace certificate complete must be boolean")


__all__ = [
    "CertificateBinding",
    "CertificateCompleteness",
    "CertificateError",
    "CertificateVerdict",
    "RemovalDecision",
    "StaticCertificate",
    "TraceCertificate",
    "TraceVerdict",
]
