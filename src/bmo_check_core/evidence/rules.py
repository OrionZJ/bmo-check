"""registered proof rule 的最小 registry 与 replay contract。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .ledger import EvidenceLedger
from .model import ProofFact, RegisteredProofRule


class ProofRuleReplayStatus(StrEnum):
    """规则 replay 只报告输入是否可检查，不产生 verdict。"""

    # VALID 表示字段、registry 和 premise 类型都满足 contract。
    VALID = "valid"
    # INCOMPLETE 表示 legacy proof、缺 registry 或缺 conclusion。
    INCOMPLETE = "incomplete"
    # MISMATCH 表示 typed 字段之间明确冲突。
    MISMATCH = "mismatch"


@dataclass(frozen=True, slots=True)
class ProofRuleDefinition:
    """一个可被 replay verifier 识别的 rule 定义。"""

    # identity 绑定 rule name/version，不能只用旧的裸 rule 字符串。
    identity: RegisteredProofRule
    # legacy_name 让新 rule 与现有 ProofFact.rule 显式对应。
    legacy_name: str
    # 当前所有注册 rule 都要求 typed conclusion；兼容性由 registry 选择。
    requires_conclusion: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.identity, RegisteredProofRule):
            raise ValueError("rule definition identity must be a RegisteredProofRule")
        if not isinstance(self.legacy_name, str) or not self.legacy_name:
            raise ValueError("rule definition legacy_name must be non-empty")
        if not isinstance(self.requires_conclusion, bool):
            raise ValueError("rule definition requires_conclusion must be boolean")


@dataclass(frozen=True, slots=True)
class ProofRuleRegistry:
    """不可变的 rule registry；producer 不能在 replay 时临时注册规则。"""

    # definitions 是版本化 rule 的完整集合，顺序不参与 lookup 语义。
    definitions: tuple[ProofRuleDefinition, ...]

    def __post_init__(self) -> None:
        if any(not isinstance(item, ProofRuleDefinition) for item in self.definitions):
            raise ValueError("rule registry definitions must be typed")
        identities = tuple(item.identity.value for item in self.definitions)
        if len(identities) != len(set(identities)):
            raise ValueError("rule registry contains duplicate identities")
        object.__setattr__(
            self,
            "definitions",
            tuple(sorted(self.definitions, key=lambda item: item.identity.value)),
        )

    def resolve(self, identity: RegisteredProofRule) -> ProofRuleDefinition | None:
        for definition in self.definitions:
            if definition.identity == identity:
                return definition
        return None


@dataclass(frozen=True, slots=True)
class ProofRuleReplay:
    """一次 rule replay contract 检查的结果。"""

    # status 只表达 rule 输入是否完整，不等价于 proof 成立或 SAFE。
    status: ProofRuleReplayStatus
    # reason 记录缺字段或冲突，供 certificate verifier 继续保守失败。
    reason: str


def replay_proof_rule(
    proof: ProofFact,
    ledger: EvidenceLedger,
    registry: ProofRuleRegistry,
) -> ProofRuleReplay:
    """检查 typed rule/conclusion/premise contract，不执行定理证明。"""

    if not isinstance(proof, ProofFact):
        return ProofRuleReplay(
            ProofRuleReplayStatus.MISMATCH,
            "replay subject is not a ProofFact",
        )
    if proof.registered_rule is None or proof.conclusion is None:
        return ProofRuleReplay(
            ProofRuleReplayStatus.INCOMPLETE,
            "legacy proof is missing registered rule or conclusion",
        )
    definition = registry.resolve(proof.registered_rule)
    if definition is None:
        return ProofRuleReplay(
            ProofRuleReplayStatus.INCOMPLETE,
            "proof rule is not present in the registry",
        )
    if proof.rule != definition.legacy_name:
        return ProofRuleReplay(
            ProofRuleReplayStatus.MISMATCH,
            "legacy rule name does not match registered rule",
        )
    if definition.requires_conclusion and proof.conclusion.scope != proof.scope:
        return ProofRuleReplay(
            ProofRuleReplayStatus.MISMATCH,
            "proof conclusion scope does not match proof scope",
        )
    for premise_id in proof.premises:
        if not isinstance(ledger.get(premise_id), ProofFact):
            return ProofRuleReplay(
                ProofRuleReplayStatus.MISMATCH,
                "proof premise is not a ProofFact in the ledger",
            )
    return ProofRuleReplay(ProofRuleReplayStatus.VALID, "typed rule contract is complete")


__all__ = [
    "ProofRuleDefinition",
    "ProofRuleRegistry",
    "ProofRuleReplay",
    "ProofRuleReplayStatus",
    "replay_proof_rule",
]
