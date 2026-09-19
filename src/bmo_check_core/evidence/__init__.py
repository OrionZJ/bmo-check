"""静态证明、动态观察和诊断提示的类型边界。"""

from .model import (
    DiagnosticHint,
    EvidenceAttribute,
    EvidenceCategory,
    EvidenceMaterialError,
    EvidenceNode,
    ObservedFact,
    ProofConclusion,
    ProofFact,
    RegisteredProofRule,
    ProducerId,
    UnknownDischarge,
    UnknownFact,
    UnknownKind,
    UnknownProposition,
)
from .ledger import EvidenceLedger, LedgerError
from .rules import (
    ProofRuleDefinition,
    ProofRuleRegistry,
    ProofRuleReplay,
    ProofRuleReplayStatus,
    replay_proof_rule,
)

__all__ = [
    "DiagnosticHint",
    "EvidenceAttribute",
    "EvidenceCategory",
    "EvidenceLedger",
    "EvidenceMaterialError",
    "EvidenceNode",
    "LedgerError",
    "ProofRuleDefinition",
    "ProofRuleRegistry",
    "ProofRuleReplay",
    "ProofRuleReplayStatus",
    "ObservedFact",
    "ProofConclusion",
    "ProofFact",
    "RegisteredProofRule",
    "ProducerId",
    "UnknownDischarge",
    "UnknownFact",
    "UnknownKind",
    "UnknownProposition",
    "replay_proof_rule",
]
