"""与具体 YAML/CLI 无关的 DBT memory-order contract。"""

from .model import (
    ContractError,
    ContractIssue,
    MemoryOrderContract,
    TargetFence,
    TargetOrdering,
    TranslationContract,
)
from .semantics import (
    AccessRange,
    MemoryAccessKind,
    MemoryOperation,
    RangeRelation,
    SemanticPrimitive,
    SemanticPrimitiveRef,
    ranges_overlap,
    relate_ranges,
    source_ppo_preserved,
)

__all__ = [
    "ContractError",
    "ContractIssue",
    "MemoryOrderContract",
    "TargetFence",
    "TargetOrdering",
    "TranslationContract",
    "AccessRange",
    "MemoryAccessKind",
    "MemoryOperation",
    "RangeRelation",
    "SemanticPrimitive",
    "SemanticPrimitiveRef",
    "ranges_overlap",
    "relate_ranges",
    "source_ppo_preserved",
]
