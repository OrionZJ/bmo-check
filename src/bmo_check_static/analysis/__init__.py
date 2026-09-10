"""把二进制恢复结果转换为共享状态分析事实。"""

from .memory_events import extract_memory_events
from .evidence import (
    MemoryEvidenceError,
    MemoryEventIdentityLink,
    StaticMemoryEventEvidence,
    extract_memory_events_with_evidence,
)
from .lifecycle_symbolic import SymbolicLifecycleProof, prove_symbolic_lifecycle
from .partition_symbolic import SymbolicPartitionProof, prove_symbolic_partition
from .shared_state import analyze_shared_state

__all__ = [
    "SymbolicPartitionProof",
    "SymbolicLifecycleProof",
    "analyze_shared_state",
    "MemoryEvidenceError",
    "MemoryEventIdentityLink",
    "StaticMemoryEventEvidence",
    "extract_memory_events",
    "extract_memory_events_with_evidence",
    "prove_symbolic_partition",
    "prove_symbolic_lifecycle",
]
