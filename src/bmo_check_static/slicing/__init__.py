"""构建保守的跨线程共享内存切片。"""

from .slice_builder import build_shared_memory_slice
from .application_scope import restrict_to_application_scope
from .evidence import (
    SliceEvidenceError,
    SliceProofLink,
    StaticSliceEvidence,
    build_shared_memory_slice_with_evidence,
)

__all__ = [
    "SliceEvidenceError",
    "SliceProofLink",
    "StaticSliceEvidence",
    "build_shared_memory_slice",
    "build_shared_memory_slice_with_evidence",
    "restrict_to_application_scope",
]
