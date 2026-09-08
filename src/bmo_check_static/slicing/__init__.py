"""构建保守的跨线程共享内存切片。"""

from .slice_builder import build_shared_memory_slice
from .application_scope import restrict_to_application_scope

__all__ = ["build_shared_memory_slice", "restrict_to_application_scope"]
