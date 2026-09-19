"""从二进制调用点恢复 pthread 线程角色。"""

from .pthread import discover_pthread_threads
from .evidence import StaticThreadEvidence, discover_pthread_threads_with_evidence
from .lifecycle_adapter import characterize_thread_discovery
from .callback import (
    CallbackResolution,
    resolve_argument_locations,
    resolve_callback_targets,
    target_set_from_resolution,
)

__all__ = [
    "StaticThreadEvidence",
    "discover_pthread_threads",
    "discover_pthread_threads_with_evidence",
    "characterize_thread_discovery",
    "CallbackResolution",
    "resolve_argument_locations",
    "resolve_callback_targets",
    "target_set_from_resolution",
]
