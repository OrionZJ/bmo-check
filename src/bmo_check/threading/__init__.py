"""从二进制调用点恢复 pthread 线程角色。"""

from .pthread import discover_pthread_threads

__all__ = ["discover_pthread_threads"]
