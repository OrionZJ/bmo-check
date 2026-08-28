"""从具体动态库指令生成同步原语摘要。"""

from .pthread import analyze_pthread_synchronization

__all__ = ["analyze_pthread_synchronization"]
