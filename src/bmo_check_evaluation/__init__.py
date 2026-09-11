"""PARSEC 评测应用服务。

评测编排只依赖静态分析的 typed service 和报告模型；静态 CLI 不再承载
benchmark 循环，也不会被评测服务反向调用。
"""

from .parsec import (
    EvaluationApplicationError,
    ParsecEvaluationRequest,
    run_parsec,
)

__all__ = [
    "EvaluationApplicationError",
    "ParsecEvaluationRequest",
    "run_parsec",
]
