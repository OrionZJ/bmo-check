"""static/dynamic execution-legality 的 characterization 比较。

这里故意只消费两个 route 的固定执行结果。比较层不重算 ``po/rf/co/fr``，
也不把差异转成 SAFE；发现 drift 时应回到对应 route 修正或标记支持边界。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class _ModelResult(Protocol):
    model: str
    status: str


class _ExecutionResult(Protocol):
    source: _ModelResult
    target: _ModelResult


class DifferentialStatus(StrEnum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True, slots=True)
class DifferentialComparison:
    """两个 route 对同一固定执行的逐模型比较结果。"""

    status: DifferentialStatus
    source_static: str
    source_dynamic: str
    target_static: str
    target_dynamic: str
    mismatches: tuple[str, ...] = ()


def compare_fixed_execution(
    static_result: _ExecutionResult,
    dynamic_result: _ExecutionResult,
) -> DifferentialComparison:
    """比较 source/target legality；Unknown 不会被当成匹配。"""

    values = {
        "source": (static_result.source.status, dynamic_result.source.status),
        "target": (static_result.target.status, dynamic_result.target.status),
    }
    mismatches = tuple(
        f"{model}: static={static!r}, dynamic={dynamic!r}"
        for model, (static, dynamic) in values.items()
        if static != dynamic
    )
    statuses = tuple(status for pair in values.values() for status in pair)
    if any(status == "unknown" for status in statuses):
        status = DifferentialStatus.INCOMPLETE
    elif mismatches:
        status = DifferentialStatus.MISMATCH
    else:
        status = DifferentialStatus.MATCH
    return DifferentialComparison(
        status=status,
        source_static=static_result.source.status,
        source_dynamic=dynamic_result.source.status,
        target_static=static_result.target.status,
        target_dynamic=dynamic_result.target.status,
        mismatches=mismatches,
    )


__all__ = [
    "DifferentialComparison",
    "DifferentialStatus",
    "compare_fixed_execution",
]
