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


class DifferentialClassification(StrEnum):
    """对 route 比较结果的审计分类，而不是最终 verdict。"""

    EQUIVALENT = "EQUIVALENT"
    INTENDED_ROUTE_DIFFERENCE = "INTENDED_ROUTE_DIFFERENCE"
    UNRESOLVED_MODEL_DRIFT = "UNRESOLVED_MODEL_DRIFT"
    UNSUPPORTED_BY_STATIC = "UNSUPPORTED_BY_STATIC"
    UNSUPPORTED_BY_DYNAMIC = "UNSUPPORTED_BY_DYNAMIC"


@dataclass(frozen=True, slots=True)
class DifferentialComparison:
    """两个 route 对同一固定执行的逐模型比较结果。"""

    status: DifferentialStatus
    source_static: str
    source_dynamic: str
    target_static: str
    target_dynamic: str
    mismatches: tuple[str, ...] = ()
    classification: DifferentialClassification = DifferentialClassification.EQUIVALENT
    classification_reason: str = ""


def compare_fixed_execution(
    static_result: _ExecutionResult,
    dynamic_result: _ExecutionResult,
    *,
    expected: DifferentialClassification | None = None,
    expected_reason: str = "",
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
    statuses = tuple(status.lower() for pair in values.values() for status in pair)
    static_statuses = tuple(status.lower() for status in (static_result.source.status, static_result.target.status))
    dynamic_statuses = tuple(status.lower() for status in (dynamic_result.source.status, dynamic_result.target.status))
    if any(status == "unknown" for status in statuses):
        status = DifferentialStatus.INCOMPLETE
    elif mismatches:
        status = DifferentialStatus.MISMATCH
    else:
        status = DifferentialStatus.MATCH
    if expected is not None:
        classification = expected
        classification_reason = expected_reason
    elif status is DifferentialStatus.MATCH:
        classification = DifferentialClassification.EQUIVALENT
        classification_reason = "both route facades classify source and target alike"
    elif all(item == "unknown" for item in static_statuses) and not all(
        item == "unknown" for item in dynamic_statuses
    ):
        classification = DifferentialClassification.UNSUPPORTED_BY_STATIC
        classification_reason = "static route did not support the fixed execution"
    elif all(item == "unknown" for item in dynamic_statuses) and not all(
        item == "unknown" for item in static_statuses
    ):
        classification = DifferentialClassification.UNSUPPORTED_BY_DYNAMIC
        classification_reason = "dynamic route did not support the fixed execution"
    else:
        classification = DifferentialClassification.UNRESOLVED_MODEL_DRIFT
        classification_reason = "route results differ or are incomplete without an exemption"
    return DifferentialComparison(
        status=status,
        source_static=static_result.source.status,
        source_dynamic=dynamic_result.source.status,
        target_static=static_result.target.status,
        target_dynamic=dynamic_result.target.status,
        mismatches=mismatches,
        classification=classification,
        classification_reason=classification_reason,
    )


__all__ = [
    "DifferentialComparison",
    "DifferentialClassification",
    "DifferentialStatus",
    "compare_fixed_execution",
]
