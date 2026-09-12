"""把 execution legality 与 herd oracle 做逐模型对照。

这里严格保留三层结果：herd 的 outcome、BMoCheck 对一个固定关系赋值的
legality，以及最终 verifier verdict。对照失败只表示回归或资料不完整，
不会构造 SAFE/TRACE_SAFE，也不能把 oracle 变成证明前提。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .model import HerdOracleRecord, HerdOutcome


class _ExecutionResult(Protocol):
    source_status: str
    target_status: str


class OracleComparisonStatus(StrEnum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True, slots=True)
class OracleLegalityComparison:
    """固定 execution 与 external oracle 的逐层比较结果。"""

    status: OracleComparisonStatus
    source_execution: str
    target_execution: str
    source_oracle: HerdOutcome
    target_oracle: HerdOutcome
    differences: tuple[str, ...] = ()


def _expected_status(outcome: HerdOutcome) -> str | None:
    if outcome is HerdOutcome.ALLOWED:
        return "allowed"
    if outcome is HerdOutcome.FORBIDDEN:
        return "forbidden"
    return None


def compare_execution_with_oracle(
    execution: _ExecutionResult,
    oracle: HerdOracleRecord,
) -> OracleLegalityComparison:
    """比较 source/target execution legality；Unsupported 或 Unknown 不匹配。"""

    differences: list[str] = []
    for model, actual, expected in (
        ("source", execution.source_status, oracle.source_outcome),
        ("target", execution.target_status, oracle.target_outcome),
    ):
        wanted = _expected_status(expected)
        if wanted is None:
            differences.append(f"{model} herd outcome is unsupported")
        elif actual.lower() == "unknown":
            differences.append(f"{model} execution legality is unknown")
        elif actual.lower() != wanted:
            differences.append(
                f"{model}: execution={actual!r}, herd={expected.value!r}"
            )
    if differences:
        incomplete = any(
            "unsupported" in difference or "unknown" in difference
            for difference in differences
        )
        status = (
            OracleComparisonStatus.INCOMPLETE
            if incomplete
            else OracleComparisonStatus.MISMATCH
        )
    else:
        status = OracleComparisonStatus.MATCH
    return OracleLegalityComparison(
        status=status,
        source_execution=execution.source_status,
        target_execution=execution.target_status,
        source_oracle=oracle.source_outcome,
        target_oracle=oracle.target_outcome,
        differences=tuple(differences),
    )


__all__ = [
    "OracleComparisonStatus",
    "OracleLegalityComparison",
    "compare_execution_with_oracle",
]
