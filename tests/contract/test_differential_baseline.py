from __future__ import annotations

from dataclasses import dataclass

from bmo_check_evaluation.litmus import DifferentialStatus, compare_fixed_execution


@dataclass(frozen=True)
class _Model:
    model: str
    status: str


@dataclass(frozen=True)
class _Execution:
    source: _Model
    target: _Model


def test_differential_marks_status_drift_without_changing_either_result() -> None:
    static = _Execution(_Model("x86-tso", "forbidden"), _Model("rvwmo", "allowed"))
    dynamic = _Execution(_Model("x86-tso", "allowed"), _Model("rvwmo", "allowed"))

    comparison = compare_fixed_execution(static, dynamic)

    assert comparison.status is DifferentialStatus.MISMATCH
    assert comparison.mismatches == ("source: static='forbidden', dynamic='allowed'",)
    assert comparison.source_static == "forbidden"
    assert comparison.source_dynamic == "allowed"


def test_differential_keeps_unknown_incomplete_even_when_other_side_matches() -> None:
    static = _Execution(_Model("x86-tso", "unknown"), _Model("rvwmo", "allowed"))
    dynamic = _Execution(_Model("x86-tso", "unknown"), _Model("rvwmo", "allowed"))

    comparison = compare_fixed_execution(static, dynamic)

    assert comparison.status is DifferentialStatus.INCOMPLETE
    assert comparison.mismatches == ()
