from __future__ import annotations

from dataclasses import dataclass

from bmo_check_evaluation.litmus import (
    HerdOutcome,
    HerdOracleRecord,
    OracleComparisonStatus,
    compare_execution_with_oracle,
)


HASH = "a" * 64


@dataclass(frozen=True)
class _Execution:
    source_status: str
    target_status: str


def _oracle(source: HerdOutcome, target: HerdOutcome) -> HerdOracleRecord:
    return HerdOracleRecord(
        herd_version="herd7-reviewed",
        source_model="x86.cat",
        target_model="riscv.cat",
        source_outcome=source,
        target_outcome=target,
        source_input_sha256=HASH,
        target_input_sha256=HASH,
        elf_sha256=HASH,
        contract_version="dbt6-mo-off-v2",
        contract_sha256=HASH,
        raw_output_sha256=HASH,
    )


def test_oracle_comparison_keeps_execution_and_herd_layers_separate() -> None:
    result = compare_execution_with_oracle(
        _Execution("forbidden", "allowed"),
        _oracle(HerdOutcome.FORBIDDEN, HerdOutcome.ALLOWED),
    )
    assert result.status is OracleComparisonStatus.MATCH
    assert result.source_oracle is HerdOutcome.FORBIDDEN
    assert result.target_execution == "allowed"


def test_oracle_mismatch_is_not_a_verdict() -> None:
    result = compare_execution_with_oracle(
        _Execution("allowed", "allowed"),
        _oracle(HerdOutcome.FORBIDDEN, HerdOutcome.ALLOWED),
    )
    assert result.status is OracleComparisonStatus.MISMATCH
    assert result.differences == ("source: execution='allowed', herd='Forbidden'",)


def test_unsupported_or_unknown_stays_incomplete() -> None:
    result = compare_execution_with_oracle(
        _Execution("unknown", "allowed"),
        _oracle(HerdOutcome.UNSUPPORTED, HerdOutcome.ALLOWED),
    )
    assert result.status is OracleComparisonStatus.INCOMPLETE
    assert result.differences == ("source herd outcome is unsupported",)
