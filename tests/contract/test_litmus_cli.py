from __future__ import annotations

import json
from pathlib import Path

from bmo_check_evaluation.litmus.conformance import ConformanceStatus
from bmo_check_evaluation.litmus.service import (
    LitmusCaseConformance,
    LitmusConformanceReport,
)
from bmo_check_static.cli import main


def _args(tmp_path: Path) -> list[str]:
    contract = Path(__file__).resolve().parents[2] / "specs" / "static" / "dbt6-mo-off.yaml"
    return [
        "litmus",
        "--manifest",
        str(tmp_path / "manifest.yaml"),
        "--corpus-root",
        str(tmp_path),
        "--dbt-contract",
        str(contract),
        "--output",
        str(tmp_path / "report.json"),
    ]


def test_litmus_cli_emits_typed_report_and_conformance_exit_code(
    tmp_path: Path, monkeypatch
) -> None:
    expected = LitmusConformanceReport(
        manifest_path=str(tmp_path / "manifest.yaml"),
        corpus_name="fixture",
        corpus_revision="rev-1",
        contract_version="dbt6-mo-off-v2",
        contract_sha256="a" * 64,
        cases=(
            LitmusCaseConformance(
                case_id="case-1",
                status=ConformanceStatus.MATCHED,
                elf_path=str(tmp_path / "elf.exe"),
                source_path=str(tmp_path / "case.litmus"),
            ),
        ),
    )
    monkeypatch.setattr(
        "bmo_check_evaluation.litmus.service.run_litmus_conformance",
        lambda request: expected,
    )

    result = main(_args(tmp_path))
    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert result == 0
    assert payload["status"] == "MATCHED"
    assert payload["cases"][0]["case_id"] == "case-1"


def test_litmus_cli_maps_unknown_conformance_to_exit_code_two(
    tmp_path: Path, monkeypatch
) -> None:
    expected = LitmusConformanceReport(
        manifest_path=str(tmp_path / "manifest.yaml"),
        corpus_name="fixture",
        corpus_revision="rev-1",
        contract_version="unknown",
        contract_sha256=None,
        cases=(),
    )
    monkeypatch.setattr(
        "bmo_check_evaluation.litmus.service.run_litmus_conformance",
        lambda request: expected,
    )

    result = main(_args(tmp_path))

    assert result == 2
