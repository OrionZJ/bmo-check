from __future__ import annotations

import json
import shutil
from pathlib import Path

from bmo_check.cli import main


def test_fingerprint_cli_outputs_round_trip_json(
    elf_fixture, capsys, tmp_path: Path
) -> None:
    contract = tmp_path / "contract.yaml"
    contract.write_text(
        "schema: 1\ncontract_version: test-contract-v1\n", encoding="utf-8"
    )
    roots = [
        value
        for root in (elf_fixture.library_root,) + elf_fixture.system_roots
        for value in ("--library-root", str(root))
    ]
    result = main(
        [
            "fingerprint",
            "--exe",
            str(elf_fixture.executable),
            *roots,
            "--argv-json",
            '["sample-app", "4"]',
            "--threads",
            "4",
            "--dbt-contract",
            str(contract),
            "--dbt-revision",
            "a" * 40,
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["manifest"]["closure_complete"] is True
    assert payload["manifest"]["execution"]["thread_count_min"] == 4


def test_fingerprint_cli_returns_incomplete_for_missing_library(
    elf_fixture, capsys, tmp_path: Path
) -> None:
    contract = tmp_path / "contract.yaml"
    contract.write_text(
        "schema: 1\ncontract_version: test-contract-v1\n", encoding="utf-8"
    )
    roots = [
        value
        for root in elf_fixture.system_roots
        for value in ("--library-root", str(root))
    ]
    result = main(
        [
            "fingerprint",
            "--exe",
            str(elf_fixture.executable),
            *roots,
            "--dbt-contract",
            str(contract),
            "--dbt-revision",
            "a" * 40,
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert result == 1
    assert payload["manifest"]["closure_complete"] is False


def test_invalid_contract_is_reported_as_unknown(
    elf_fixture, capsys, tmp_path: Path
) -> None:
    contract = tmp_path / "invalid-contract.yaml"
    contract.write_text("schema: 1\n", encoding="utf-8")
    roots = [
        value
        for root in (elf_fixture.library_root,) + elf_fixture.system_roots
        for value in ("--library-root", str(root))
    ]
    result = main(
        [
            "fingerprint",
            "--exe",
            str(elf_fixture.executable),
            *roots,
            "--dbt-contract",
            str(contract),
            "--dbt-revision",
            "a" * 40,
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    kinds = {
        item["kind"] for item in payload["manifest"]["unknowns"]
    }
    assert result == 1
    assert "InvalidDbtContract" in kinds


def test_recover_cli_emits_cfg_and_thread_layers(
    elf_fixture, capsys, tmp_path: Path, monkeypatch
) -> None:
    contract = tmp_path / "contract.yaml"
    contract.write_text(
        "schema: 1\ncontract_version: test-contract-v1\n", encoding="utf-8"
    )
    pthread_spec = tmp_path / "pthread.yaml"
    pthread_spec.write_text("schema: 1\napis: {}\n", encoding="utf-8")
    roots = [
        value
        for root in (elf_fixture.library_root,) + elf_fixture.system_roots
        for value in ("--library-root", str(root))
    ]
    # 这个用例只检查 CLI 编排；同步库的真实指令摘要由独立集成测试覆盖。
    monkeypatch.setattr("bmo_check.cli.function_symbols", lambda _: ())

    result = main(
        [
            "recover",
            "--exe",
            str(elf_fixture.executable),
            *roots,
            "--dbt-contract",
            str(contract),
            "--pthread-spec",
            str(pthread_spec),
            "--dbt-revision",
            "a" * 40,
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert result == 0
    assert payload["control_flow"]["coverage"]["functions"] > 0
    assert payload["thread_roles"]["roles"][0]["id"] == "main"
    assert payload["synchronization"] == []


def test_slice_cli_emits_proof_carrying_shared_slice(
    elf_fixture, capsys, tmp_path: Path, monkeypatch
) -> None:
    contract = tmp_path / "contract.yaml"
    contract.write_text(
        "schema: 1\ncontract_version: test-contract-v1\n", encoding="utf-8"
    )
    pthread_spec = tmp_path / "pthread.yaml"
    pthread_spec.write_text("schema: 1\napis: {}\n", encoding="utf-8")
    roots = [
        value
        for root in (elf_fixture.library_root,) + elf_fixture.system_roots
        for value in ("--library-root", str(root))
    ]
    monkeypatch.setattr("bmo_check.cli.function_symbols", lambda _: ())

    result = main(
        [
            "slice",
            "--exe",
            str(elf_fixture.executable),
            *roots,
            "--dbt-contract",
            str(contract),
            "--pthread-spec",
            str(pthread_spec),
            "--dbt-revision",
            "a" * 40,
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert result == 0
    assert payload["memory_events"] is not None
    assert payload["shared_state"] is not None
    assert payload["shared_slice"]["coverage"]["total_events"] > 0
    assert "verdict" not in payload


def test_analyze_and_explain_cli_emit_unknown_certificate(
    elf_fixture, capsys, tmp_path: Path, monkeypatch
) -> None:
    contract = tmp_path / "contract.yaml"
    contract.write_text(
        "schema: 1\ncontract_version: test-contract-v1\n", encoding="utf-8"
    )
    pthread_spec = tmp_path / "pthread.yaml"
    pthread_spec.write_text("schema: 1\napis: {}\n", encoding="utf-8")
    certificate_path = tmp_path / "certificate.json"
    roots = [
        value
        for root in (elf_fixture.library_root,) + elf_fixture.system_roots
        for value in ("--library-root", str(root))
    ]
    monkeypatch.setattr("bmo_check.cli.function_symbols", lambda _: ())

    result = main(
        [
            "analyze",
            "--exe",
            str(elf_fixture.executable),
            *roots,
            "--dbt-contract",
            str(contract),
            "--pthread-spec",
            str(pthread_spec),
            "--dbt-revision",
            "a" * 40,
            "--output",
            str(certificate_path),
        ]
    )
    payload = json.loads(certificate_path.read_text(encoding="utf-8"))

    assert result == 1
    assert payload["verdict"] == "UNKNOWN"
    assert payload["scope"]["executable_sha256"]
    assert payload["scope"]["modules"]
    assert payload["relevant_unknowns"]

    explain_result = main(["explain", str(certificate_path)])
    explanation = capsys.readouterr().out
    assert explain_result == 0
    assert "verdict: UNKNOWN" in explanation
    assert "unknown" in explanation


def test_evaluate_cli_writes_ablation_report(
    elf_fixture, tmp_path: Path, monkeypatch
) -> None:
    parsec_root = tmp_path / "parsec"
    binary_directory = parsec_root / "fixture" / "bin"
    binary_directory.mkdir(parents=True)
    executable = binary_directory / "sample-app"
    shutil.copy2(elf_fixture.executable, executable)
    (parsec_root / "fixture" / "run").mkdir()
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        "schema: 1\n"
        "name: fixture-suite\n"
        "benchmarks:\n"
        "  - id: fixture\n"
        "    executable: fixture/bin/sample-app\n"
        "    run_directory: fixture/run\n"
        "    argv: []\n"
        "    threads: 2\n",
        encoding="utf-8",
    )
    contract = tmp_path / "contract.yaml"
    contract.write_text(
        "schema: 1\ncontract_version: test-contract-v1\n", encoding="utf-8"
    )
    pthread_spec = tmp_path / "pthread.yaml"
    pthread_spec.write_text("schema: 1\napis: {}\n", encoding="utf-8")
    output = tmp_path / "evaluation"
    roots = [
        value
        for root in (elf_fixture.library_root,) + elf_fixture.system_roots
        for value in ("--library-root", str(root))
    ]
    monkeypatch.setattr("bmo_check.cli.function_symbols", lambda _: ())

    result = main(
        [
            "evaluate",
            "--suite",
            str(suite),
            "--parsec-root",
            str(parsec_root),
            *roots,
            "--dbt-contract",
            str(contract),
            "--pthread-spec",
            str(pthread_spec),
            "--dbt-revision",
            "a" * 40,
            "--output-dir",
            str(output),
        ]
    )
    payload = json.loads((output / "evaluation.json").read_text(encoding="utf-8"))
    ablations = payload["benchmarks"][0]["ablations"]

    assert result == 0
    assert [item["level"] for item in ablations] == [
        "none",
        "thread-local",
        "read-only",
        "disjoint",
        "atomic-covered",
    ]
    assert all(item["certificate_sha256"] for item in ablations)
    assert payload["benchmarks"][0]["native_run"]["attempted"] is False
