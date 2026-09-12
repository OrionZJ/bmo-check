from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path

from bmo_check_evaluation.litmus import (
    HerdOracleRequest,
    HerdOracleRecord,
    HerdOutcome,
    HerdReplayStatus,
    parse_herd_outcome,
    replay_herd_oracle,
    run_herd_oracle,
)
from bmo_check_evaluation.litmus.oracle import (
    ORACLE_REPORT_SCHEMA,
    oracle_record_from_run,
    replay_report,
    report_payload,
    write_report,
)


def _request(tmp_path: Path) -> HerdOracleRequest:
    source = tmp_path / "source.litmus"
    target = tmp_path / "target.litmus"
    source.write_text("source", encoding="utf-8")
    target.write_text("target", encoding="utf-8")
    return HerdOracleRequest(
        source_input=source,
        target_input=target,
        source_model="x86.cat",
        target_model="riscv.cat",
        contract_version="dbt6-mo-off-v2",
        contract_sha256="a" * 64,
        elf_sha256="b" * 64,
        herd_executable="herd7",
        extra_args=("-bell",),
    )


def test_parser_keeps_allowed_forbidden_and_unsupported_distinct() -> None:
    assert parse_herd_outcome("Test SB Allowed\n") is HerdOutcome.ALLOWED
    assert parse_herd_outcome("Test SB Forbidden\n") is HerdOutcome.FORBIDDEN
    assert (
        parse_herd_outcome("Condition exists (0:r1=0) is confirmed")
        is HerdOutcome.ALLOWED
    )
    assert (
        parse_herd_outcome("Condition exists (0:r1=0) is not confirmed")
        is HerdOutcome.FORBIDDEN
    )
    assert parse_herd_outcome("herd crashed") is HerdOutcome.UNSUPPORTED


def test_run_binds_both_inputs_and_preserves_raw_observations(
    tmp_path: Path, monkeypatch
) -> None:
    request = _request(tmp_path)
    outputs = iter(
        (
            subprocess.CompletedProcess(
                args=(), returncode=0, stdout="Test source Allowed\n", stderr=""
            ),
            subprocess.CompletedProcess(
                args=(), returncode=0, stdout="Test target Forbidden\n", stderr=""
            ),
        )
    )
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(list(command))
        assert kwargs["check"] is False
        assert kwargs["shell"] is False if "shell" in kwargs else True
        return next(outputs)

    monkeypatch.setattr("subprocess.run", fake_run)
    run = run_herd_oracle(request)

    assert run.complete
    assert run.source.outcome is HerdOutcome.ALLOWED
    assert run.target.outcome is HerdOutcome.FORBIDDEN
    assert commands == [
        ["herd7", "-model", "x86.cat", "-bell", str(request.source_input)],
        ["herd7", "-model", "riscv.cat", "-bell", str(request.target_input)],
    ]
    assert run.source.input_sha256 == hashlib.sha256(b"source").hexdigest()
    assert run.target.input_sha256 == hashlib.sha256(b"target").hexdigest()


def test_replay_rejects_changed_contract_or_outcome_without_proof_effect(
    tmp_path: Path, monkeypatch
) -> None:
    request = _request(tmp_path)
    outputs = iter(
        (
            subprocess.CompletedProcess(
                args=(), returncode=0, stdout="Test source Allowed\n", stderr=""
            ),
            subprocess.CompletedProcess(
                args=(), returncode=0, stdout="Test target Allowed\n", stderr=""
            ),
        )
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: next(outputs))
    run = run_herd_oracle(request)
    record = HerdOracleRecord(
        herd_version="herd7",
        source_model=request.source_model,
        target_model=request.target_model,
        source_outcome=HerdOutcome.ALLOWED,
        target_outcome=HerdOutcome.FORBIDDEN,
        source_input_sha256=run.source.input_sha256,
        target_input_sha256=run.target.input_sha256,
        elf_sha256=request.elf_sha256,
        contract_version=request.contract_version,
        contract_sha256=request.contract_sha256,
        raw_output_sha256="c" * 64,
    )

    replay = replay_herd_oracle(record, run)

    assert replay.status is HerdReplayStatus.MISMATCH
    assert "target herd outcome changed" in replay.differences
    assert "herd raw output hash changed" in replay.differences


def test_oracle_report_round_trip_keeps_contract_and_run_provenance(
    tmp_path: Path, monkeypatch
) -> None:
    request = _request(tmp_path)
    request = replace(request, herd_version="herd7-test")
    outputs = iter(
        (
            subprocess.CompletedProcess(args=(), returncode=0, stdout="Test source Allowed\n", stderr=""),
            subprocess.CompletedProcess(args=(), returncode=0, stdout="Test target Allowed\n", stderr=""),
        )
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: next(outputs))
    run = run_herd_oracle(request)

    payload = report_payload(run, herd_version="herd7-test")
    assert payload["schema"] == ORACLE_REPORT_SCHEMA
    assert payload["request"]["contract_version"] == request.contract_version
    assert payload["oracle"]["source_outcome"] == "Allowed"
    assert payload["oracle"]["target_outcome"] == "Allowed"
    record = oracle_record_from_run(run, herd_version="herd7-test")
    assert record.contract_sha256 == request.contract_sha256

    output = tmp_path / "oracle.json"
    write_report(run, herd_version="herd7-test", output=output)
    loaded = output.read_text(encoding="utf-8")
    assert '"schema": "e2.5-herd-oracle-run-v1"' in loaded


def test_oracle_replay_detects_herd_version_drift(tmp_path: Path, monkeypatch) -> None:
    request = _request(tmp_path)
    request = replace(request, herd_version="herd7-recorded")
    outputs = iter(
        (
            subprocess.CompletedProcess(args=(), returncode=0, stdout="Test source Allowed\n", stderr=""),
            subprocess.CompletedProcess(args=(), returncode=0, stdout="Test target Allowed\n", stderr=""),
        )
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: next(outputs))
    run = run_herd_oracle(request)
    output = tmp_path / "oracle.json"
    write_report(run, herd_version="herd7-recorded", output=output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["request"]["herd_version"] = "herd7-current"
    output.write_text(json.dumps(payload), encoding="utf-8")

    replay_outputs = iter(
        (
            subprocess.CompletedProcess(args=(), returncode=0, stdout="Test source Allowed\n", stderr=""),
            subprocess.CompletedProcess(args=(), returncode=0, stdout="Test target Allowed\n", stderr=""),
        )
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: next(replay_outputs))
    status, differences = replay_report(output)

    assert status is HerdReplayStatus.UNKNOWN
    assert "herd version does not match the oracle record" in differences
