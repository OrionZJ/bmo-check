from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import bmo_check_dynamic.cli as dynamic_cli
from bmo_check_dynamic.cli import main
from bmo_check_dynamic.pipeline import _write_global_constraint_progress
from bmo_check_dynamic.capture import CaptureError
from bmo_check_dynamic.model import (
    BinaryFingerprint,
    DynamicCertificate,
    EventKind,
    GlobalConstraintValidationReport,
    TraceEvent,
    TraceManifest,
    TraceScope,
    TraceVerdict,
)
from bmo_check_dynamic.trace import TraceWriter


def test_analyze_and_explain_trace_safe(
    trace_manifest, tmp_path: Path, capsys
) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4))
    contract = tmp_path / "contract.yaml"
    shutil.copyfile(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml",
        contract,
    )
    certificate = tmp_path / "certificate.json"

    result = main(
        [
            "analyze",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--output",
            str(certificate),
        ]
    )
    payload = json.loads(certificate.read_text(encoding="utf-8"))
    assert result == 0
    assert payload["verdict"] == "TRACE_SAFE"
    assert "Limit:" in capsys.readouterr().out

    assert main(["explain", str(certificate)]) == 0
    assert "TRACE_SAFE" in capsys.readouterr().out


def test_p17_cli_defaults_to_bounded_full_window_experiment() -> None:
    args = dynamic_cli.build_parser().parse_args(
        [
            "p17-global-validation",
            "trace-dir",
            "--fixed-candidate-report",
            "candidates.json",
            "--reduction-certificate",
            "ppo.json",
            "--output",
            "p17.json",
        ]
    )

    assert args.max_window_events == 10_000
    assert args.expected_candidate_count == 10
    assert args.process_wall_limit_seconds == 1_800
    assert args.process_memory_limit_mb == 8_192
    assert args.p17_max_symbolic_terms == 100_000


def test_p17_progress_checkpoint_is_atomically_serialized(tmp_path: Path) -> None:
    path = tmp_path / "p17.progress.json"
    snapshot = GlobalConstraintValidationReport(
        trace_id="trace",
        trace_sha256="trace-digest",
        contract_sha256="contract-digest",
        window_id="window",
        event_count=4,
        ppo_certificate_digest="ppo-digest",
        candidate_skeleton_ids=(),
        max_partial_timeout_ms=1_000,
        max_full_timeout_ms=30_000,
        max_symbolic_terms=10_000,
        max_queries_per_solver_session=2,
        process_wall_limit_seconds=60,
        termination_reason="in_progress",
    )

    _write_global_constraint_progress(path, snapshot)

    assert json.loads(path.read_text(encoding="utf-8"))["termination_reason"] == "in_progress"
    assert not tuple(tmp_path.glob("*.writing"))


def test_characterize_scans_windows_without_running_proof(
    trace_manifest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace_dir = tmp_path / "characterize-trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4))
    contract = tmp_path / "contract.yaml"
    shutil.copyfile(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml",
        contract,
    )
    monkeypatch.setattr(
        "bmo_check_dynamic.pipeline.check_window",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("characterize must stop before proof")
        ),
    )
    output = tmp_path / "characterization.json"

    result = main(
        [
            "characterize",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--output",
            str(output),
        ]
    )

    assert result == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "window-characterization-v4"
    assert payload["analysis_reached_windows"] is True
    assert payload["event_count"] == 2
    assert payload["raw_event_count"] == 2
    assert payload["communication_edge_count"] == 1
    assert len(payload["windows"]) == 1
    assert {
        item["event_id"] for item in payload["windows"][0]["event_inclusions"]
    } == {"t1:e1", "t2:e1"}
    assert all(
        item["reasons"] == ["communication_endpoint"]
        for item in payload["windows"][0]["event_inclusions"]
    )
    assert len(payload["symbolic"]) == 1
    assert payload["symbolic"][0]["estimated_formula_terms"] > 0


def test_slice_candidates_are_diagnostic_only(
    trace_manifest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace_dir = tmp_path / "slice-trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4))
        writer.write(TraceEvent(1, 2, 0, 0x11, EventKind.LOAD, 0x1000, 4))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 4))
    contract = tmp_path / "contract.yaml"
    shutil.copyfile(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml",
        contract,
    )
    monkeypatch.setattr(
        "bmo_check_dynamic.pipeline.check_window",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("slice candidate report must stop before proof")
        ),
    )
    output = tmp_path / "slice-candidates.json"

    result = main(
        [
            "slice-candidates",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--output",
            str(output),
        ]
    )

    assert result == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "slice-candidate-report-v1"
    assert payload["analysis_reached_windows"] is True
    candidate = payload["windows"][0]
    assert candidate["complete"] is False
    assert candidate["removed_event_ids"] == []
    assert candidate["retained_event_ids"] == ["t1:e1", "t1:e2", "t2:e1"]
    assert candidate["proposed_event_ids"] == []
    assert candidate["groups"][0]["communication_endpoint_count"] == 2
    assert candidate["obligations"]


def test_slice_plan_is_report_only(
    trace_manifest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace_dir = tmp_path / "plan-trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4))
    contract = tmp_path / "contract.yaml"
    shutil.copyfile(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml",
        contract,
    )
    monkeypatch.setattr(
        "bmo_check_dynamic.pipeline.check_window",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("slice plan must stop before proof")
        ),
    )
    output = tmp_path / "slice-plan.json"

    result = main(
        [
            "slice-plan",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--output",
            str(output),
        ]
    )

    assert result == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "slice-plan-report-v1"
    assert payload["plans"][0]["status"] == "no-safe-split"
    assert payload["plans"][0]["complete"] is False


def test_packages_do_not_import_each_other() -> None:
    root = Path(__file__).resolve().parents[2] / "src"
    for path in (root / "bmo_check_dynamic").rglob("*.py"):
        assert "bmo_check_static" not in path.read_text(encoding="utf-8")
    for path in (root / "bmo_check_static").rglob("*.py"):
        assert "bmo_check_dynamic" not in path.read_text(encoding="utf-8")


def test_locate_command_reports_module_relative_site(
    tmp_path: Path, capsys
) -> None:
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    module = "/app/program"
    (trace_dir / "modules.tsv").write_text(
        f"0x1000\t0x2000\t{module}\n", encoding="utf-8"
    )
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(3, 7, 1, 0x1010, EventKind.STORE, 0x4000, 4))

    result = main(
        ["locate", str(trace_dir), "--module", module, "--offset", "0x10"]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["event_count"] == 1
    assert payload["thread_event_counts"] == [[3, 1]]


def test_campaign_rejects_zero_run_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        "runs:\n  - name: empty\n    command: [/bin/true]\n    repeat: 0\n",
        encoding="utf-8",
    )

    result = main(["campaign", str(manifest), "--output", str(tmp_path / "out")])

    assert result == 3


def _unknown_campaign_certificate() -> DynamicCertificate:
    executable = BinaryFingerprint(path="/tmp/program", sha256="a" * 64)
    return DynamicCertificate(
        verdict=TraceVerdict.UNKNOWN,
        scope=TraceScope(
            trace_ids=("campaign-trace",),
            trace_sha256=("b" * 64,),
            executable=executable,
            commands=(("/tmp/program",),),
            working_directories=("/tmp",),
        ),
        dbt_contract_sha256="c" * 64,
        analyzer_version="test",
        trace_complete=False,
        event_count=4,
        thread_count=1,
        object_count=0,
        unique_pc_count=2,
        communication_edge_count=0,
        indirect_target_count=0,
        unknown_reasons=("resource limit",),
    )


def test_campaign_keeps_unknown_members_and_deduplicates_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        "runs:\n  - name: sample\n    command: [/bin/true]\n    repeat: 2\n",
        encoding="utf-8",
    )

    def fake_capture(request):
        request.output_dir.mkdir(parents=True)
        return None

    monkeypatch.setattr(dynamic_cli, "capture_request", fake_capture)
    monkeypatch.setattr(
        dynamic_cli,
        "analyze_request",
        lambda request: _unknown_campaign_certificate(),
    )

    output = tmp_path / "out"
    result = main(["campaign", str(manifest), "--output", str(output)])

    assert result == 2
    payload = json.loads((output / "campaign.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "campaign-v2"
    assert payload["verdict"] == "UNKNOWN"
    assert payload["member_count"] == 2
    assert payload["unique_trace_count"] == 1
    assert payload["duplicate_trace_count"] == 1
    assert payload["verdict_counts"]["UNKNOWN"] == 2
    assert all(item["certificate_path"] for item in payload["certificates"])


def test_campaign_records_capture_failure_as_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        "runs:\n  - name: failed\n    command: [/bin/true]\n",
        encoding="utf-8",
    )

    def fake_capture(request):
        raise CaptureError("client unavailable")

    monkeypatch.setattr(dynamic_cli, "capture_request", fake_capture)
    output = tmp_path / "out"

    assert main(["campaign", str(manifest), "--output", str(output)]) == 2
    payload = json.loads((output / "campaign.json").read_text(encoding="utf-8"))
    assert payload["verdict"] == "UNKNOWN"
    assert payload["unique_trace_count"] == 1
    assert payload["certificates"][0]["error"] == "capture failed: client unavailable"


def test_campaign_rejects_duplicate_run_names(tmp_path: Path) -> None:
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        "runs:\n  - name: same\n    command: [/bin/true]\n  - name: same\n    command: [/bin/true]\n",
        encoding="utf-8",
    )

    assert main(["campaign", str(manifest), "--output", str(tmp_path / "out")]) == 3


def test_verify_replays_certificate(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4))
    contract = tmp_path / "contract.yaml"
    shutil.copyfile(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml",
        contract,
    )
    certificate = dynamic_cli.analyze_request(
        dynamic_cli.AnalyzeRequest(
            trace_dir=trace_dir,
            dbt_contract=contract,
            config=dynamic_cli.DynamicConfig(),
        )
    )
    certificate_path = tmp_path / "certificate.json"
    certificate_path.write_text(certificate.model_dump_json(), encoding="utf-8")

    assert main(
        [
            "verify",
            str(certificate_path),
            "--trace",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
        ]
    ) == 0
