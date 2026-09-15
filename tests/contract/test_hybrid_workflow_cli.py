from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from bmo_check_dynamic.cli import main


class _Certificate:
    def __init__(self, verdict: str) -> None:
        self.verdict = SimpleNamespace(value=verdict)

    def model_dump_json(self, *, indent: int) -> str:
        return json.dumps({"verdict": self.verdict.value}, indent=indent)


def _inputs(tmp_path: Path, *, dbt_revision: bool = True, drrun: bool = True) -> Path:
    (tmp_path / "program").write_bytes(b"ELF fixture is not executed by these tests")
    (tmp_path / "dbt.yaml").write_text("contract: test\n", encoding="utf-8")
    (tmp_path / "pthread.yaml").write_text("apis: []\n", encoding="utf-8")
    (tmp_path / "effects.yaml").write_text("functions: []\n", encoding="utf-8")
    (tmp_path / "libbmo_trace.so").write_bytes(b"native client fixture")
    runtime = tmp_path / "dynamorio" / "bin64"
    runtime.mkdir(parents=True)
    if drrun:
        (runtime / "drrun").write_bytes(b"launcher fixture")

    revision = (
        "  dbt_revision: 0123456789abcdef0123456789abcdef01234567\n"
        if dbt_revision
        else ""
    )
    manifest = tmp_path / "workload.yaml"
    manifest.write_text(
        "schema_version: hybrid-workload-v1\n"
        "workload:\n"
        "  executable: ./program\n"
        "  argv: [--case, '1']\n"
        "  working_directory: .\n"
        "  environment: {WORKERS: '2'}\n"
        "static:\n"
        "  dbt_contract: ./dbt.yaml\n"
        "  pthread_spec: ./pthread.yaml\n"
        "  function_effects: ./effects.yaml\n"
        f"{revision}"
        "dynamic:\n"
        "  dynamorio_home: ./dynamorio\n"
        "  client_path: ./libbmo_trace.so\n",
        encoding="utf-8",
    )
    return manifest


def _install_workflow_stubs(monkeypatch, *, static_verdict="UNKNOWN", dynamic_verdict="UNKNOWN"):
    import bmo_check_cli.hybrid as hybrid_cli

    observed = SimpleNamespace(request=None)

    def analyze(request):
        observed.request = request
        request.trace_dir.mkdir(parents=True)
        (request.trace_dir / "manifest.json").write_text("{}\n", encoding="utf-8")
        return SimpleNamespace(
            static_analysis=SimpleNamespace(
                legacy_certificate=_Certificate(static_verdict),
                canonical_certificate=None,
            ),
            dynamic_evidence=SimpleNamespace(
                certificate=_Certificate(dynamic_verdict),
            ),
            diagnostics_unavailable_reason=(
                "DBT revision is unbound" if request.static_request.dbt_revision is None else None
            ),
        )

    class Report:
        def to_json(self):
            return json.dumps(
                {
                    "schema_version": "hybrid-workflow-report-v2",
                    "static_verdict": static_verdict,
                    "dynamic_verdict": dynamic_verdict,
                    "combined_verdict": "not_defined",
                }
            )

    def save_report(report, path):
        path.write_text(report.to_json() + "\n", encoding="utf-8")

    monkeypatch.setattr(hybrid_cli, "analyze_workload", analyze)
    monkeypatch.setattr(hybrid_cli, "build_hybrid_workflow_report", lambda result: Report())
    monkeypatch.setattr(hybrid_cli, "save_hybrid_workflow_report", save_report)
    return observed


def test_hybrid_cli_writes_separate_route_certificates_and_report(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    manifest = _inputs(tmp_path)
    observed = _install_workflow_stubs(monkeypatch)
    output = tmp_path / "E-drive" / "run-001"

    status = main(
        ["hybrid", "--workload", str(manifest), "--output-dir", str(output)]
    )

    assert status == 0
    assert observed.request.static_request.argv == ("--case", "1")
    assert observed.request.dynamic_config.database_path == output / "dynamic-analysis.duckdb"
    assert (output / "static-certificate.json").is_file()
    assert (output / "dynamic-certificate.json").is_file()
    report = json.loads((output / "hybrid-workflow-report.json").read_text(encoding="utf-8"))
    assert report["static_verdict"] == "UNKNOWN"
    assert report["dynamic_verdict"] == "UNKNOWN"
    assert report["combined_verdict"] == "not_defined"
    assert "No combined verdict is defined." in capsys.readouterr().out


def test_missing_dbt_revision_stays_static_unknown_but_workflow_completes(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    manifest = _inputs(tmp_path, dbt_revision=False)
    observed = _install_workflow_stubs(monkeypatch)
    output = tmp_path / "out"

    status = main(
        ["hybrid", "--workload", str(manifest), "--output-dir", str(output)]
    )

    assert status == 0
    assert observed.request.static_request.dbt_revision is None
    assert "Diagnostics unavailable: DBT revision is unbound" in capsys.readouterr().out
    assert (output / "hybrid-workflow-report.json").is_file()


def test_missing_dynamorio_fails_before_output_is_created(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    manifest = _inputs(tmp_path, drrun=False)
    observed = _install_workflow_stubs(monkeypatch)
    output = tmp_path / "out"

    status = main(
        ["hybrid", "--workload", str(manifest), "--output-dir", str(output)]
    )

    assert status == 3
    assert not output.exists()
    assert observed.request is None
    assert "DynamoRIO launcher is not a file" in capsys.readouterr().err


def test_invalid_manifest_does_not_allocate_output_directory(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    manifest = _inputs(tmp_path)
    manifest.write_text("schema_version: unsupported\n", encoding="utf-8")
    _install_workflow_stubs(monkeypatch)
    output = tmp_path / "out"

    status = main(
        ["hybrid", "--workload", str(manifest), "--output-dir", str(output)]
    )

    assert status == 3
    assert not output.exists()
    assert "invalid workload manifest" in capsys.readouterr().err


def test_existing_output_directory_is_never_overwritten(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    manifest = _inputs(tmp_path)
    observed = _install_workflow_stubs(monkeypatch)
    output = tmp_path / "out"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("user data", encoding="utf-8")

    status = main(
        ["hybrid", "--workload", str(manifest), "--output-dir", str(output)]
    )

    assert status == 3
    assert sentinel.read_text(encoding="utf-8") == "user data"
    assert observed.request is None
    assert "refusing to reuse existing output directory" in capsys.readouterr().err


def test_write_failure_preserves_partial_trace_and_returns_tool_error(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    manifest = _inputs(tmp_path)
    _install_workflow_stubs(monkeypatch)
    import bmo_check_cli.hybrid as hybrid_cli

    def fail_save(report, path):
        raise OSError("simulated disk error")

    monkeypatch.setattr(hybrid_cli, "save_hybrid_workflow_report", fail_save)
    output = tmp_path / "out"

    status = main(
        ["hybrid", "--workload", str(manifest), "--output-dir", str(output)]
    )

    assert status == 3
    assert (output / "trace" / "manifest.json").is_file()
    assert (output / "static-certificate.json").is_file()
    assert "Partial trace artifacts were preserved" in capsys.readouterr().err
