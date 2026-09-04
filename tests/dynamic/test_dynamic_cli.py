from __future__ import annotations

import json
import shutil
from pathlib import Path

from bmo_check_dynamic.cli import main
from bmo_check_dynamic.model import EventKind, TraceEvent
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
