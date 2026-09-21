from __future__ import annotations

import json
import shutil
from pathlib import Path

from bmo_check_dynamic.analysis import AnalysisWindow, characterize_obligation_bottleneck
from bmo_check_dynamic.analysis.communication import CommunicationEdge
from bmo_check_dynamic.cli import main
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.proof import characterize_symbolic_encoding
from bmo_check_dynamic.trace import TraceWriter


def _window() -> AnalysisWindow:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 3, 0, 0x12, EventKind.LOAD, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 4),
    )
    return AnalysisWindow(
        window_id="window-p6-fixture",
        events=events,
        communication_edges=(
            CommunicationEdge("t1:e2", "t2:e1", 0x1000, 4),
        ),
    )


def test_obligation_bottleneck_matches_symbolic_from_read_candidates() -> None:
    window = _window()

    report = characterize_obligation_bottleneck(window)
    symbolic = characterize_symbolic_encoding(window)

    assert report.schema_version == "obligation-bottleneck-v1"
    assert report.inventory_obligation_count > 0
    assert report.from_read_candidate_count == symbolic.from_read_candidate_count
    assert report.rf_candidate_count == 4
    assert report.component_count == 1
    assert report.hotspots[0].event_count == 2
    assert report.hotspots[0].communication_endpoint_count == 1
    assert report.hotspots[0].from_read_exposure_total == 4


def test_obligation_bottleneck_classifies_boundaries() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.LFENCE),
        TraceEvent(1, 3, 0, 0x12, EventKind.ATOMIC_RMW, 0x1000, 4),
        TraceEvent(1, 4, 0, 0x13, EventKind.FUTEX_WAIT, 0x2000, 4),
    )
    report = characterize_obligation_bottleneck(
        AnalysisWindow("window-boundaries", events, ())
    )
    kinds = {item.kind.value: item.total_count for item in report.relation_types}

    assert kinds["fence"] == 1
    assert kinds["atomic_rmw"] == 1
    assert kinds["sync_boundary"] == 1


def test_obligation_bottleneck_cli_stops_before_proof(
    trace_manifest, tmp_path: Path, monkeypatch
) -> None:
    trace_dir = tmp_path / "trace"
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
            AssertionError("P6 must stop before proof")
        ),
    )
    output = tmp_path / "obligation-bottleneck.json"

    result = main(
        [
            "obligation-bottleneck",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--output",
            str(output),
        ]
    )

    assert result == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "trace-obligation-bottleneck-v1"
    assert payload["analysis_reached_windows"] is True
    assert payload["windows"][0]["inventory_obligation_count"] > 0
