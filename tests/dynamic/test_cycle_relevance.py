from __future__ import annotations

import json
import shutil
from pathlib import Path

from bmo_check_dynamic.analysis import AnalysisWindow, characterize_cycle_relevance
from bmo_check_dynamic.analysis.communication import CommunicationEdge
from bmo_check_dynamic.cli import main
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.trace import TraceWriter


def _window() -> AnalysisWindow:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.LOAD, 0x1000, 4),
        TraceEvent(1, 3, 0, 0x12, EventKind.LOAD, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x1000, 4),
    )
    return AnalysisWindow(
        window_id="window-p7-fixture",
        events=events,
        communication_edges=(
            CommunicationEdge("t1:e2", "t2:e1", 0x1000, 4),
        ),
    )


def test_cycle_relevance_recovers_checker_semantics_and_ppo_redundancy() -> None:
    report = characterize_cycle_relevance(_window())

    assert report.schema_version == "cycle-relevance-v1"
    assert report.full_relation_count > 0
    assert report.semantics.source_cycle_required is True
    assert report.semantics.target_cycle_forbidden is True
    assert report.source_ppo.direct_edge_count == 3
    assert report.source_ppo.transitive_reduction_candidate_count == 1
    assert report.target_ppo.direct_edge_count == 2
    assert report.target_ppo.transitive_reduction_candidate_count == 0
    assert report.rf.total_candidate_count == 4
    assert report.fr.total_candidate_count == 4
    assert report.hotspots[0].event_count == 2
    assert report.reachability_support_count == (
        report.source_ppo.transitive_reduction_candidate_count
        + report.target_ppo.transitive_reduction_candidate_count
    )
    assert sum(item.count for item in report.classification_counts) == (
        report.full_relation_count
    )
    assert report.estimated_explicit_relation_reduction == 1
    assert report.estimate_is_diagnostic_only is True


def test_cycle_relevance_cli_stops_before_proof(
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
            AssertionError("P7 must stop before proof")
        ),
    )
    output = tmp_path / "cycle-relevance.json"

    result = main(
        [
            "cycle-relevance",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--output",
            str(output),
        ]
    )

    assert result == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "trace-cycle-relevance-v1"
    assert payload["analysis_reached_windows"] is True
    assert payload["windows"][0]["semantics"]["schema_version"] == (
        "violation-cycle-semantics-v1"
    )
