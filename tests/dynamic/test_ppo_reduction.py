from __future__ import annotations

import json
import shutil
from pathlib import Path

from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    PpoGraphInput,
    build_ppo_reduction,
    build_ppo_reduction_certificate,
    ppo_certificate_digest,
    replay_ppo_reduction,
)
from bmo_check_dynamic.analysis.communication import CommunicationEdge
from bmo_check_dynamic.model import EventKind, RemovedPpoEdge, TraceEvent
from bmo_check_dynamic.cli import main
from bmo_check_dynamic.trace import TraceWriter


def _events(*kinds: EventKind) -> tuple[TraceEvent, ...]:
    return tuple(
        TraceEvent(1, index, 0, 0x100 + index, kind, 0x1000 + index * 8, 4)
        for index, kind in enumerate(kinds, start=1)
    )


def _graph(
    events: tuple[TraceEvent, ...],
    source: set[tuple[str, str]],
    target: set[tuple[str, str]],
    endpoints: set[str],
    *,
    protected_source: set[tuple[str, str]] | None = None,
    protected_target: set[tuple[str, str]] | None = None,
    reasons: dict[str, tuple[str, ...]] | None = None,
) -> PpoGraphInput:
    return PpoGraphInput(
        window_id="p8-fixture",
        events=events,
        source_edges=frozenset(source),
        target_edges=frozenset(target),
        source_protected_edges=frozenset(protected_source or ()),
        target_protected_edges=frozenset(protected_target or ()),
        relevant_endpoints=frozenset(endpoints),
        endpoint_reasons=tuple(
            sorted((event_id, values) for event_id, values in (reasons or {}).items())
        ),
    )


def test_chain_reduction_has_replayable_witness() -> None:
    events = _events(EventKind.LOAD, EventKind.LOAD, EventKind.LOAD)
    edges = {("t1:e1", "t1:e2"), ("t1:e2", "t1:e3"), ("t1:e1", "t1:e3")}
    graph = _graph(events, edges, edges, {"t1:e1", "t1:e2", "t1:e3"})

    certificate, replay = build_ppo_reduction_certificate(graph)

    assert replay.accepted is True
    assert certificate.source.reduced_edge_count == 2
    assert certificate.target.reduced_edge_count == 2
    assert certificate.source.removed_edges[0].witness_path == (
        "t1:e1",
        "t1:e2",
        "t1:e3",
    )
    assert certificate.source.missing_pairs.pair_count == 0


def test_replay_rejects_tampered_witness() -> None:
    events = _events(EventKind.LOAD, EventKind.LOAD, EventKind.LOAD)
    edges = {("t1:e1", "t1:e2"), ("t1:e2", "t1:e3"), ("t1:e1", "t1:e3")}
    graph = _graph(events, edges, edges, {"t1:e1", "t1:e3"})
    certificate, _ = build_ppo_reduction_certificate(graph)
    bad_edge = RemovedPpoEdge(
        source_event="t1:e1",
        target_event="t1:e3",
        witness_path=("t1:e1", "t1:e3"),
    )
    bad_source = certificate.source.model_copy(update={"removed_edges": (bad_edge,)})
    bad_certificate = certificate.model_copy(update={"source": bad_source})

    replay = replay_ppo_reduction(graph, bad_certificate)

    assert replay.accepted is False
    assert replay.certificate_digest_matches is False
    assert any("witness path" in reason for reason in replay.reasons)


def test_replay_rejects_a_reduction_that_loses_required_reachability() -> None:
    events = _events(EventKind.LOAD, EventKind.LOAD, EventKind.LOAD)
    edges = {("t1:e1", "t1:e2"), ("t1:e2", "t1:e3"), ("t1:e1", "t1:e3")}
    graph = _graph(events, edges, edges, {"t1:e1", "t1:e2", "t1:e3"})
    certificate, _ = build_ppo_reduction_certificate(graph)
    bad_source = certificate.source.model_copy(
        update={
            "removed_edges": (
                RemovedPpoEdge(
                    source_event="t1:e1",
                    target_event="t1:e2",
                    witness_path=("t1:e1", "t1:e2"),
                ),
            ),
            "reduced_edge_count": 2,
            "reduced_edge_digest": "tampered",
            "preserved_pairs": certificate.source.required_reachability_pairs,
            "missing_pairs": certificate.source.missing_pairs,
            "extra_pairs": certificate.source.extra_pairs,
        }
    )
    bad_certificate = certificate.model_copy(update={"source": bad_source})
    bad_certificate = bad_certificate.model_copy(
        update={"proof_digest": ppo_certificate_digest(bad_certificate)}
    )

    replay = replay_ppo_reduction(graph, bad_certificate)

    assert replay.certificate_digest_matches is True
    assert replay.accepted is False
    assert any(
        "reachability inventory mismatch" in reason
        or "witness path" in reason
        for reason in replay.reasons
    )


def test_diamond_keeps_one_of_multiple_witness_paths() -> None:
    events = _events(
        EventKind.LOAD,
        EventKind.LOAD,
        EventKind.LOAD,
        EventKind.LOAD,
    )
    edges = {
        ("t1:e1", "t1:e2"),
        ("t1:e1", "t1:e3"),
        ("t1:e2", "t1:e4"),
        ("t1:e3", "t1:e4"),
        ("t1:e1", "t1:e4"),
    }
    graph = _graph(events, edges, edges, {"t1:e1", "t1:e4"})

    certificate, replay = build_ppo_reduction_certificate(graph)

    assert replay.accepted is True
    witness = certificate.source.removed_edges[0].witness_path
    assert witness in {
        ("t1:e1", "t1:e2", "t1:e4"),
        ("t1:e1", "t1:e3", "t1:e4"),
    }


def test_fence_boundary_edges_are_protected() -> None:
    events = _events(EventKind.LOAD, EventKind.MFENCE, EventKind.STORE)
    chain = {("t1:e1", "t1:e2"), ("t1:e2", "t1:e3")}
    edges = chain | {("t1:e1", "t1:e3")}
    graph = _graph(
        events,
        edges,
        edges,
        {"t1:e1", "t1:e3"},
        protected_source=chain,
        protected_target=chain,
        reasons={"t1:e2": ("fence",)},
    )

    certificate, replay = build_ppo_reduction_certificate(graph)

    assert replay.accepted is True
    assert {(item.source_event, item.target_event) for item in certificate.source.removed_edges} == {
        ("t1:e1", "t1:e3")
    }
    assert not (
        {("t1:e1", "t1:e2"), ("t1:e2", "t1:e3")}
        & {(item.source_event, item.target_event) for item in certificate.source.removed_edges}
    )


def test_source_and_target_are_reduced_independently_and_endpoints_are_bound() -> None:
    events = _events(EventKind.LOAD, EventKind.LOAD, EventKind.LOAD)
    source = {("t1:e1", "t1:e2"), ("t1:e2", "t1:e3"), ("t1:e1", "t1:e3")}
    target = {("t1:e1", "t1:e3")}
    graph = _graph(
        events,
        source,
        target,
        {"t1:e1", "t1:e3"},
        reasons={"t1:e1": ("rf",), "t1:e3": ("fr",)},
    )

    certificate, replay = build_ppo_reduction_certificate(graph)

    assert replay.accepted is True
    assert certificate.source.reduced_edge_count == 2
    assert certificate.target.reduced_edge_count == 1
    assert certificate.source.required_reachability_pairs.pair_count == 1
    assert certificate.source.required_reachability_pairs.sample[0].reasons == (
        "fr",
        "rf",
    )


def test_window_report_contains_shadow_only_comparison() -> None:
    events = _events(EventKind.LOAD, EventKind.STORE, EventKind.LOAD)
    window = AnalysisWindow(
        window_id="p8-window",
        events=events,
        communication_edges=(
            CommunicationEdge("t1:e1", "t1:e2", 0x1008, 4),
        ),
    )

    report = build_ppo_reduction(window)

    assert report.replay.accepted is True
    assert report.shadow.used_for_verdict is False
    assert report.shadow.full.source_ppo_edge_count >= report.shadow.reduced.source_ppo_edge_count


def test_ppo_cli_writes_certificate_and_replays_without_check_window(
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
            AssertionError("P8 shadow/replay must stop before proof")
        ),
    )
    output = tmp_path / "ppo-report.json"
    certificate = tmp_path / "ppo-certificate.json"

    assert main(
        [
            "ppo-reduction",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--output",
            str(output),
            "--certificate",
            str(certificate),
        ]
    ) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == (
        "trace-ppo-reduction-v1"
    )
    assert certificate.is_file()

    replay_output = tmp_path / "ppo-replay.json"
    assert main(
        [
            "ppo-replay",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--certificate",
            str(certificate),
            "--output",
            str(replay_output),
        ]
    ) == 0
    replay_payload = json.loads(replay_output.read_text(encoding="utf-8"))
    assert replay_payload["schema_version"] == "trace-ppo-reduction-replay-v1"
    assert all(item["accepted"] for item in replay_payload["windows"])
