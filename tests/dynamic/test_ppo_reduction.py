from __future__ import annotations

import json
import shutil
import sys
import subprocess
from pathlib import Path

import pytest

from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    PpoGraphInput,
    build_ppo_graph_input,
    build_ppo_reduction,
    build_ppo_reduction_certificate,
    profile_ppo_reduction_window,
    load_ppo_certificate_cache,
    save_ppo_certificate_cache,
    build_shadow_solver_comparison,
    run_isolated_solver_benchmark,
    build_solver_certificate,
    ppo_certificate_digest,
    replay_solver_certificate,
    replay_ppo_reduction,
)
from bmo_check_dynamic.analysis.communication import CommunicationEdge
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import (
    BenchmarkSide,
    EventFlags,
    EventKind,
    RemovedPpoEdge,
    ShadowSolverPhase,
    SolverDiagnosticProfile,
    TraceEvent,
)
from bmo_check_dynamic.cli import main
from bmo_check_dynamic.proof import run_symbolic_shadow
from bmo_check_dynamic.trace import TraceWriter
import bmo_check_dynamic.analysis.solver_benchmark as solver_benchmark_module


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


def test_ppo_profile_is_deterministic_and_reports_traversals() -> None:
    events = _events(EventKind.LOAD, EventKind.LOAD, EventKind.LOAD)
    edges = {("t1:e1", "t1:e2"), ("t1:e2", "t1:e3"), ("t1:e1", "t1:e3")}
    window = AnalysisWindow(
        "profile-fixture",
        events,
        (CommunicationEdge("t1:e1", "t1:e3", 0x1000, 4),),
    )

    first = profile_ppo_reduction_window(window)
    second = profile_ppo_reduction_window(window)

    assert first.replay_accepted is True
    assert first.certificate_digest == second.certificate_digest
    first_stage_shape = [
        item.model_copy(update={"wall_time_ms": 0.0, "cpu_time_ms": 0.0, "peak_rss_mb": None})
        for item in first.stages
    ]
    second_stage_shape = [
        item.model_copy(update={"wall_time_ms": 0.0, "cpu_time_ms": 0.0, "peak_rss_mb": None})
        for item in second.stages
    ]
    assert first_stage_shape == second_stage_shape
    stages = {item.stage.value: item for item in first.stages}
    assert "full_ppo_generation" in stages
    assert "reduced_ppo_computation" in stages
    assert "required_reachability_inventory" in stages
    assert "witness_generation" in stages
    assert stages["required_reachability_inventory"].graph_traversal_count > 0
    assert stages["required_reachability_inventory"].visited_node_count > 0


def test_ppo_certificate_cache_requires_binding_and_replay(tmp_path: Path) -> None:
    events = _events(EventKind.LOAD, EventKind.LOAD, EventKind.LOAD)
    edges = {("t1:e1", "t1:e2"), ("t1:e2", "t1:e3"), ("t1:e1", "t1:e3")}
    graph = _graph(events, edges, edges, {"t1:e1", "t1:e3"})
    certificate, replay = build_ppo_reduction_certificate(graph)
    cache = tmp_path / "ppo-cache.json"

    save_ppo_certificate_cache(
        cache,
        graph,
        certificate,
        replay,
        trace_digest="trace-a",
        window_digest="window-a",
        dbt_contract_digest="contract-a",
    )
    hit = load_ppo_certificate_cache(
        cache,
        graph,
        trace_digest="trace-a",
        window_digest="window-a",
        dbt_contract_digest="contract-a",
    )
    assert hit.status == "hit"
    assert hit.replay is not None and hit.replay.accepted is True

    stale = load_ppo_certificate_cache(
        cache,
        graph,
        trace_digest="trace-b",
        window_digest="window-a",
        dbt_contract_digest="contract-a",
    )
    assert stale.status == "stale"

    payload = json.loads(cache.read_text(encoding="utf-8"))
    payload["certificate"]["source"]["removed_edges"][0]["source_event"] = "t1:e2"
    cache.write_text(json.dumps(payload), encoding="utf-8")
    corrupt = load_ppo_certificate_cache(
        cache,
        graph,
        trace_digest="trace-a",
        window_digest="window-a",
        dbt_contract_digest="contract-a",
    )
    assert corrupt.status in {"stale", "corrupt"}


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

    profile_output = tmp_path / "ppo-profile.json"
    assert main(
        [
            "ppo-certificate-profile",
            str(trace_dir),
            "--dbt-contract",
            str(contract),
            "--output",
            str(profile_output),
        ]
    ) == 0
    profile_payload = json.loads(profile_output.read_text(encoding="utf-8"))
    assert profile_payload["schema_version"] == "trace-ppo-certificate-generation-v1"
    assert profile_payload["windows"][0]["replay_accepted"] is True
    assert {item["stage"] for item in profile_payload["windows"][0]["stages"]} >= {
        "full_ppo_generation",
        "independent_replay",
    }

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

    solver_output = tmp_path / "solver-report.json"
    solver_certificate = tmp_path / "solver-certificate.json"
    assert main(
        [
            "ppo-solver-compare",
            str(trace_dir),
            "--reduction-certificate",
            str(certificate),
            "--dbt-contract",
            str(contract),
            "--output",
            str(solver_output),
            "--certificate",
            str(solver_certificate),
            "--solver-timeout-ms",
            "1000",
        ]
    ) == 0
    solver_payload = json.loads(solver_output.read_text(encoding="utf-8"))
    assert solver_payload["schema_version"] == "trace-shadow-solver-v1"
    assert solver_certificate.is_file()

    solver_replay_output = tmp_path / "solver-replay.json"
    assert main(
        [
            "ppo-solver-replay",
            str(trace_dir),
            "--reduction-certificate",
            str(certificate),
            "--certificate",
            str(solver_certificate),
            "--dbt-contract",
            str(contract),
            "--output",
            str(solver_replay_output),
            "--solver-timeout-ms",
            "1000",
        ]
    ) == 0
    solver_replay_payload = json.loads(solver_replay_output.read_text(encoding="utf-8"))
    assert solver_replay_payload["schema_version"] == "trace-solver-replay-v1"
    assert all(item["accepted"] for item in solver_replay_payload["windows"])


def _solver_fixture() -> tuple[AnalysisWindow, PpoGraphInput, object]:
    events = _events(
        EventKind.LOAD,
        EventKind.LOAD,
        EventKind.LOAD,
        EventKind.LOAD,
    )
    edges = {
        ("t1:e1", "t1:e2"),
        ("t1:e2", "t1:e3"),
        ("t1:e3", "t1:e4"),
        ("t1:e1", "t1:e3"),
        ("t1:e2", "t1:e4"),
        ("t1:e1", "t1:e4"),
    }
    window = AnalysisWindow("p9-window", events, ())
    graph = _graph(events, edges, edges, {"t1:e1", "t1:e4"})
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted is True
    return window, graph, certificate


def test_shadow_solver_full_and_reduced_have_same_bounded_result() -> None:
    window, graph, certificate = _solver_fixture()

    comparison = build_shadow_solver_comparison(
        window,
        graph,
        certificate,
        control_flow_closed=True,
        timeout_ms=1_000,
        max_symbolic_terms=100_000,
        execute_solver=True,
    )

    assert comparison.replay_accepted is True
    assert comparison.result_match is True
    assert comparison.full.result == comparison.reduced.result == "unsat"
    assert comparison.full.assertion_count > 0
    assert comparison.full.z3_ast_count > 0
    assert comparison.reduced.source_ppo_edges < comparison.full.source_ppo_edges


def test_shadow_encoding_only_does_not_call_solver() -> None:
    window, graph, certificate = _solver_fixture()

    comparison = build_shadow_solver_comparison(
        window,
        graph,
        certificate,
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=100_000,
        execute_solver=False,
    )

    assert comparison.replay_accepted is True
    assert comparison.full.phase.value == "encoding"
    assert comparison.full.result == comparison.reduced.result == "not_run"
    assert comparison.result_match is True
    assert comparison.full.assertion_count > 0


def test_solver_certificate_replay_reconstructs_inputs_and_results() -> None:
    window, graph, reduction = _solver_fixture()
    comparison = build_shadow_solver_comparison(
        window,
        graph,
        reduction,
        control_flow_closed=True,
        timeout_ms=1_000,
        max_symbolic_terms=100_000,
        execute_solver=True,
    )
    certificate = build_solver_certificate(
        trace_sha256="trace-digest",
        window=window,
        graph=graph,
        reduction=reduction,
        comparison=comparison,
        dbt_contract_sha256="dbt-contract-digest",
        timeout_ms=1_000,
        max_symbolic_terms=100_000,
        execute_solver=True,
        control_flow_closed=True,
    )

    replay = replay_solver_certificate(
        window,
        graph,
        reduction,
        certificate,
        trace_sha256="trace-digest",
        dbt_contract_sha256="dbt-contract-digest",
        timeout_ms=1_000,
        max_symbolic_terms=100_000,
        execute_solver=True,
        control_flow_closed=True,
    )

    assert replay.accepted is True
    assert replay.binding_matches is True
    assert replay.result_matches is True


@pytest.mark.parametrize("case_name", ("fence", "rmw", "futex", "mixed_width", "rf_fr"))
def test_shadow_solver_small_correctness_corpus(case_name: str) -> None:
    cases = {
        "fence": (
            TraceEvent(1, 1, 0, 1, EventKind.LOAD, 0x1000, 4),
            TraceEvent(1, 2, 0, 2, EventKind.MFENCE),
            TraceEvent(1, 3, 0, 3, EventKind.STORE, 0x2000, 4),
            TraceEvent(2, 1, 0, 4, EventKind.STORE, 0x1000, 4),
            TraceEvent(2, 2, 0, 5, EventKind.LOAD, 0x2000, 4),
        ),
        "rmw": (
            TraceEvent(1, 1, 0, 1, EventKind.ATOMIC_RMW, 0x1000, 4),
            TraceEvent(2, 1, 0, 2, EventKind.STORE, 0x1000, 4),
        ),
        "futex": (
            TraceEvent(1, 1, 1, 1, EventKind.FUTEX_WAIT, 0x1000, 4),
            TraceEvent(1, 2, 2, 2, EventKind.LOAD, 0x2000, 4),
            TraceEvent(2, 1, 3, 3, EventKind.STORE, 0x1000, 4),
        ),
        "mixed_width": (
            TraceEvent(1, 1, 0, 1, EventKind.STORE, 0x1000, 8),
            TraceEvent(2, 1, 0, 2, EventKind.LOAD, 0x1004, 4),
        ),
        "rf_fr": (
            TraceEvent(1, 1, 0, 1, EventKind.STORE, 0x1000, 4),
            TraceEvent(2, 1, 0, 2, EventKind.LOAD, 0x1000, 4),
            TraceEvent(2, 2, 0, 3, EventKind.STORE, 0x1000, 4),
        ),
    }[case_name]
    events = cases
    communication = {
        (left.event_id, right.event_id): CommunicationEdge(
            left.event_id,
            right.event_id,
            left.address,
            min(left.size, right.size),
        )
        for left in events
        for right in events
        if left.thread_id != right.thread_id
        and left.overlaps(right)
        and (left.kind.is_write or right.kind.is_write)
    }
    window = AnalysisWindow(case_name, events, tuple(communication.values()))
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted is True
    comparison = build_shadow_solver_comparison(
        window,
        graph,
        certificate,
        control_flow_closed=True,
        timeout_ms=1_000,
        max_symbolic_terms=100_000,
        execute_solver=True,
    )
    assert comparison.replay_accepted is True
    assert comparison.result_match is not False


def test_isolated_solver_benchmark_records_child_resources(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "isolated-trace"
    trace_manifest(trace_dir, control_closed=True)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4))
    contract = Path(__file__).resolve().parents[2] / "specs" / "dynamic" / "dbt6-mo-off.yaml"
    output_dir = tmp_path / "workers"
    report = run_isolated_solver_benchmark(
        (trace_dir,),
        dbt_contract=contract,
        reduction_certificates=(),
        phase=ShadowSolverPhase.ENCODING,
        sides=(BenchmarkSide.FULL, BenchmarkSide.REDUCED),
        repetitions=1,
        budgets_ms=(5_000,),
        config=DynamicConfig(
            max_window_events=64,
            max_communication_edges=100,
            max_communication_active_events=100,
            max_object_events=100,
            solver_timeout_ms=5_000,
            max_symbolic_terms=100_000,
        ),
        process_grace_ms=10_000,
        worker_output_dir=output_dir,
        python_executable=sys.executable,
    )

    assert report.diagnostic_only is True
    assert len(report.runs) == 2
    assert all(run.status == "completed" for run in report.runs)
    assert all(run.child is not None for run in report.runs)
    assert all(run.child.peak_rss_mb is not None for run in report.runs)
    assert all(run.child.analysis_overhead_ms >= 0 for run in report.runs)
    assert all(aggregate.completed == 1 for aggregate in report.aggregates)
    assert all(aggregate.median_analysis_overhead_ms is not None for aggregate in report.aggregates)
    assert any(aggregate.constraint_breakdown for aggregate in report.aggregates)


def test_isolated_solver_worker_timeout_is_not_a_completed_result(
    trace_manifest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """外部 worker 超时只能记为 process_timeout，不能伪装成 UNKNOWN/完成。"""

    trace_dir = tmp_path / "timeout-trace"
    trace_manifest(trace_dir, control_closed=True)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(solver_benchmark_module.subprocess, "run", timeout)
    report = run_isolated_solver_benchmark(
        (trace_dir,),
        dbt_contract=Path(__file__).resolve().parents[2] / "specs" / "dynamic" / "dbt6-mo-off.yaml",
        reduction_certificates=(),
        phase=ShadowSolverPhase.ENCODING,
        sides=(BenchmarkSide.FULL,),
        repetitions=1,
        budgets_ms=(5,),
        config=DynamicConfig(),
        process_grace_ms=1,
        worker_output_dir=tmp_path / "timeout-workers",
        python_executable=sys.executable,
    )
    assert len(report.runs) == 1
    assert report.runs[0].status == "process_timeout"
    assert report.runs[0].child is None
    assert report.runs[0].error is not None


def test_fixed_rf_profile_records_observed_assignment() -> None:
    known = EventFlags.VALUE_KNOWN
    events = (
        TraceEvent(1, 1, 1, 0x10, EventKind.STORE, 0x1000, 4, 7, known),
        TraceEvent(2, 1, 2, 0x20, EventKind.LOAD, 0x1000, 4, 7, known),
    )
    window = AnalysisWindow("fixed-rf", events, ())
    _, observation = run_symbolic_shadow(
        window,
        source_ppo=set(),
        target_ppo=set(),
        control_flow_closed=True,
        timeout_ms=1_000,
        max_symbolic_terms=100_000,
        execute_solver=False,
        profile=SolverDiagnosticProfile.PPO_FIXED_RF,
    )

    inventory = observation.constraint_inventory
    assert inventory.profile is SolverDiagnosticProfile.PPO_FIXED_RF
    assert inventory.fixed_rf_parts == 1
    assert inventory.fixed_rf_assigned == 1
    assert inventory.fixed_rf_value_unknown == 0
