from pathlib import Path
import shutil

from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent, TraceVerdict
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.pipeline import analyze_trace
from bmo_check_dynamic.trace import TraceWriter


def _contract(tmp_path: Path) -> Path:
    target = tmp_path / "contract.yaml"
    source = Path(__file__).resolve().parents[2] / "specs" / "dynamic" / "dbt6-mo-off.yaml"
    shutil.copyfile(source, target)
    return target


def test_no_cross_thread_communication_is_trace_safe(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4))
    contract = _contract(tmp_path)

    certificate = analyze_trace(trace_dir, dbt_contract=contract)
    assert certificate.verdict == TraceVerdict.TRACE_SAFE
    assert certificate.communication_edge_count == 0


def test_application_scope_records_and_excludes_external_runtime_edges(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    (trace_dir / "modules.tsv").write_text(
        f"0x1000\t0x2000\t{manifest.executable.path}\n",
        encoding="utf-8",
    )
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 1, 0x1100, EventKind.THREAD_START))
        writer.write(TraceEvent(1, 2, 1, 0x3000, EventKind.STORE, 0x5000, 4))
        writer.write(TraceEvent(1, 3, 3, 0x1101, EventKind.THREAD_END))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 2, 0x1200, EventKind.THREAD_START))
        writer.write(TraceEvent(2, 2, 2, 0x3001, EventKind.LOAD, 0x5000, 4))
        writer.write(TraceEvent(2, 3, 4, 0x1201, EventKind.THREAD_END))
    certificate = analyze_trace(
        trace_dir,
        dbt_contract=_contract(tmp_path),
        config=DynamicConfig(application_only=True),
    )
    assert certificate.verdict == TraceVerdict.TRACE_SAFE
    assert certificate.scope.analysis_scope == "application"
    assert certificate.communication_edge_count == 1
    assert certificate.external_runtime_edge_count == 1
    assert "application scope excludes external-module" in " ".join(
        certificate.assumptions
    )


def test_application_scope_stops_before_graph_when_partition_is_unknown(
    trace_manifest, tmp_path: Path, monkeypatch
) -> None:
    trace_dir = tmp_path / "overlapping-workers"
    manifest = trace_manifest(trace_dir)
    (trace_dir / "modules.tsv").write_text(
        f"0x1000\t0x2000\t{manifest.executable.path}\n",
        encoding="utf-8",
    )
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 1, 0x1100, EventKind.THREAD_START))
        writer.write(TraceEvent(1, 2, 10, 0x1101, EventKind.THREAD_END))
    for thread, start_ticket, end_ticket in ((2, 2, 8), (3, 3, 9)):
        with TraceWriter(trace_dir / f"events-{thread}.bin") as writer:
            writer.write(TraceEvent(thread, 1, start_ticket, 0x1100, EventKind.THREAD_START))
            writer.write(TraceEvent(thread, 2, start_ticket + 1, 0x1101, EventKind.STORE, 0x4000, 4))
            writer.write(TraceEvent(thread, 3, end_ticket, 0x1102, EventKind.THREAD_END))

    def unexpected_graph_scan(*_args, **_kwargs):
        raise AssertionError("an unknown partition must not build a communication graph")

    monkeypatch.setattr(
        "bmo_check_dynamic.pipeline.find_communication_edges", unexpected_graph_scan
    )
    certificate = analyze_trace(
        trace_dir,
        dbt_contract=_contract(tmp_path),
        config=DynamicConfig(application_only=True),
    )
    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert certificate.communication_edge_count == 0
    assert not certificate.windows
    assert any("safe main-module partition" in reason for reason in certificate.unknown_reasons)


def test_application_partition_can_close_without_runtime_graph(
    trace_manifest, tmp_path: Path, monkeypatch
) -> None:
    trace_dir = tmp_path / "disjoint-workers"
    manifest = trace_manifest(trace_dir)
    (trace_dir / "modules.tsv").write_text(
        f"0x1000\t0x2000\t{manifest.executable.path}\n",
        encoding="utf-8",
    )
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 1, 0x1100, EventKind.THREAD_START))
        writer.write(TraceEvent(1, 2, 2, 0x1101, EventKind.THREAD_CREATE, address=2))
        writer.write(TraceEvent(1, 3, 10, 0x1102, EventKind.THREAD_JOIN, aux=2))
        writer.write(TraceEvent(1, 4, 11, 0x1103, EventKind.THREAD_END))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 3, 0x1200, EventKind.THREAD_START))
        writer.write(TraceEvent(2, 2, 4, 0x1104, EventKind.STORE, 0x5000, 4))
        writer.write(TraceEvent(2, 3, 9, 0x1201, EventKind.THREAD_END))

    def unexpected_graph_scan(*_args, **_kwargs):
        raise AssertionError("a closed disjoint partition must not scan runtime edges")

    monkeypatch.setattr(
        "bmo_check_dynamic.pipeline.find_communication_edges", unexpected_graph_scan
    )
    certificate = analyze_trace(
        trace_dir,
        dbt_contract=_contract(tmp_path),
        config=DynamicConfig(application_only=True),
    )
    assert certificate.verdict == TraceVerdict.TRACE_SAFE
    assert not certificate.communication_edges_complete
    assert certificate.windows == ()


def test_application_atomic_event_does_not_use_partition_shortcut(
    trace_manifest, tmp_path: Path, monkeypatch
) -> None:
    trace_dir = tmp_path / "atomic-worker"
    manifest = trace_manifest(trace_dir)
    (trace_dir / "modules.tsv").write_text(
        f"0x1000\t0x2000\t{manifest.executable.path}\n",
        encoding="utf-8",
    )
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 1, 0x1100, EventKind.THREAD_START))
        writer.write(TraceEvent(1, 2, 2, 0x1101, EventKind.THREAD_CREATE, address=2))
        writer.write(TraceEvent(1, 3, 10, 0x1102, EventKind.THREAD_JOIN, address=2))
        writer.write(TraceEvent(1, 4, 11, 0x1103, EventKind.THREAD_END))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 3, 0x1200, EventKind.THREAD_START))
        writer.write(TraceEvent(2, 2, 4, 0x1104, EventKind.ATOMIC_RMW, 0x5000, 4))
        writer.write(TraceEvent(2, 3, 9, 0x1201, EventKind.THREAD_END))

    calls = 0

    def graph_scan(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return iter(())

    monkeypatch.setattr("bmo_check_dynamic.pipeline.find_communication_edges", graph_scan)
    certificate = analyze_trace(
        trace_dir,
        dbt_contract=_contract(tmp_path),
        config=DynamicConfig(application_only=True),
    )
    assert calls == 1
    assert certificate.communication_edges_complete


def test_incomplete_trace_is_unknown(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir, complete=False)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0, EventKind.THREAD_START))
    contract = _contract(tmp_path)
    certificate = analyze_trace(trace_dir, dbt_contract=contract)
    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert certificate.unknown_reasons


def test_object_materialization_budget_returns_unknown_before_update(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "object-budget"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4))
        writer.write(TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1004, 4))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 0, 0x11, EventKind.STORE, 0x1004, 4))
    certificate = analyze_trace(
        trace_dir,
        dbt_contract=_contract(tmp_path),
        config=DynamicConfig(max_object_events=1),
    )
    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert certificate.event_count == 3
    assert any("object identity materialization" in reason for reason in certificate.unknown_reasons)


def test_single_thread_trace_skips_object_materialization_budget(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "single-thread"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4))
        writer.write(TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1004, 4))
    certificate = analyze_trace(
        trace_dir,
        dbt_contract=_contract(tmp_path),
        config=DynamicConfig(max_object_events=1),
    )
    assert certificate.verdict == TraceVerdict.TRACE_SAFE
    assert certificate.communication_edge_count == 0
    assert certificate.assumptions[1].startswith("the complete trace contains one thread")


def test_cross_location_cycle_is_kept_in_one_window(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir, control_closed=True)
    known = EventFlags.VALUE_KNOWN
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4, 1, known))
        writer.write(TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2000, 4, 1, known))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4, 1, known))
        writer.write(TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x1000, 4, 1, known))
    contract = _contract(tmp_path)
    certificate = analyze_trace(trace_dir, dbt_contract=contract)
    assert certificate.verdict == TraceVerdict.COUNTEREXAMPLE
    assert len(certificate.windows) == 1


def test_unsupported_contract_is_unknown(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4))
    contract = _contract(tmp_path)
    contract.write_text(contract.read_text().replace("r,r", "rw,rw", 1))
    certificate = analyze_trace(trace_dir, dbt_contract=contract)
    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert any("unsupported DBT contract" in reason for reason in certificate.unknown_reasons)


def test_truncated_record_returns_certificate_instead_of_raising(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    path = trace_dir / "events-1.bin"
    with TraceWriter(path) as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4))
    path.write_bytes(path.read_bytes()[:-1])
    certificate = analyze_trace(trace_dir, dbt_contract=_contract(tmp_path))
    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert not certificate.trace_complete
    assert any("truncated" in reason for reason in certificate.unknown_reasons)


def test_dropped_trace_cannot_promote_local_counterexample(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir, control_closed=True)
    manifest.model_copy(update={"dropped_events": 1}).save(trace_dir / "manifest.json")
    for thread, read_address, write_address in ((1, 0x1000, 0x2000), (2, 0x2000, 0x1000)):
        with TraceWriter(trace_dir / f"events-{thread}.bin") as writer:
            writer.write(TraceEvent(thread, 1, 0, 0x10, EventKind.LOAD,
                                    read_address, 4, 1, EventFlags.VALUE_KNOWN))
            writer.write(TraceEvent(thread, 2, 0, 0x20, EventKind.STORE,
                                    write_address, 4, 1, EventFlags.VALUE_KNOWN))
    certificate = analyze_trace(trace_dir, dbt_contract=_contract(tmp_path))
    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert not certificate.windows
