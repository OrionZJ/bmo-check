from pathlib import Path
import shutil

from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent, TraceVerdict
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


def test_incomplete_trace_is_unknown(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir, complete=False)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0, EventKind.THREAD_START))
    contract = _contract(tmp_path)
    certificate = analyze_trace(trace_dir, dbt_contract=contract)
    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert certificate.unknown_reasons


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
