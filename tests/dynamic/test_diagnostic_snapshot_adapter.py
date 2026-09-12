from __future__ import annotations

import json
from pathlib import Path

from bmo_check_core import (
    CertificateVerdict,
    EvidenceSnapshot,
    StaticDiagnosticSnapshot,
    UnknownFact,
    UnknownKind,
    ProducerId,
)
from bmo_check_dynamic.adapters import dynamic_snapshot_from_trace
from bmo_check_dynamic.cli import main
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.trace import TraceWriter
from bmo_check_diagnostics.serialization import save_snapshot


def _write_trace(trace_dir: Path, executable: Path, *, operand: int | None = 1) -> None:
    (trace_dir / "modules.tsv").write_text(
        f"0x1000\t0x2000\t{executable}\n", encoding="utf-8"
    )
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(
            TraceEvent(
                thread_id=1,
                sequence=1,
                ticket=0,
                pc=0x1010,
                kind=EventKind.STORE,
                address=0x4000,
                size=4,
                operand_index=operand,
            )
        )
        writer.write(
            TraceEvent(
                thread_id=1,
                sequence=2,
                ticket=0,
                pc=0x1010,
                kind=EventKind.STORE,
                address=0x4004,
                size=4,
                operand_index=operand,
            )
        )
    # adapter 只把 client 的尾部 marker 当作完整轨迹；不完整 fixture 故意不写。
    if json.loads((trace_dir / "manifest.json").read_text(encoding="utf-8"))["complete"]:
        (trace_dir / ".complete").write_text("\n", encoding="ascii")


def test_dynamic_adapter_streams_sites_and_keeps_trace_identity(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    _write_trace(trace_dir, Path(manifest.executable.path))

    snapshot = dynamic_snapshot_from_trace(trace_dir)

    assert snapshot.complete is True
    assert snapshot.binary_closure is not None
    assert len(snapshot.observed_ids) == 1
    observed = snapshot.evidence.nodes[0]
    assert observed.observation_kind == "memory-site"
    assert any(item.name == "sample_count" and item.value == "2" for item in observed.attributes)


def test_missing_operand_is_site_level_observation_and_not_guessed(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    _write_trace(trace_dir, Path(manifest.executable.path), operand=None)

    snapshot = dynamic_snapshot_from_trace(trace_dir)
    observed = snapshot.evidence.nodes[0]

    assert observed.subject is not None
    assert observed.subject.prefix == "instruction"
    assert any(
        item.name == "operand_identity" and item.value == "missing"
        for item in observed.attributes
    )


def test_incomplete_trace_is_retained_as_dynamic_unknown(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir, complete=False)
    _write_trace(trace_dir, Path(manifest.executable.path))

    snapshot = dynamic_snapshot_from_trace(trace_dir)

    assert snapshot.complete is False
    unknowns = [node for node in snapshot.evidence.nodes if isinstance(node, UnknownFact)]
    assert len(unknowns) == 1
    assert unknowns[0].kind == UnknownKind.INCOMPLETE_RECOVERY
    assert "clean process exit" in unknowns[0].reason


def test_diagnose_cli_can_build_dynamic_snapshot_from_trace(
    trace_manifest, tmp_path: Path, capsys
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    _write_trace(trace_dir, Path(manifest.executable.path))
    dynamic = dynamic_snapshot_from_trace(trace_dir)
    observed = next(
        node for node in dynamic.evidence.nodes if hasattr(node, "subject") and node.subject is not None
    )
    unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "1"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="upper bound missing",
        subject=observed.subject,
        scope="static.test",
    )
    static = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v1",
        scope="static.test",
        verdict=CertificateVerdict.UNKNOWN,
        evidence=EvidenceSnapshot((unknown,)),
        binary_closure=dynamic.binary_closure,
        subject_ids=(observed.subject,),
    )
    static_path = tmp_path / "static.json"
    output = tmp_path / "report.json"
    save_snapshot(static, static_path)

    result = main(
        [
            "diagnose",
            str(static_path),
            "--trace",
            str(trace_dir),
            "--output",
            str(output),
        ]
    )

    assert result == 2
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["trace_complete"] is True
    assert payload["coverage"]["exact_count"] == 1
    assert "static=UNKNOWN" in capsys.readouterr().out
