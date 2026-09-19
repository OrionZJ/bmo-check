from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from bmo_check_core import TraceId
from bmo_check_dynamic.adapters import (
    DynamicTraceBindingError,
    bind_dynamic_certificate_to_trace,
    replay_dynamic_coverage,
    verify_dynamic_certificate_coverage,
)
from bmo_check_dynamic.model import DynamicCertificate, TraceScope, TraceVerdict
from bmo_check_dynamic.pipeline import analyze_trace
from bmo_check_dynamic.trace import trace_digest
from bmo_check_dynamic.model import BinaryFingerprint


def _certificate(manifest, trace_dir: Path, contract: Path) -> DynamicCertificate:
    return DynamicCertificate(
        verdict=TraceVerdict.UNKNOWN,
        scope=TraceScope(
            trace_ids=(manifest.trace_id,),
            trace_sha256=(trace_digest(trace_dir),),
            executable=manifest.executable,
            libraries=manifest.libraries,
            commands=(manifest.command,),
            working_directories=(manifest.working_directory,),
            analysis_scope="full",
        ),
        dbt_contract_sha256=hashlib.sha256(contract.read_bytes()).hexdigest(),
        analyzer_version="h3-test",
        trace_complete=True,
        event_count=2,
        thread_count=1,
        object_count=0,
        unique_pc_count=1,
        communication_edge_count=0,
        indirect_target_count=0,
        unknown_reasons=("test certificate remains UNKNOWN",),
    )


def _write_trace(trace_dir: Path, executable: Path) -> None:
    from bmo_check_dynamic.model import EventKind, TraceEvent
    from bmo_check_dynamic.trace import TraceWriter

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
            )
        )
    (trace_dir / ".complete").write_text("\n", encoding="ascii")


def _contract_path() -> Path:
    return Path(__file__).resolve().parents[2] / "specs" / "dynamic" / "dbt6-mo-off.yaml"


def test_binding_maps_manifest_id_to_trace_content_identity(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    _write_trace(trace_dir, Path(manifest.executable.path))
    contract = _contract_path()
    certificate = _certificate(manifest, trace_dir, contract)

    bound = bind_dynamic_certificate_to_trace(certificate, trace_dir, contract)

    assert bound.manifest_trace_id == manifest.trace_id == "fixture-trace"
    assert isinstance(bound.content_trace_id, TraceId)
    assert bound.content_trace_id == bound.snapshot.trace_id
    assert bound.content_trace_id.value != bound.manifest_trace_id
    assert bound.trace_sha256 == certificate.scope.trace_sha256[0]
    assert bound.dbt_contract_sha256 == certificate.dbt_contract_sha256
    assert bound.certificate is certificate


def test_determinate_legacy_certificate_is_explain_only(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "legacy-determinate"
    manifest = trace_manifest(trace_dir)
    _write_trace(trace_dir, Path(manifest.executable.path))
    contract = _contract_path()
    certificate = _certificate(manifest, trace_dir, contract).model_copy(
        update={
            "verdict": TraceVerdict.TRACE_SAFE,
            "unknown_reasons": (),
            "communication_edges_complete": True,
        }
    )

    with pytest.raises(DynamicTraceBindingError, match="coverage ledger"):
        verify_dynamic_certificate_coverage(certificate)
    with pytest.raises(DynamicTraceBindingError, match="coverage ledger"):
        bind_dynamic_certificate_to_trace(certificate, trace_dir, contract)


def test_binding_replays_decoded_event_inventory(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "replay-events"
    manifest = trace_manifest(trace_dir)
    _write_trace(trace_dir, Path(manifest.executable.path))
    contract = _contract_path()
    certificate = analyze_trace(trace_dir, dbt_contract=contract)
    assert certificate.verdict == TraceVerdict.TRACE_SAFE
    assert certificate.coverage is not None

    bad_coverage = certificate.coverage.model_copy(
        update={"event_sha256": "f" * 64}
    )
    tampered = certificate.model_copy(update={"coverage": bad_coverage})

    with pytest.raises(DynamicTraceBindingError, match="event digest"):
        bind_dynamic_certificate_to_trace(tampered, trace_dir, contract)


def test_replay_reconstructs_communication_and_window_coverage(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "replay-coverage"
    manifest = trace_manifest(trace_dir, control_closed=True)
    (trace_dir / "modules.tsv").write_text(
        f"0x1000\t0x2000\t{manifest.executable.path}\n", encoding="utf-8"
    )
    from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent
    from bmo_check_dynamic.trace import TraceWriter

    known = EventFlags.VALUE_KNOWN
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x1100, EventKind.LOAD, 0x4000, 4, 1, known))
        writer.write(TraceEvent(1, 2, 0, 0x1101, EventKind.STORE, 0x5000, 4, 1, known))
    with TraceWriter(trace_dir / "events-2.bin") as writer:
        writer.write(TraceEvent(2, 1, 0, 0x1200, EventKind.LOAD, 0x5000, 4, 1, known))
        writer.write(TraceEvent(2, 2, 0, 0x1201, EventKind.STORE, 0x4000, 4, 1, known))

    contract = _contract_path()
    certificate = analyze_trace(trace_dir, dbt_contract=contract)
    assert certificate.verdict == TraceVerdict.COUNTEREXAMPLE
    replay_dynamic_coverage(certificate, trace_dir)

    assert certificate.coverage is not None
    communication = certificate.coverage.communication.model_copy(
        update={"external_edge_count": certificate.coverage.communication.external_edge_count + 1}
    )
    tampered = certificate.model_copy(
        update={"coverage": certificate.coverage.model_copy(update={"communication": communication})}
    )
    with pytest.raises(DynamicTraceBindingError, match="communication coverage"):
        replay_dynamic_coverage(tampered, trace_dir)

    fake_subject = TraceId.from_parts(
        "trace-1.2", "a" * 64, (), ("tampered",), "b" * 64
    )
    subject_tampered = certificate.model_copy(
        update={
            "coverage": certificate.coverage.model_copy(
                update={"trace_subject": fake_subject.value}
            )
        }
    )
    with pytest.raises(DynamicTraceBindingError, match="subject"):
        replay_dynamic_coverage(subject_tampered, trace_dir)


@pytest.mark.parametrize(
    ("field", "expected_reason"),
    (
        ("trace_id", "manifest trace ID"),
        ("libraries", "loaded library fingerprints"),
        ("command", "command"),
        ("contract", "DBT contract digest"),
    ),
)
def test_binding_rejects_certificate_input_mismatch(
    trace_manifest,
    tmp_path: Path,
    field: str,
    expected_reason: str,
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    _write_trace(trace_dir, Path(manifest.executable.path))
    contract = _contract_path()
    certificate = _certificate(manifest, trace_dir, contract)
    if field == "trace_id":
        scope = certificate.scope.model_copy(update={"trace_ids": ("other-trace",)})
        certificate = certificate.model_copy(update={"scope": scope})
    elif field == "libraries":
        extra = BinaryFingerprint(path="/lib/other.so", sha256="b" * 64)
        scope = certificate.scope.model_copy(update={"libraries": (extra,)})
        certificate = certificate.model_copy(update={"scope": scope})
    elif field == "command":
        scope = certificate.scope.model_copy(update={"commands": (("/other",),)})
        certificate = certificate.model_copy(update={"scope": scope})
    else:
        certificate = certificate.model_copy(update={"dbt_contract_sha256": "c" * 64})

    with pytest.raises(DynamicTraceBindingError, match=expected_reason):
        bind_dynamic_certificate_to_trace(certificate, trace_dir, contract)


def test_binding_rejects_trace_changed_after_certificate_creation(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    _write_trace(trace_dir, Path(manifest.executable.path))
    contract = _contract_path()
    certificate = _certificate(manifest, trace_dir, contract)
    with (trace_dir / "modules.tsv").open("a", encoding="utf-8") as stream:
        stream.write("# changed after analysis\n")

    with pytest.raises(DynamicTraceBindingError, match="trace digest"):
        bind_dynamic_certificate_to_trace(certificate, trace_dir, contract)
