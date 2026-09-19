from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from bmo_check_core import TraceId
from bmo_check_dynamic.adapters import (
    DynamicTraceBindingError,
    bind_dynamic_certificate_to_trace,
    verify_dynamic_certificate_coverage,
)
from bmo_check_dynamic.model import DynamicCertificate, TraceScope, TraceVerdict
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
