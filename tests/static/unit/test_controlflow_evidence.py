from __future__ import annotations

from pathlib import Path

from bmo_check_core import ObservedFact, UnknownFact as CanonicalUnknownFact
from bmo_check_core.evidence import DiagnosticHint
from bmo_check_core.evidence import UnknownKind as CanonicalUnknownKind
from bmo_check_static.binary.dependency_closure import build_program_manifest
from bmo_check_static.binary.angr_backend import AngrBackendError
from bmo_check_static.controlflow import recover_control_flow, recover_control_flow_with_evidence
from bmo_check_static.model import ExecutionScope


def _manifest(executable: Path):
    roots = tuple(
        path
        for path in (
            Path("/lib64"),
            Path("/lib/x86_64-linux-gnu"),
            Path("/usr/lib/x86_64-linux-gnu"),
        )
        if path.is_dir()
    )
    return build_program_manifest(
        executable,
        roots,
        ExecutionScope(),
        "dbt6-mo-off-v1",
        "test-revision",
    )


def test_cfg_evidence_sidecar_preserves_report_and_emits_static_unknown(
    elf_fixture,
    monkeypatch,
) -> None:
    manifest = _manifest(elf_fixture.executable)
    assert manifest.executable is not None

    def fail(_module):
        raise AngrBackendError("synthetic CFG failure")

    monkeypatch.setattr(
        "bmo_check_static.controlflow.cfg.load_cfg",
        fail,
    )
    legacy = recover_control_flow(manifest.executable, manifest)
    snapshot = recover_control_flow_with_evidence(manifest.executable, manifest)

    assert snapshot.report == legacy
    assert len(snapshot.unknown_ids) == 1
    unknown = snapshot.ledger.get(snapshot.unknown_ids[0])
    assert isinstance(unknown, CanonicalUnknownFact)
    assert unknown.kind == CanonicalUnknownKind.CFG_BACKEND_FAILURE
    assert all(
        not isinstance(node, (ObservedFact, DiagnosticHint))
        for node in snapshot.ledger.nodes()
    )
