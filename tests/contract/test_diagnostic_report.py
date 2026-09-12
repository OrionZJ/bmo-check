from __future__ import annotations

import json
from pathlib import Path

from bmo_check_core import (
    BinaryClosureId,
    CertificateVerdict,
    DynamicDiagnosticSnapshot,
    EvidenceSnapshot,
    InstructionId,
    MemoryOperandId,
    ModuleId,
    ObservedFact,
    ProducerId,
    StaticDiagnosticSnapshot,
    ThreadInstanceId,
    TraceId,
    UnknownFact,
    UnknownKind,
)
from bmo_check_diagnostics import build_diagnostic_report
from bmo_check_diagnostics import DiagnosticReportError
from bmo_check_diagnostics.serialization import (
    load_snapshot,
    report_to_dict,
    save_snapshot,
    snapshot_from_dict,
    snapshot_to_dict,
)
from bmo_check_dynamic.cli import main


HASH = "a" * 64


def _snapshots() -> tuple[
    StaticDiagnosticSnapshot,
    DynamicDiagnosticSnapshot,
    UnknownFact,
    ObservedFact,
]:
    module = ModuleId.from_parts(HASH, "executable")
    instruction = InstructionId.from_parts(module, 0x120)
    operand = MemoryOperandId.from_parts(instruction, 1, "store")
    closure = BinaryClosureId.from_parts(
        HASH, (("executable", HASH),), "x86_64-elf64-le"
    )
    trace = TraceId.from_parts(
        "trace-v1", HASH, (module,), ("synthetic",), HASH
    )
    unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "1"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="missing loop bound",
        subject=operand,
        scope="static.test",
    )
    observed = ObservedFact.create(
        schema_version="observed-v1",
        producer=ProducerId("dynamic-test", "1"),
        trace_id=trace,
        execution_id=ThreadInstanceId.from_parts(trace, 1),
        subject=operand,
        observation_kind="memory-range",
    )
    static = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v1",
        scope="static.test",
        verdict=CertificateVerdict.UNKNOWN,
        evidence=EvidenceSnapshot((unknown,)),
        binary_closure=closure,
        subject_ids=(operand,),
    )
    dynamic = DynamicDiagnosticSnapshot(
        schema_version="dynamic-diagnostic-v1",
        trace_id=trace,
        scope="trace.test",
        complete=True,
        evidence=EvidenceSnapshot((observed,)),
        binary_closure=closure,
    )
    return static, dynamic, unknown, observed


def test_report_keeps_static_verdict_and_typed_evidence() -> None:
    static, dynamic, unknown, observed = _snapshots()

    report = build_diagnostic_report(static, dynamic)

    assert report.static_verdict == CertificateVerdict.UNKNOWN
    assert report.static_proof_unchanged is True
    assert report.selected_unknowns == (unknown,)
    assert report.observed_facts == (observed,)
    assert report.coverage.exact_count == 1
    assert report.coverage.ambiguous_count == 0
    assert report.coverage.unmatched_count == 0
    assert report.hints[0].unknown_ids == (unknown.id,)
    assert report.hints[0].observed_ids == (observed.id,)
    assert report.hints[0].root_cause == UnknownKind.UNKNOWN_ROOT_CAUSE.value


def test_snapshot_json_round_trip_rebuilds_typed_identity(tmp_path: Path) -> None:
    static, dynamic, _, _ = _snapshots()

    for snapshot, kind in ((static, "static"), (dynamic, "dynamic")):
        document = snapshot_to_dict(snapshot)
        assert document["kind"] == kind
        rebuilt = snapshot_from_dict(document, expected_kind=kind)
        assert rebuilt == snapshot
        path = tmp_path / f"{kind}.json"
        save_snapshot(snapshot, path)
        assert load_snapshot(path, expected_kind=kind) == snapshot


def test_diagnose_cli_writes_versioned_report_without_upgrading_unknown(
    tmp_path: Path, capsys
) -> None:
    static, dynamic, _, _ = _snapshots()
    static_path = tmp_path / "static.json"
    dynamic_path = tmp_path / "dynamic.json"
    output = tmp_path / "diagnostic.json"
    save_snapshot(static, static_path)
    save_snapshot(dynamic, dynamic_path)

    result = main(
        [
            "diagnose",
            str(static_path),
            str(dynamic_path),
            "--output",
            str(output),
        ]
    )

    assert result == 2
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "diagnostic-report-v1"
    assert payload["static_verdict"] == "UNKNOWN"
    assert payload["static_proof_unchanged"] is True
    assert payload["coverage"]["exact_count"] == 1
    assert payload["hints"][0]["category"] == "DiagnosticHint"
    assert "static=UNKNOWN" in capsys.readouterr().out


def test_report_payload_keeps_observation_separate_from_static_unknown() -> None:
    static, dynamic, unknown, observed = _snapshots()
    report = build_diagnostic_report(static, dynamic)
    payload = report_to_dict(report)

    assert payload["selected_unknowns"][0]["id"] == unknown.id.value
    assert payload["observed_facts"][0]["id"] == observed.id.value
    assert payload["static_verdict"] == "UNKNOWN"
    assert payload["trace_id"] == dynamic.trace_id.value


def test_selected_unknowns_are_explicit_and_missing_id_is_rejected() -> None:
    static, dynamic, unknown, _ = _snapshots()

    report = build_diagnostic_report(
        static,
        dynamic,
        selected_unknown_ids=(unknown.id,),
    )
    assert report.coverage.selected_unknown_count == 1

    from bmo_check_core import EvidenceId

    missing = EvidenceId.from_parts(
        category="UnknownFact",
        schema_version="unknown-v1",
        producer="test@1",
        subject="scope:missing",
        premises=(),
        content_discriminator="missing",
    )
    try:
        build_diagnostic_report(static, dynamic, selected_unknown_ids=(missing,))
    except DiagnosticReportError as error:
        assert "absent from static snapshot" in str(error)
    else:
        raise AssertionError("missing selected Unknown must fail closed")


def test_snapshot_reader_rejects_tampered_evidence_id() -> None:
    static, _, _, _ = _snapshots()
    payload = snapshot_to_dict(static)
    payload["evidence"]["nodes"][0]["id"] = "evidence:" + "b" * 64

    try:
        snapshot_from_dict(payload, expected_kind="static")
    except ValueError as error:
        assert "id/content mismatch" in str(error)
    else:
        raise AssertionError("tampered evidence identity must fail closed")


def test_changing_dynamic_observations_cannot_change_static_result() -> None:
    static, dynamic, unknown, _ = _snapshots()
    without_observation = DynamicDiagnosticSnapshot(
        schema_version=dynamic.schema_version,
        trace_id=dynamic.trace_id,
        scope=dynamic.scope,
        complete=dynamic.complete,
        evidence=EvidenceSnapshot(),
        binary_closure=dynamic.binary_closure,
    )

    with_observation = build_diagnostic_report(static, dynamic)
    without = build_diagnostic_report(static, without_observation)

    assert with_observation.static_verdict == without.static_verdict == static.verdict
    assert with_observation.selected_unknowns == without.selected_unknowns == (unknown,)
    assert with_observation.records[0].status.value == "Exact"
    assert without.records[0].status.value == "Unmatched"
