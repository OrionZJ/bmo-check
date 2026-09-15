from __future__ import annotations

import pytest

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
    ProofFact,
    StaticDiagnosticSnapshot,
    ThreadInstanceId,
    TraceId,
    UnknownDischarge,
    UnknownFact,
    UnknownKind,
)
from bmo_check_diagnostics import (
    CorrelationStatus,
    DiagnosticRootCause,
    affine_report_to_dict,
    build_affine_validation_report,
    build_diagnostic_report,
    correlate_unknowns,
)


HASH = "a" * 64


def _snapshots(
    *,
    static_scope: str = "static.full",
    dynamic_scope: str = "dynamic.application",
    observations: bool = True,
) -> tuple[StaticDiagnosticSnapshot, DynamicDiagnosticSnapshot, UnknownFact]:
    module = ModuleId.from_parts(HASH, "executable")
    operand = MemoryOperandId.from_parts(
        InstructionId.from_parts(module, 0x120), 0, "store"
    )
    closure = BinaryClosureId.from_parts(
        HASH, (("executable", HASH),), "x86_64-elf64-le"
    )
    trace = TraceId.from_parts(
        "trace-v1", HASH, (module,), ("complete",), HASH
    )
    unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "e3-h0"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="the loop upper bound is not closed",
        subject=operand,
        scope=static_scope,
    )
    nodes = ()
    if observations:
        nodes = (
            ObservedFact.create(
                schema_version="observed-v1",
                producer=ProducerId("dynamic-test", "e3-h0"),
                trace_id=trace,
                execution_id=ThreadInstanceId.from_parts(trace, 1),
                subject=operand,
                observation_kind="memory-site",
            ),
        )
    static = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v1",
        scope=static_scope,
        verdict=CertificateVerdict.UNKNOWN,
        evidence=EvidenceSnapshot((unknown,)),
        binary_closure=closure,
        subject_ids=(operand,),
    )
    dynamic = DynamicDiagnosticSnapshot(
        schema_version="dynamic-diagnostic-v1",
        trace_id=trace,
        scope=dynamic_scope,
        complete=True,
        evidence=EvidenceSnapshot(nodes),
        binary_closure=closure,
    )
    return static, dynamic, unknown


def test_h0_correlation_uses_site_and_closure_not_route_scope_labels() -> None:
    static, dynamic, unknown = _snapshots()

    assert static.scope != dynamic.scope
    record = correlate_unknowns(static, dynamic).records[0]

    # Characterizes the current snapshot correlator only. It does not establish
    # that the static and dynamic certificates cover compatible workloads.
    assert record.unknown_id == unknown.id
    assert record.status == CorrelationStatus.EXACT


def test_h0_d4_omits_dynamic_verdict_and_keeps_affine_as_separate_output() -> None:
    static, dynamic, _unknown = _snapshots(observations=False)

    diagnostic = build_diagnostic_report(static, dynamic)
    affine = build_affine_validation_report(static, dynamic)
    payload = diagnostic.to_dict()
    affine_payload = affine_report_to_dict(affine)

    assert diagnostic.static_verdict == CertificateVerdict.UNKNOWN
    assert diagnostic.trace_complete is True
    assert "dynamic_verdict" not in payload
    assert "patterns" not in payload
    assert affine.static_verdict == static.verdict
    assert affine_payload["patterns"]


def test_h2_d4_separates_blocking_and_discharged_unknowns() -> None:
    static, dynamic, open_unknown = _snapshots(observations=False)
    closed_unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "e3-h0"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="a historical bound gap was discharged",
        subject=None,
        scope=static.scope,
    )
    proof = ProofFact.create(
        schema_version="proof-v1",
        producer=ProducerId("static-test", "e3-h0"),
        subject=None,
        rule="BoundClosedByStaticProof",
        scope=static.scope,
    )
    evidence = EvidenceSnapshot(
        nodes=(closed_unknown, open_unknown, proof),
        discharges=(UnknownDischarge(closed_unknown.id, proof.id, static.scope),),
    )
    static = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v2",
        scope=static.scope,
        verdict=CertificateVerdict.UNKNOWN,
        evidence=evidence,
        binary_closure=static.binary_closure,
        subject_ids=static.subject_ids,
        blocking_unknown_ids=(open_unknown.id,),
    )

    assert static.ledger().unresolved_unknowns(static.scope) == (open_unknown,)
    report = build_diagnostic_report(static, dynamic)

    assert report.blocking_unknowns == report.selected_unknowns == (open_unknown,)
    assert report.discharged_unknowns == (closed_unknown,)
    assert report.coverage.blocking_unknown_count == 1
    assert report.coverage.discharged_unknown_count == 1
    payload = report.to_dict()
    assert [item["id"] for item in payload["blocking_unknowns"]] == [
        open_unknown.id.value
    ]
    assert [item["id"] for item in payload["discharged_unknowns"]] == [
        closed_unknown.id.value
    ]

    with pytest.raises(ValueError, match="discharged"):
        build_diagnostic_report(
            static,
            dynamic,
            selected_unknown_ids=(closed_unknown.id,),
        )

    legacy_snapshot = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v1",
        scope=static.scope,
        verdict=static.verdict,
        evidence=evidence,
        binary_closure=static.binary_closure,
        subject_ids=static.subject_ids,
    )
    legacy_report = build_diagnostic_report(legacy_snapshot, dynamic)
    assert {item.id for item in legacy_report.blocking_unknowns} == {
        closed_unknown.id,
        open_unknown.id,
    }
    assert legacy_report.discharged_unknowns == ()


def test_h1_complete_unmatched_trace_does_not_claim_site_was_not_executed() -> None:
    static, dynamic, _unknown = _snapshots(observations=False)

    report = build_diagnostic_report(static, dynamic)

    assert dynamic.complete is True
    assert report.records[0].status == CorrelationStatus.UNMATCHED
    assert report.hints[0].root_cause == DiagnosticRootCause.UNKNOWN_ROOT_CAUSE.value
    assert "workload and scope compatibility are not bound" in report.hints[0].explanation
