from __future__ import annotations

import json

import pytest

from bmo_check_core import (
    BinaryClosureId,
    CertificateVerdict,
    DynamicDiagnosticSnapshot,
    EvidenceAttribute,
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
from bmo_check_diagnostics import (
    AffineObservationError,
    ObservedAffineStatus,
    ObservedOverlap,
    affine_report_to_dict,
    build_affine_validation_report,
    site_filter_for_affine_unknowns,
    summarize_observed_affine_patterns,
)
from bmo_check_diagnostics.correlation import CorrelationStatus


HASH = "a" * 64


def _inputs() -> tuple[StaticDiagnosticSnapshot, DynamicDiagnosticSnapshot, UnknownFact]:
    module = ModuleId.from_parts(HASH, "executable")
    operand = MemoryOperandId.from_parts(
        InstructionId.from_parts(module, 0x120),
        0,
        "Store",
    )
    closure = BinaryClosureId.from_parts(
        HASH, (("executable", HASH),), "x86_64-elf64-le"
    )
    trace = TraceId.from_parts("trace-v1", HASH, (module,), ("synthetic",), HASH)
    unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "e1"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="loop upper bound is not closed",
        subject=operand,
        scope="static.test",
    )

    def observed(thread: int, addresses: str, *, complete: str = "true") -> ObservedFact:
        return ObservedFact.create(
            schema_version="observed-v1",
            producer=ProducerId("dynamic-test", "e1"),
            trace_id=trace,
            execution_id=ThreadInstanceId.from_parts(trace, thread),
            subject=operand,
            observation_kind="memory-site",
            attributes=(
                EvidenceAttribute("sample_count", "3"),
                EvidenceAttribute("address_distinct_count", "3"),
                EvidenceAttribute("address_min", addresses.split(",")[0]),
                EvidenceAttribute(
                    "address_max_end", f"0x{int(addresses.split(',')[-1], 16) + 4:x}"
                ),
                EvidenceAttribute("address_samples", addresses),
                EvidenceAttribute("address_sample_complete", complete),
                EvidenceAttribute("stride_candidates", "4"),
                EvidenceAttribute("stride_candidates_complete", complete),
            ),
        )

    first = observed(1, "0x3000,0x3004,0x3008")
    second = observed(2, "0x4000,0x4004,0x4008")
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
        evidence=EvidenceSnapshot((first, second)),
        binary_closure=closure,
    )
    return static, dynamic, unknown


def test_observed_affine_summary_is_stable_but_not_a_static_proof() -> None:
    static, dynamic, unknown = _inputs()

    patterns = summarize_observed_affine_patterns(static, dynamic)

    assert len(patterns) == 1
    pattern = patterns[0]
    assert pattern.unknown_id == unknown.id
    assert pattern.status == ObservedAffineStatus.STABLE
    assert pattern.overlap == ObservedOverlap.NONE_OBSERVED
    assert pattern.sample_count == 6
    assert pattern.base_candidates == (0x3000, 0x4000)
    assert pattern.stride_candidates == (4,)
    assert pattern.complete is True
    assert all(node.__class__.__name__ != "ProofFact" for node in static.evidence.nodes)


def test_sample_cap_and_incomplete_trace_stay_observational() -> None:
    static, dynamic, _ = _inputs()
    observed = next(node for node in dynamic.evidence.nodes if isinstance(node, ObservedFact))
    capped = ObservedFact.create(
        schema_version=observed.schema_version,
        producer=observed.producer,
        trace_id=observed.trace_id,
        execution_id=observed.execution_id,
        subject=observed.subject,
        observation_kind=observed.observation_kind,
        attributes=tuple(
            EvidenceAttribute(
                item.name,
                "false" if item.name in {"address_sample_complete", "stride_candidates_complete"} else item.value,
            )
            for item in observed.attributes
        ),
    )
    dynamic = DynamicDiagnosticSnapshot(
        schema_version=dynamic.schema_version,
        trace_id=dynamic.trace_id,
        scope=dynamic.scope,
        complete=False,
        evidence=EvidenceSnapshot((capped,)),
        binary_closure=dynamic.binary_closure,
    )

    pattern = summarize_observed_affine_patterns(static, dynamic)[0]

    assert pattern.status == ObservedAffineStatus.INCOMPLETE
    assert pattern.complete is False
    assert "address samples reached the adapter limit" in pattern.limitations


def test_validation_report_keeps_unknown_and_has_explicit_json_boundary(tmp_path) -> None:
    static, dynamic, _ = _inputs()

    report = build_affine_validation_report(static, dynamic)
    payload = affine_report_to_dict(report)
    path = tmp_path / "affine.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert report.static_verdict == CertificateVerdict.UNKNOWN
    assert report.static_proof_unchanged is True
    assert report.exercised_count == 1
    assert report.ambiguous_count == 0
    assert report.unmatched_count == 0
    assert payload["schema_version"] == "affine-validation-report-v1"
    assert payload["static_verdict"] == "UNKNOWN"
    assert json.loads(path.read_text(encoding="utf-8"))["static_proof_unchanged"] is True


def test_unobserved_affine_unknown_is_reported_without_changing_static_verdict() -> None:
    static, dynamic, _unknown = _inputs()
    empty = DynamicDiagnosticSnapshot(
        schema_version=dynamic.schema_version,
        trace_id=dynamic.trace_id,
        scope=dynamic.scope,
        complete=True,
        evidence=EvidenceSnapshot(),
        binary_closure=dynamic.binary_closure,
    )

    report = build_affine_validation_report(static, empty)

    assert report.static_verdict == CertificateVerdict.UNKNOWN
    assert report.exercised_count == 0
    assert report.ambiguous_count == 0
    assert report.not_executed_count == 1
    assert report.unmatched_count == 1
    assert report.patterns[0].status == ObservedAffineStatus.NOT_OBSERVED


def test_non_memory_match_does_not_count_as_an_affine_address_observation() -> None:
    static, dynamic, unknown = _inputs()
    fence = ObservedFact.create(
        schema_version="observed-v1",
        producer=ProducerId("dynamic-test", "e1-fence"),
        trace_id=dynamic.trace_id,
        execution_id=ThreadInstanceId.from_parts(dynamic.trace_id, 3),
        subject=unknown.subject,
        observation_kind="explicit-fence",
        attributes=(EvidenceAttribute("sample_count", "1"),),
    )
    dynamic = DynamicDiagnosticSnapshot(
        schema_version=dynamic.schema_version,
        trace_id=dynamic.trace_id,
        scope=dynamic.scope,
        complete=True,
        evidence=EvidenceSnapshot((fence,)),
        binary_closure=dynamic.binary_closure,
    )

    report = build_affine_validation_report(static, dynamic)
    pattern = report.patterns[0]

    assert pattern.correlation_status == CorrelationStatus.EXACT
    assert pattern.observed_ids == ()
    assert report.exercised_count == 0
    assert report.not_executed_count == 0
    assert report.unmatched_count == 1


def test_site_filter_uses_only_explicit_static_provenance() -> None:
    static, _dynamic, _unknown = _inputs()
    with_location = UnknownFact.create(
        schema_version="unknown-location-v1",
        producer=ProducerId("static-test", "e1-location"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="missing bound",
        subject=None,
        scope=static.scope,
        supporting_context=(
            "legacy.module=/bin/example",
            "legacy.pc=0x1234",
        ),
    )
    located = StaticDiagnosticSnapshot(
        schema_version=static.schema_version,
        scope=static.scope,
        verdict=static.verdict,
        evidence=EvidenceSnapshot((with_location,)),
        binary_closure=static.binary_closure,
    )

    assert site_filter_for_affine_unknowns(located) == {("/bin/example", 0x1234)}


def test_address_sample_order_is_not_rewritten_into_an_affine_stride() -> None:
    static, dynamic, _unknown = _inputs()
    observed = next(node for node in dynamic.evidence.nodes if isinstance(node, ObservedFact))
    reordered = ObservedFact.create(
        schema_version=observed.schema_version,
        producer=observed.producer,
        trace_id=observed.trace_id,
        execution_id=observed.execution_id,
        subject=observed.subject,
        observation_kind=observed.observation_kind,
        attributes=tuple(
            EvidenceAttribute(
                item.name,
                "0x3000,0x3008,0x3004"
                if item.name == "address_samples"
                else "8,-4"
                if item.name == "stride_candidates"
                else item.value,
            )
            for item in observed.attributes
        ),
    )
    dynamic = DynamicDiagnosticSnapshot(
        schema_version=dynamic.schema_version,
        trace_id=dynamic.trace_id,
        scope=dynamic.scope,
        complete=True,
        evidence=EvidenceSnapshot((reordered,)),
        binary_closure=dynamic.binary_closure,
    )

    pattern = summarize_observed_affine_patterns(static, dynamic)[0]

    assert pattern.thread_observations[0].sample_addresses == (0x3000, 0x3008, 0x3004)
    assert pattern.status == ObservedAffineStatus.VARIABLE


def test_explicit_empty_correlation_list_must_match_snapshot_count() -> None:
    static, dynamic, _unknown = _inputs()

    with pytest.raises(AffineObservationError, match="correlations must align"):
        summarize_observed_affine_patterns(static, dynamic, correlations=())
