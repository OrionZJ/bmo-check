from __future__ import annotations

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
from bmo_check_diagnostics import (
    CorrelationKey,
    CorrelationStatus,
    correlate_unknowns,
)


HASH = "a" * 64


def _ids():
    module = ModuleId.from_parts(HASH, "executable")
    instruction = InstructionId.from_parts(module, 0x120)
    operand = MemoryOperandId.from_parts(instruction, 1, "store")
    closure = BinaryClosureId.from_parts(HASH, (("executable", HASH),), "x86_64-elf64-le")
    trace = TraceId.from_parts(
        "trace-v1",
        HASH,
        (module,),
        ("synthetic",),
        HASH,
    )
    return operand, closure, trace


def _unknown(subject, scope="static.test"):
    return UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "1"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="missing bound",
        subject=subject,
        scope=scope,
    )


def _observed(subject, trace):
    return ObservedFact.create(
        schema_version="observed-v1",
        producer=ProducerId("dynamic-test", "1"),
        trace_id=trace,
        execution_id=ThreadInstanceId.from_parts(trace, 1),
        subject=subject,
        observation_kind="memory-range",
    )


def _snapshots(*, same_closure=True, subject=True):
    operand, closure, trace = _ids()
    unknown = _unknown(operand if subject else None)
    observed = _observed(operand if subject else None, trace)
    static = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v1",
        scope="static.test",
        verdict=CertificateVerdict.UNKNOWN,
        evidence=EvidenceSnapshot((unknown,)),
        binary_closure=closure,
    )
    dynamic = DynamicDiagnosticSnapshot(
        schema_version="dynamic-diagnostic-v1",
        trace_id=trace,
        scope="trace.test",
        complete=True,
        evidence=EvidenceSnapshot((observed,)),
        binary_closure=closure if same_closure else BinaryClosureId.from_parts(
            "b" * 64, (("executable", "b" * 64),), "x86_64-elf64-le"
        ),
    )
    return static, dynamic, unknown, observed


def test_exact_correlation_preserves_static_unknown_verdict() -> None:
    static, dynamic, unknown, observed = _snapshots()

    report = correlate_unknowns(static, dynamic)

    assert report.static_verdict == CertificateVerdict.UNKNOWN
    assert report.records[0].status == CorrelationStatus.EXACT
    assert report.records[0].key == CorrelationKey.SUBJECT
    assert report.records[0].unknown_id == unknown.id
    assert report.records[0].observed_ids == (observed.id,)


def test_closure_mismatch_is_unmatched_even_when_subject_matches() -> None:
    static, dynamic, _, _ = _snapshots(same_closure=False)

    record = correlate_unknowns(static, dynamic).records[0]

    assert record.status == CorrelationStatus.UNMATCHED
    assert record.key == CorrelationKey.BINARY_CLOSURE
    assert record.observed_ids == ()


def test_missing_subject_is_not_guessed() -> None:
    static, dynamic, _, _ = _snapshots(subject=False)

    record = correlate_unknowns(static, dynamic).records[0]

    assert record.status == CorrelationStatus.UNMATCHED
    assert record.key == CorrelationKey.NONE
