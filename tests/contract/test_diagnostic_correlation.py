from __future__ import annotations

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


def test_legacy_location_fallback_correlates_static_unknown_without_subject() -> None:
    _operand, closure, trace = _ids()
    module_path = "/bin/fixture"
    unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "1"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="loop upper bound is not closed",
        subject=None,
        scope="static.test",
        supporting_context=(
            f"legacy.module={module_path}",
            "legacy.pc=0x120",
            "legacy.kind=Store",
        ),
    )
    instruction = InstructionId.from_parts(ModuleId.from_parts(HASH, "executable"), 0x120)
    observed = ObservedFact.create(
        schema_version="observed-v1",
        producer=ProducerId("dynamic-test", "1"),
        trace_id=trace,
        execution_id=ThreadInstanceId.from_parts(trace, 1),
        subject=instruction,
        observation_kind="memory-site",
        attributes=(
            EvidenceAttribute("module_path", module_path),
            EvidenceAttribute("elf_pc", "0x120"),
            EvidenceAttribute("event_kind", "Store"),
            EvidenceAttribute("operand_index", "0"),
        ),
    )
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
        binary_closure=closure,
    )

    record = correlate_unknowns(static, dynamic).records[0]

    assert record.status == CorrelationStatus.EXACT
    assert record.key == CorrelationKey.INSTRUCTION
    assert record.observed_ids == (observed.id,)


def test_old_site_only_trace_is_ambiguous_for_multiple_static_operands() -> None:
    _operand, closure, trace = _ids()
    module_path = "/bin/fixture"
    context = (
        f"legacy.module={module_path}",
        "legacy.pc=0x120",
        "legacy.kind=Store",
    )
    unknowns = tuple(
        UnknownFact.create(
            schema_version="unknown-v1",
            producer=ProducerId("static-test", str(index)),
            kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
            reason="loop upper bound is not closed",
            subject=None,
            scope="static.test",
            supporting_context=context + (f"legacy.detail.operand={index}",),
        )
        for index in (0, 1)
    )
    instruction = InstructionId.from_parts(ModuleId.from_parts(HASH, "executable"), 0x120)
    observed = ObservedFact.create(
        schema_version="observed-v1",
        producer=ProducerId("dynamic-test", "1"),
        trace_id=trace,
        execution_id=ThreadInstanceId.from_parts(trace, 1),
        subject=instruction,
        observation_kind="memory-site",
        attributes=(
            EvidenceAttribute("module_path", module_path),
            EvidenceAttribute("elf_pc", "0x120"),
            EvidenceAttribute("event_kind", "Store"),
            EvidenceAttribute("operand_identity", "missing"),
        ),
    )
    static = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v1",
        scope="static.test",
        verdict=CertificateVerdict.UNKNOWN,
        evidence=EvidenceSnapshot(unknowns),
        binary_closure=closure,
    )
    dynamic = DynamicDiagnosticSnapshot(
        schema_version="dynamic-diagnostic-v1",
        trace_id=trace,
        scope="trace.test",
        complete=True,
        evidence=EvidenceSnapshot((observed,)),
        binary_closure=closure,
    )

    records = correlate_unknowns(static, dynamic).records

    assert len(records) == 2
    assert all(item.status == CorrelationStatus.AMBIGUOUS for item in records)
    assert all(item.key == CorrelationKey.INSTRUCTION for item in records)


def test_call_site_location_can_correlate_an_indirect_target_observation() -> None:
    _operand, closure, trace = _ids()
    module_path = "/bin/fixture"
    unknown = UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "1"),
        kind=UnknownKind.INCOMPLETE_INDIRECT_TARGET,
        reason="indirect call target set is incomplete",
        subject=None,
        scope="static.test",
        supporting_context=(
            f"legacy.module={module_path}",
            "legacy.pc=0x120",
        ),
    )
    instruction = InstructionId.from_parts(ModuleId.from_parts(HASH, "executable"), 0x120)
    observed = ObservedFact.create(
        schema_version="observed-v1",
        producer=ProducerId("dynamic-test", "1"),
        trace_id=trace,
        execution_id=ThreadInstanceId.from_parts(trace, 1),
        subject=instruction,
        observation_kind="indirect-target",
        attributes=(
            EvidenceAttribute("module_path", module_path),
            EvidenceAttribute("elf_pc", "0x120"),
            EvidenceAttribute("event_kind", "IndirectTarget"),
            EvidenceAttribute("target_min", "0x500"),
            EvidenceAttribute("target_max", "0x500"),
        ),
    )
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
        binary_closure=closure,
    )

    record = correlate_unknowns(static, dynamic).records[0]

    assert record.status == CorrelationStatus.EXACT
    assert record.key == CorrelationKey.INSTRUCTION
