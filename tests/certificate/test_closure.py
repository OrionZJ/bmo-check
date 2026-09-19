from __future__ import annotations

import pytest

from bmo_check_core import (
    BinaryClosureId,
    CertificateBinding,
    CertificateError,
    CertificateVerdict,
    EvidenceAttribute,
    EvidenceLedger,
    FunctionId,
    InstructionId,
    MemoryEventId,
    MemoryOperandId,
    ModuleId,
    ObservedFact,
    ProofFact,
    ProducerId,
    RemovalDecision,
    StaticCertificate,
    ThreadInstanceId,
    ThreadRoleId,
    TraceCertificate,
    TraceId,
    TraceVerdict,
    UnknownFact,
    UnknownKind,
    UnknownProposition,
    audit_unknown_propositions,
    verify_static_certificate,
    verify_trace_certificate,
)


A = "a" * 64
B = "b" * 64
C = "c" * 64


def _binding(scope: str = "scope-a", executable: str = A) -> CertificateBinding:
    closure = BinaryClosureId.from_parts(
        executable,
        (("executable", executable), ("shared_library", B)),
        "x86_64",
    )
    return CertificateBinding(
        binary_closure=closure,
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision="d" * 40,
        scope=scope,
    )


def _event() -> MemoryEventId:
    module = ModuleId.from_parts(A, "executable")
    function = FunctionId.from_parts(module, 0x100)
    instruction = InstructionId.from_parts(module, 0x120)
    operand = MemoryOperandId.from_parts(instruction, 0, "Store")
    role = ThreadRoleId.from_parts(None, None, (function,))
    return MemoryEventId.from_parts(operand, role, "Store", "event-1")


def _trace() -> tuple[TraceId, ThreadInstanceId]:
    module = ModuleId.from_parts(A, "executable")
    trace = TraceId.from_parts("1", B, (module,), ("complete",), C)
    return trace, ThreadInstanceId.from_parts(trace, 1)


def _proof(event: MemoryEventId) -> ProofFact:
    return ProofFact.create(
        schema_version="1",
        producer=ProducerId("static-test", "c5"),
        subject=event,
        rule="DisjointPartition",
        scope="scope-a",
        covered_events=(event,),
    )


def test_static_safe_requires_reachable_proof_for_each_removed_event() -> None:
    event = _event()
    proof = _proof(event)
    ledger = EvidenceLedger()
    ledger.add(proof)
    certificate = StaticCertificate(
        schema_version="static-1",
        verdict=CertificateVerdict.SAFE,
        binding=_binding(),
        proof_roots=(proof.id,),
        removal_decisions=(RemovalDecision(event, proof.id, "scope-a"),),
    )

    with pytest.raises(CertificateError, match="explain-only"):
        verify_static_certificate(certificate, ledger)


def test_static_safe_rejects_observed_or_diagnostic_root() -> None:
    trace, instance = _trace()
    observed = ObservedFact.create(
        schema_version="1",
        producer=ProducerId("trace", "c5"),
        trace_id=trace,
        execution_id=instance,
        subject=None,
        observation_kind="address",
        attributes=(EvidenceAttribute("address", "0x1000"),),
    )
    ledger = EvidenceLedger()
    ledger.add(observed)
    certificate = StaticCertificate(
        schema_version="static-1",
        verdict=CertificateVerdict.SAFE,
        binding=_binding(),
        proof_roots=(observed.id,),
    )

    with pytest.raises(CertificateError, match="proof closure"):
        verify_static_certificate(certificate, ledger)


def test_static_safe_rejects_removed_event_without_coverage() -> None:
    event = _event()
    other_event = MemoryEventId.from_parts(
        MemoryOperandId.from_parts(
            InstructionId.from_parts(ModuleId.from_parts(A, "executable"), 0x124),
            0,
            "Store",
        ),
        ThreadRoleId.from_legacy("other"),
        "Store",
        "event-2",
    )
    proof = _proof(other_event)
    ledger = EvidenceLedger()
    ledger.add(proof)
    certificate = StaticCertificate(
        schema_version="static-1",
        verdict=CertificateVerdict.SAFE,
        binding=_binding(),
        proof_roots=(proof.id,),
        removal_decisions=(RemovalDecision(event, proof.id, "scope-a"),),
    )

    with pytest.raises(CertificateError, match="not covered"):
        verify_static_certificate(certificate, ledger)


def test_static_safe_rejects_unresolved_unknown_and_accepts_explicit_discharge() -> None:
    event = _event()
    proof = _proof(event)
    unknown = UnknownFact.create(
        schema_version="1",
        producer=ProducerId("static-test", "c5"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="loop bound is missing",
        subject=event,
        scope="scope-a",
    )
    ledger = EvidenceLedger()
    ledger.add(unknown)
    ledger.add(proof)
    certificate = StaticCertificate(
        schema_version="static-1",
        verdict=CertificateVerdict.SAFE,
        binding=_binding(),
        proof_roots=(proof.id,),
        relevant_unknowns=(unknown.id,),
    )

    with pytest.raises(CertificateError, match="unresolved UnknownFact"):
        verify_static_certificate(certificate, ledger)

    from bmo_check_core import UnknownDischarge

    ledger.add_discharge(UnknownDischarge(unknown.id, proof.id, "scope-a"))
    with pytest.raises(CertificateError, match="explain-only"):
        verify_static_certificate(certificate, ledger)


def test_certificate_unknown_audit_distinguishes_typed_legacy_and_missing() -> None:
    event = _event()
    producer = ProducerId("static-test", "c6")
    legacy = UnknownFact.create(
        schema_version="1",
        producer=producer,
        kind=UnknownKind.UNKNOWN_ESCAPE,
        reason="legacy escape gap",
        subject=event,
        scope="scope-a",
    )
    proposition = UnknownProposition.create(
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS.value,
        scope="scope-a",
        subjects=(event,),
    )
    typed = UnknownFact.create(
        schema_version="2",
        producer=producer,
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="typed bounds gap",
        subject=event,
        scope="scope-a",
        proposition=proposition,
    )
    ledger = EvidenceLedger()
    ledger.add(legacy)
    ledger.add(typed)
    missing = MemoryEventId.from_parts(
        MemoryOperandId.from_parts(
            InstructionId.from_parts(ModuleId.from_parts(B, "executable"), 0x128),
            0,
            "Load",
        ),
        ThreadRoleId.from_legacy("missing"),
        "Load",
        "missing",
    )
    missing_id = UnknownFact.create(
        schema_version="1",
        producer=producer,
        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
        reason="missing node id fixture",
        subject=missing,
        scope="scope-a",
    ).id

    audit = audit_unknown_propositions(ledger, (legacy.id, typed.id, missing_id))

    assert audit.typed_ids == (typed.id,)
    assert audit.legacy_ids == (legacy.id,)
    assert audit.missing_ids == (missing_id,)


def test_static_safe_rejects_bounded_result_and_binding_mismatch() -> None:
    certificate = StaticCertificate(
        schema_version="static-1",
        verdict=CertificateVerdict.SAFE,
        binding=_binding(),
        bounded=True,
    )
    with pytest.raises(CertificateError, match="bounded"):
        verify_static_certificate(certificate, EvidenceLedger())

    mismatched = StaticCertificate(
        schema_version="static-1",
        verdict=CertificateVerdict.SAFE,
        binding=_binding(executable=B),
    )
    with pytest.raises(CertificateError, match="binding"):
        verify_static_certificate(
            mismatched,
            EvidenceLedger(),
            expected_binding=_binding(),
        )


def test_trace_certificate_accepts_only_same_trace_observed_roots() -> None:
    trace, instance = _trace()
    observed = ObservedFact.create(
        schema_version="1",
        producer=ProducerId("trace", "c5"),
        trace_id=trace,
        execution_id=instance,
        subject=None,
        observation_kind="target",
    )
    ledger = EvidenceLedger()
    ledger.add(observed)
    certificate = TraceCertificate(
        schema_version="trace-1",
        verdict=TraceVerdict.TRACE_SAFE,
        binding=_binding(),
        trace_id=trace,
        observed_roots=(observed.id,),
        complete=True,
    )

    with pytest.raises(CertificateError, match="explain-only"):
        verify_trace_certificate(certificate, ledger)


def test_unknown_legacy_certificate_remains_explainable() -> None:
    trace, _ = _trace()
    certificate = TraceCertificate(
        schema_version="trace-1",
        verdict=TraceVerdict.UNKNOWN,
        binding=_binding(),
        trace_id=trace,
    )

    result = verify_trace_certificate(certificate, EvidenceLedger())

    assert result.observed_roots == ()


def test_v2_placeholder_cannot_be_upgraded_with_empty_completeness() -> None:
    trace, _ = _trace()
    certificate = TraceCertificate(
        schema_version="trace-certificate-v2",
        verdict=TraceVerdict.TRACE_SAFE,
        binding=_binding(),
        trace_id=trace,
        complete=True,
    )

    with pytest.raises(CertificateError, match="completeness ledgers"):
        verify_trace_certificate(certificate, EvidenceLedger())


def test_trace_safe_rejects_incomplete_or_static_root() -> None:
    trace, _ = _trace()
    incomplete = TraceCertificate(
        schema_version="trace-1",
        verdict=TraceVerdict.TRACE_SAFE,
        binding=_binding(),
        trace_id=trace,
        complete=False,
    )
    with pytest.raises(CertificateError, match="incomplete"):
        verify_trace_certificate(incomplete, EvidenceLedger())

    event = _event()
    proof = _proof(event)
    ledger = EvidenceLedger()
    ledger.add(proof)
    static_root = TraceCertificate(
        schema_version="trace-1",
        verdict=TraceVerdict.UNKNOWN,
        binding=_binding(),
        trace_id=trace,
        observed_roots=(proof.id,),
    )
    with pytest.raises(CertificateError, match="ObservedFact"):
        verify_trace_certificate(static_root, ledger)
