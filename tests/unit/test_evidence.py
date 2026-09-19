from __future__ import annotations

from dataclasses import replace

import pytest

from bmo_check_core.evidence import (
    DiagnosticHint,
    EvidenceAttribute,
    EvidenceMaterialError,
    EvidenceLedger,
    LedgerError,
    ObservedFact,
    ProofFact,
    ProducerId,
    UnknownDischarge,
    UnknownFact,
    UnknownKind,
    UnknownProposition,
)
from bmo_check_core.identity import (
    EvidenceId,
    FunctionId,
    InstructionId,
    ModuleId,
    ThreadInstanceId,
    ThreadRoleId,
    TraceId,
)


A = "a" * 64
B = "b" * 64
C = "c" * 64


@pytest.fixture
def identities() -> dict[str, object]:
    module = ModuleId.from_parts(A, "executable")
    function = FunctionId.from_parts(module, 0x100)
    instruction = InstructionId.from_parts(module, 0x120)
    role = ThreadRoleId.from_parts(None, None, (function,))
    trace = TraceId.from_parts("1.0", B, (module,), ("complete",), C)
    instance = ThreadInstanceId.from_parts(trace, 1)
    return {
        "instruction": instruction,
        "trace": trace,
        "instance": instance,
    }


def test_proof_and_unknown_have_content_bound_ids(identities: dict[str, object]) -> None:
    producer = ProducerId("static-recovery", "c3")
    subject = identities["instruction"]
    assert isinstance(subject, InstructionId)
    proof = ProofFact.create(
        schema_version="1",
        producer=producer,
        subject=subject,
        rule="InstructionRecovered",
        scope="closure-a",
    )
    changed = replace(proof, rule="DifferentRule")
    ledger = EvidenceLedger()

    ledger.add(proof)
    with pytest.raises(LedgerError, match="id/content mismatch"):
        ledger.add(changed)


def test_unknown_can_bind_a_typed_proposition_without_legacy_id_guessing(
    identities: dict[str, object],
) -> None:
    producer = ProducerId("static-analysis", "c4")
    subject = identities["instruction"]
    assert isinstance(subject, InstructionId)
    proposition = UnknownProposition.create(
        kind=UnknownKind.UNKNOWN_ESCAPE.value,
        scope="scope-a",
        subjects=(subject,),
    )
    unknown = UnknownFact.create(
        schema_version="2",
        producer=producer,
        kind=UnknownKind.UNKNOWN_ESCAPE,
        reason="escape proof is open",
        subject=subject,
        scope="scope-a",
        proposition=proposition,
    )

    assert proposition.id == proposition.expected_id()
    assert unknown.proposition == proposition
    assert unknown.id == unknown.expected_id()
    legacy = UnknownFact.create(
        schema_version="2",
        producer=producer,
        kind=UnknownKind.UNKNOWN_ESCAPE,
        reason="escape proof is open",
        subject=subject,
        scope="scope-a",
    )
    assert legacy.proposition is None
    assert legacy.id != unknown.id

    with pytest.raises(EvidenceMaterialError, match="scope"):
        UnknownFact.create(
            schema_version="2",
            producer=producer,
            kind=UnknownKind.UNKNOWN_ESCAPE,
            reason="escape proof is open",
            subject=subject,
            scope="scope-a",
            proposition=UnknownProposition.create(
                kind=UnknownKind.UNKNOWN_ESCAPE.value,
                scope="scope-b",
                subjects=(subject,),
            ),
        )


def test_ledger_rejects_missing_and_nonproof_premises(identities: dict[str, object]) -> None:
    producer = ProducerId("static-analysis", "c3")
    subject = identities["instruction"]
    assert isinstance(subject, InstructionId)
    root = ProofFact.create(
        schema_version="1",
        producer=producer,
        subject=subject,
        rule="Root",
        scope="scope-a",
    )
    child = ProofFact.create(
        schema_version="1",
        producer=producer,
        subject=subject,
        rule="Child",
        scope="scope-a",
        premises=(root.id,),
    )
    with pytest.raises(LedgerError, match="missing proof premise"):
        EvidenceLedger().add(child)

    trace = identities["trace"]
    instance = identities["instance"]
    assert isinstance(trace, TraceId)
    assert isinstance(instance, ThreadInstanceId)
    observed = ObservedFact.create(
        schema_version="1",
        producer=ProducerId("trace-normalizer", "c3"),
        trace_id=trace,
        execution_id=instance,
        subject=subject,
        observation_kind="address",
        attributes=(EvidenceAttribute("address", "0x1000"),),
    )
    invalid = ProofFact.create(
        schema_version="1",
        producer=producer,
        subject=subject,
        rule="UsesObservation",
        scope="scope-a",
        premises=(observed.id,),
    )
    ledger = EvidenceLedger()
    ledger.add(observed)
    with pytest.raises(LedgerError, match="only ProofFact"):
        ledger.add(invalid)


def test_diagnostic_hint_can_reference_unknown_and_observation_but_not_prove(
    identities: dict[str, object],
) -> None:
    subject = identities["instruction"]
    trace = identities["trace"]
    instance = identities["instance"]
    assert isinstance(subject, InstructionId)
    assert isinstance(trace, TraceId)
    assert isinstance(instance, ThreadInstanceId)
    unknown = UnknownFact.create(
        schema_version="1",
        producer=ProducerId("static-affine", "c3"),
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="loop upper bound is missing",
        subject=subject,
        scope="scope-a",
        supporting_context=("pc=0x120",),
    )
    observed = ObservedFact.create(
        schema_version="1",
        producer=ProducerId("trace-normalizer", "c3"),
        trace_id=trace,
        execution_id=instance,
        subject=subject,
        observation_kind="affine-pattern",
        attributes=(EvidenceAttribute("stride", "64"),),
    )
    hint = DiagnosticHint.create(
        schema_version="1",
        producer=ProducerId("diagnostics", "c3"),
        scope="scope-a",
        unknown_ids=(unknown.id,),
        observed_ids=(observed.id,),
        root_cause="MissingLoopBound",
        confidence=0.75,
        explanation="runtime pattern points to a missing bound propagation rule",
    )
    ledger = EvidenceLedger()
    ledger.add(unknown)
    ledger.add(observed)
    ledger.add(hint)

    assert ledger.get(hint.id) == hint
    assert ledger.unresolved_unknowns("scope-a") == (unknown,)
    with pytest.raises(LedgerError, match="non-ProofFact"):
        ledger.proof_closure((hint.id,))


def test_unknown_discharge_requires_a_same_scope_proof(
    identities: dict[str, object],
) -> None:
    subject = identities["instruction"]
    assert isinstance(subject, InstructionId)
    producer = ProducerId("static-analysis", "c3")
    unknown = UnknownFact.create(
        schema_version="1",
        producer=producer,
        kind=UnknownKind.MISSING_PROVENANCE,
        reason="caller argument source is open",
        subject=subject,
        scope="scope-a",
    )
    proof = ProofFact.create(
        schema_version="1",
        producer=producer,
        subject=subject,
        rule="ArgumentProvenanceClosed",
        scope="scope-a",
    )
    wrong_scope = ProofFact.create(
        schema_version="1",
        producer=producer,
        subject=subject,
        rule="ArgumentProvenanceClosed",
        scope="scope-b",
    )
    ledger = EvidenceLedger()
    ledger.add(unknown)
    ledger.add(proof)
    ledger.add(wrong_scope)
    with pytest.raises(LedgerError, match="scope"):
        ledger.add_discharge(UnknownDischarge(unknown.id, wrong_scope.id, "scope-b"))

    ledger.add_discharge(UnknownDischarge(unknown.id, proof.id, "scope-a"))
    assert ledger.unresolved_unknowns("scope-a") == ()
    assert ledger.get(unknown.id) == unknown


def test_proof_closure_is_proof_only_and_ordered_from_premises(
    identities: dict[str, object],
) -> None:
    subject = identities["instruction"]
    assert isinstance(subject, InstructionId)
    producer = ProducerId("static-analysis", "c3")
    root = ProofFact.create(
        schema_version="1",
        producer=producer,
        subject=subject,
        rule="Root",
        scope="scope-a",
    )
    child = ProofFact.create(
        schema_version="1",
        producer=producer,
        subject=subject,
        rule="Child",
        scope="scope-a",
        premises=(root.id,),
    )
    ledger = EvidenceLedger()
    ledger.add(root)
    ledger.add(child)
    assert ledger.proof_closure((child.id,)) == (root, child)


def test_duplicate_identical_nodes_are_idempotent(identities: dict[str, object]) -> None:
    subject = identities["instruction"]
    assert isinstance(subject, InstructionId)
    proof = ProofFact.create(
        schema_version="1",
        producer=ProducerId("static-analysis", "c3"),
        subject=subject,
        rule="Stable",
        scope="scope-a",
    )
    ledger = EvidenceLedger()
    assert ledger.add(proof) == proof.id
    assert ledger.add(proof) == proof.id
    assert ledger.nodes() == (proof,)


def test_unknown_provenance_cannot_use_observed_fact(identities: dict[str, object]) -> None:
    subject = identities["instruction"]
    trace = identities["trace"]
    instance = identities["instance"]
    assert isinstance(subject, InstructionId)
    assert isinstance(trace, TraceId)
    assert isinstance(instance, ThreadInstanceId)
    observed = ObservedFact.create(
        schema_version="1",
        producer=ProducerId("trace-normalizer", "c3"),
        trace_id=trace,
        execution_id=instance,
        subject=subject,
        observation_kind="address",
    )
    unknown = UnknownFact.create(
        schema_version="1",
        producer=ProducerId("static-analysis", "c3"),
        kind=UnknownKind.UNKNOWN_ESCAPE,
        reason="escape is not closed",
        subject=subject,
        scope="scope-a",
        provenance=(observed.id,),
    )
    ledger = EvidenceLedger()
    ledger.add(observed)
    with pytest.raises(LedgerError, match="cannot depend"):
        ledger.add(unknown)


def test_fake_premise_id_is_still_a_missing_parent() -> None:
    fake = EvidenceId.from_parts(
        category="ProofFact",
        schema_version="1",
        producer="static@c3",
        subject="scope:scope-a",
        premises=(),
        content_discriminator='{"covered_events":[],"rule":"fake","scope":"scope-a"}',
    )
    with pytest.raises(LedgerError, match="missing proof premise"):
        EvidenceLedger().add(
            ProofFact.create(
                schema_version="1",
                producer=ProducerId("static", "c3"),
                subject=None,
                rule="child",
                scope="scope-a",
                premises=(fake,),
            )
        )
