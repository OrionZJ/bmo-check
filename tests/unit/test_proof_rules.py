from __future__ import annotations

from bmo_check_core import (
    EvidenceLedger,
    LedgerError,
    ObligationKind,
    ProofObligation,
    ProofConclusion,
    ProofFact,
    ProofRuleDefinition,
    ProofRuleRegistry,
    ProofRuleReplayStatus,
    ProducerId,
    PropositionId,
    RegisteredProofRule,
    UnknownDischarge,
    UnknownFact,
    UnknownKind,
    UnknownProposition,
    replay_proof_rule,
)


def _proof(
    *,
    registered: RegisteredProofRule | None = None,
    conclusion: ProofConclusion | None = None,
) -> ProofFact:
    return ProofFact.create(
        schema_version="2",
        producer=ProducerId("rule-test", "1"),
        subject=None,
        rule="EscapeClosed",
        scope="scope-a",
        registered_rule=registered,
        conclusion=conclusion,
    )


def test_registered_rule_replay_requires_exact_rule_and_conclusion() -> None:
    registered = RegisteredProofRule.create(name="EscapeClosed", version="1")
    conclusion = ProofConclusion.create(
        proposition_id=PropositionId.from_parts("escape", ("scope-a",)),
        scope="scope-a",
    )
    proof = _proof(registered=registered, conclusion=conclusion)
    ledger = EvidenceLedger()
    ledger.add(proof)
    registry = ProofRuleRegistry(
        definitions=(ProofRuleDefinition(registered, "EscapeClosed"),)
    )

    replay = replay_proof_rule(proof, ledger, registry)

    assert replay.status is ProofRuleReplayStatus.VALID


def test_legacy_or_unregistered_rule_stays_incomplete() -> None:
    legacy = _proof()
    ledger = EvidenceLedger()
    ledger.add(legacy)
    registry = ProofRuleRegistry(definitions=())

    assert (
        replay_proof_rule(legacy, ledger, registry).status
        is ProofRuleReplayStatus.INCOMPLETE
    )

    registered = RegisteredProofRule.create(name="EscapeClosed", version="2")
    conclusion = ProofConclusion.create(
        proposition_id=PropositionId.from_parts("escape", ("scope-a",)),
        scope="scope-a",
    )
    unregistered = _proof(registered=registered, conclusion=conclusion)
    ledger.add(unregistered)
    assert (
        replay_proof_rule(unregistered, ledger, registry).status
        is ProofRuleReplayStatus.INCOMPLETE
    )


def test_rule_registry_rejects_duplicate_versioned_identities() -> None:
    registered = RegisteredProofRule.create(name="EscapeClosed", version="1")
    definition = ProofRuleDefinition(registered, "EscapeClosed")

    try:
        ProofRuleRegistry(definitions=(definition, definition))
    except ValueError as error:
        assert "duplicate" in str(error)
    else:
        raise AssertionError("duplicate registered proof rules must be rejected")


def test_typed_discharge_requires_same_proposition_and_registered_rule() -> None:
    proposition = UnknownProposition.create(
        kind=UnknownKind.UNKNOWN_ESCAPE.value,
        scope="scope-a",
    )
    unknown = UnknownFact.create(
        schema_version="2",
        producer=ProducerId("rule-test", "1"),
        kind=UnknownKind.UNKNOWN_ESCAPE,
        reason="escape is open",
        subject=None,
        scope="scope-a",
        proposition=proposition,
    )
    registered = RegisteredProofRule.create(name="EscapeClosed", version="1")
    proof = ProofFact.create(
        schema_version="2",
        producer=ProducerId("rule-test", "1"),
        subject=None,
        rule="EscapeClosed",
        scope="scope-a",
        registered_rule=registered,
        conclusion=ProofConclusion.create(
            proposition_id=proposition.id,
            scope="scope-a",
        ),
    )
    obligation = ProofObligation.create(
        proposition_id=proposition.id,
        kind=ObligationKind.PROJECTION,
        scope="scope-a",
    )
    ledger = EvidenceLedger()
    ledger.add(unknown)
    ledger.add(proof)

    ledger.add_typed_discharge(
        UnknownDischarge(unknown.id, proof.id, "scope-a"),
        obligation,
        ProofRuleRegistry((ProofRuleDefinition(registered, "EscapeClosed"),)),
    )

    assert ledger.unresolved_unknowns("scope-a") == ()


def test_typed_discharge_keeps_legacy_unknown_incomplete() -> None:
    legacy = UnknownFact.create(
        schema_version="1",
        producer=ProducerId("rule-test", "1"),
        kind=UnknownKind.UNKNOWN_ESCAPE,
        reason="legacy escape gap",
        subject=None,
        scope="scope-a",
    )
    proof = _proof()
    proposition = PropositionId.from_parts("escape", ("scope-a",))
    obligation = ProofObligation.create(
        proposition_id=proposition,
        kind=ObligationKind.PROJECTION,
        scope="scope-a",
    )
    ledger = EvidenceLedger()
    ledger.add(legacy)
    ledger.add(proof)

    try:
        ledger.add_typed_discharge(
            UnknownDischarge(legacy.id, proof.id, "scope-a"),
            obligation,
            ProofRuleRegistry(definitions=()),
        )
    except LedgerError as error:
        assert "typed Unknown" in str(error)
    else:
        raise AssertionError("legacy Unknown must not be discharged by typed path")
