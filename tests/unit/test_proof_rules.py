from __future__ import annotations

from bmo_check_core import (
    EvidenceLedger,
    ProofConclusion,
    ProofFact,
    ProofRuleDefinition,
    ProofRuleRegistry,
    ProofRuleReplayStatus,
    ProducerId,
    PropositionId,
    RegisteredProofRule,
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
