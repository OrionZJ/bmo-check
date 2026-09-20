from __future__ import annotations

from dataclasses import replace

import pytest

from bmo_check_core import (
    BinaryClosureId,
    CertificateBinding,
    CertificateCompleteness,
    CertificateError,
    CertificateVerdict,
    CompletenessState,
    CompletenessStatus,
    EventUniverseLedger,
    EvidenceLedger,
    ObligationInventory,
    ProducerId,
    ProofFact,
    ProjectionLedger,
    StaticCertificate,
    UnknownDischarge,
    UnknownFact,
    UnknownKind,
    digest_event_universe,
    digest_obligation_inventory,
    digest_projection_ledger,
    digest_unknown_ids,
    verify_static_certificate_v2,
)


def _binding() -> CertificateBinding:
    executable = "a" * 64
    closure = BinaryClosureId.from_parts(
        executable,
        (("executable", executable),),
        "x86_64",
    )
    return CertificateBinding(
        binary_closure=closure,
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision="b" * 40,
        scope="static.test",
    )


def _sidecars() -> tuple[
    EventUniverseLedger,
    ObligationInventory,
    ProjectionLedger,
    ObligationInventory,
]:
    scope = "static.test"
    complete = CompletenessState(CompletenessStatus.COMPLETE, scope)
    events = EventUniverseLedger(
        stage=scope,
        input_event_ids=(),
        entries=(),
        completeness=complete,
    )
    obligations = ObligationInventory(scope, (), complete)
    projection = ProjectionLedger(
        stage=scope,
        input_relation_ids=(),
        entries=(),
        preservation_rule=None,
        completeness=complete,
    )
    projection_obligations = ObligationInventory(scope, (), complete)
    return events, obligations, projection, projection_obligations


def _certificate(
    events: EventUniverseLedger,
    obligations: ObligationInventory,
    projection: ProjectionLedger,
    projection_obligations: ObligationInventory,
) -> StaticCertificate:
    binding = _binding()
    return StaticCertificate(
        schema_version="static-certificate-v2",
        verdict=CertificateVerdict.SAFE,
        binding=binding,
        completeness=CertificateCompleteness(
            event_universe_sha256=digest_event_universe(events),
            obligation_sha256=digest_obligation_inventory(obligations),
            unknown_sha256=digest_unknown_ids(binding.scope, ()),
            projection_sha256=digest_projection_ledger(projection),
        ),
    )


def test_static_v2_replays_complete_empty_subject() -> None:
    events, obligations, projection, projection_obligations = _sidecars()
    result = verify_static_certificate_v2(
        _certificate(events, obligations, projection, projection_obligations),
        EvidenceLedger(),
        event_universe=events,
        obligation_inventory=obligations,
        projection_ledger=projection,
        projection_obligations=projection_obligations,
        expected_binding=_binding(),
    )

    assert result.certificate.verdict is CertificateVerdict.SAFE
    assert result.proof_closure == ()


def test_static_v2_rejects_digest_mutation() -> None:
    events, obligations, projection, projection_obligations = _sidecars()
    certificate = _certificate(events, obligations, projection, projection_obligations)
    changed = replace(
        certificate,
        completeness=replace(
            certificate.completeness,
            projection_sha256="f" * 64,
        ),
    )

    with pytest.raises(CertificateError, match="projection digest"):
        verify_static_certificate_v2(
            changed,
            EvidenceLedger(),
            event_universe=events,
            obligation_inventory=obligations,
            projection_ledger=projection,
            projection_obligations=projection_obligations,
        )


def test_static_v2_rejects_incomplete_determinate_universe() -> None:
    events, obligations, projection, projection_obligations = _sidecars()
    incomplete = replace(
        events,
        completeness=CompletenessState(
            CompletenessStatus.INCOMPLETE,
            events.stage,
            reason="missing event input",
        ),
    )
    certificate = _certificate(incomplete, obligations, projection, projection_obligations)

    with pytest.raises(CertificateError, match="incomplete event universe"):
        verify_static_certificate_v2(
            certificate,
            EvidenceLedger(),
            event_universe=incomplete,
            obligation_inventory=obligations,
            projection_ledger=projection,
            projection_obligations=projection_obligations,
        )


def test_static_v2_rejects_unrelated_unknown_discharge() -> None:
    events, obligations, projection, projection_obligations = _sidecars()
    ledger = EvidenceLedger()
    unknown = UnknownFact.create(
        schema_version="1",
        producer=ProducerId("test", "v2"),
        kind=UnknownKind.UNKNOWN_ESCAPE,
        reason="fixture unknown",
        subject=None,
        scope="static.test",
    )
    proof = ProofFact.create(
        schema_version="1",
        producer=ProducerId("test", "v2"),
        subject=None,
        rule="unrelated",
        scope="static.test",
    )
    ledger.add(unknown)
    ledger.add(proof)
    ledger.add_discharge(UnknownDischarge(unknown.id, proof.id, "static.test"))
    certificate = _certificate(events, obligations, projection, projection_obligations)

    with pytest.raises(CertificateError, match="does not match an obligation"):
        verify_static_certificate_v2(
            certificate,
            ledger,
            event_universe=events,
            obligation_inventory=obligations,
            projection_ledger=projection,
            projection_obligations=projection_obligations,
        )
