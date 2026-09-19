from __future__ import annotations

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
    ObligationInventory,
    ProjectionLedger,
    StaticCertificate,
    digest_event_universe,
    digest_obligation_inventory,
    digest_projection_ledger,
    digest_unknown_ids,
)


HASH = "a" * 64
REVISION = "b" * 40


def _empty_ledgers() -> tuple[
    EventUniverseLedger,
    ObligationInventory,
    ProjectionLedger,
]:
    event_universe = EventUniverseLedger(
        stage="static.events",
        input_event_ids=(),
        entries=(),
        completeness=CompletenessState(
            CompletenessStatus.COMPLETE,
            "static.events",
        ),
    )
    obligations = ObligationInventory(
        scope="static.obligations",
        obligations=(),
        completeness=CompletenessState(
            CompletenessStatus.COMPLETE,
            "static.obligations",
        ),
    )
    projection = ProjectionLedger(
        stage="static.projection",
        input_relation_ids=(),
        entries=(),
        preservation_rule=None,
        completeness=CompletenessState(
            CompletenessStatus.COMPLETE,
            "static.projection",
        ),
    )
    return event_universe, obligations, projection


def _binding() -> CertificateBinding:
    return CertificateBinding(
        binary_closure=BinaryClosureId.from_parts(
            HASH,
            (("executable", HASH),),
            "x86_64:elf64:le",
        ),
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision=REVISION,
        scope="static.test",
    )


def _completeness() -> CertificateCompleteness:
    return CertificateCompleteness(
        event_universe_sha256="1" * 64,
        obligation_sha256="2" * 64,
        unknown_sha256="3" * 64,
        projection_sha256="4" * 64,
    )


def test_completeness_digests_are_stable_and_include_scope() -> None:
    events, obligations, projection = _empty_ledgers()

    assert digest_event_universe(events) == digest_event_universe(events)
    assert digest_obligation_inventory(obligations) == digest_obligation_inventory(obligations)
    assert digest_projection_ledger(projection) == digest_projection_ledger(projection)
    assert digest_unknown_ids("static.test", ()) != digest_unknown_ids("static.other", ())


def test_completeness_digest_changes_when_ledger_status_changes() -> None:
    events, _, _ = _empty_ledgers()
    incomplete = EventUniverseLedger(
        stage=events.stage,
        input_event_ids=(),
        entries=(),
        completeness=CompletenessState(
            CompletenessStatus.INCOMPLETE,
            events.stage,
            reason="fixture is missing an input event",
        ),
    )

    assert digest_event_universe(events) != digest_event_universe(incomplete)


def test_v2_certificate_requires_all_completeness_digests() -> None:
    with pytest.raises(CertificateError, match="requires completeness"):
        StaticCertificate(
            schema_version="static-certificate-v2",
            verdict=CertificateVerdict.UNKNOWN,
            binding=_binding(),
        )


def test_v1_certificate_cannot_smuggle_v2_completeness() -> None:
    with pytest.raises(CertificateError, match="requires static-certificate-v2"):
        StaticCertificate(
            schema_version="static-certificate-1",
            verdict=CertificateVerdict.UNKNOWN,
            binding=_binding(),
            completeness=_completeness(),
        )


def test_v2_certificate_accepts_typed_completeness_binding() -> None:
    certificate = StaticCertificate(
        schema_version="static-certificate-v2",
        verdict=CertificateVerdict.UNKNOWN,
        binding=_binding(),
        completeness=_completeness(),
    )

    assert certificate.completeness == _completeness()


def test_completeness_rejects_non_digest_text() -> None:
    with pytest.raises(CertificateError, match="digest"):
        CertificateCompleteness(
            event_universe_sha256="missing",
            obligation_sha256="2" * 64,
            unknown_sha256="3" * 64,
            projection_sha256="4" * 64,
        )
