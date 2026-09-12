from __future__ import annotations

import pytest

from bmo_check_core import EvidenceId, ProducerId, UnknownFact, UnknownKind
from bmo_check_diagnostics import (
    ClassificationError,
    DiagnosticRootCause,
    ROOT_CAUSE_REGISTRY,
    classify_unknown,
    validate_root_cause_registry,
)
from bmo_check_diagnostics.correlation import (
    CorrelationKey,
    CorrelationRecord,
    CorrelationStatus,
)


def _unknown(kind: UnknownKind, reason: str = "synthetic gap", context: tuple[str, ...] = ()) -> UnknownFact:
    return UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("static-test", "1"),
        kind=kind,
        reason=reason,
        subject=None,
        scope="static.test",
        supporting_context=context,
    )


def test_registry_covers_every_published_root_cause() -> None:
    validate_root_cause_registry()
    assert set(ROOT_CAUSE_REGISTRY) == set(DiagnosticRootCause)
    assert all(item.description for item in ROOT_CAUSE_REGISTRY.values())


def test_affine_context_is_classified_without_dynamic_values() -> None:
    result = classify_unknown(
        _unknown(
            UnknownKind.UNKNOWN_AFFINE_BOUNDS,
            reason="upper bound missing",
            context=("static induction variable analysis",),
        )
    )

    assert result.root_cause == DiagnosticRootCause.MISSING_INDUCTION_VARIABLE
    assert result.confidence > 0
    assert "UnknownAffineBounds" in result.rationale


def test_unknown_kind_mapping_is_conservative_and_typed() -> None:
    assert classify_unknown(
        _unknown(UnknownKind.UNRESOLVED_INDIRECT_CALL)
    ).root_cause == DiagnosticRootCause.UNRESOLVED_INDIRECT
    assert classify_unknown(
        _unknown(UnknownKind.UNKNOWN_MEMORY_EFFECT)
    ).root_cause == DiagnosticRootCause.OPAQUE_CALL_BOUNDARY
    assert classify_unknown(
        _unknown(UnknownKind.UNKNOWN_ESCAPE)
    ).root_cause == DiagnosticRootCause.MISSING_ALIAS_PRECISION
    assert classify_unknown(
        _unknown(UnknownKind.UNKNOWN_ROOT_CAUSE)
    ).root_cause == DiagnosticRootCause.UNKNOWN_ROOT_CAUSE


def test_correlation_context_never_turns_observation_into_proof() -> None:
    unknown = _unknown(UnknownKind.UNKNOWN_ROOT_CAUSE)
    correlation = CorrelationRecord(
        unknown_id=unknown.id,
        observed_ids=(),
        status=CorrelationStatus.UNMATCHED,
        key=CorrelationKey.SUBJECT,
        reason="no observed fact has the same stable subject",
    )

    result = classify_unknown(unknown, correlation=correlation)

    assert result.root_cause == DiagnosticRootCause.NOT_EXECUTED_IN_OBSERVED_TRACE
    assert result.confidence == 0


def test_correlation_for_another_unknown_is_rejected() -> None:
    first = _unknown(UnknownKind.UNKNOWN_ROOT_CAUSE)
    second = _unknown(UnknownKind.UNKNOWN_MEMORY_EFFECT)
    correlation = CorrelationRecord(
        unknown_id=first.id,
        observed_ids=(),
        status=CorrelationStatus.UNMATCHED,
        key=CorrelationKey.NONE,
        reason="no stable subject",
    )

    with pytest.raises(ClassificationError, match="does not reference"):
        classify_unknown(second, correlation=correlation)
