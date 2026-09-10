from __future__ import annotations

import pytest

from bmo_check_core import (
    CertificateVerdict,
    DiagnosticHint,
    DynamicDiagnosticSnapshot,
    EvidenceSnapshot,
    ModuleId,
    ObservedFact,
    ProducerId,
    ProofFact,
    SnapshotError,
    StaticDiagnosticSnapshot,
    ThreadInstanceId,
    TraceId,
    UnknownFact,
    UnknownKind,
)


HASH = "a" * 64


def _trace() -> TraceId:
    return TraceId.from_parts(
        "trace-v1",
        HASH,
        (ModuleId.from_parts(HASH, "executable"),),
        ("synthetic",),
        HASH,
    )


def _unknown(scope: str = "static.test") -> UnknownFact:
    return UnknownFact.create(
        schema_version="unknown-v1",
        producer=ProducerId("test", "1"),
        kind=UnknownKind.UNKNOWN_ROOT_CAUSE,
        reason="synthetic missing fact",
        subject=None,
        scope=scope,
    )


def _observed(trace: TraceId) -> ObservedFact:
    return ObservedFact.create(
        schema_version="observed-v1",
        producer=ProducerId("test", "1"),
        trace_id=trace,
        execution_id=ThreadInstanceId.from_parts(trace, 1),
        subject=None,
        observation_kind="memory-range",
    )


def test_static_snapshot_keeps_unknown_and_returns_independent_ledger() -> None:
    unknown = _unknown()
    snapshot = StaticDiagnosticSnapshot(
        schema_version="static-diagnostic-v1",
        scope="static.test",
        verdict=CertificateVerdict.UNKNOWN,
        evidence=EvidenceSnapshot((unknown,)),
    )

    first = snapshot.ledger()
    first.add(
        UnknownFact.create(
            schema_version="unknown-v1",
            producer=ProducerId("test", "2"),
            kind=UnknownKind.RESOURCE_LIMIT,
            reason="synthetic budget",
            subject=None,
            scope="static.test",
        )
    )
    assert snapshot.unknown_ids == (unknown.id,)
    assert len(snapshot.ledger().nodes()) == 1


def test_static_snapshot_rejects_observed_fact_and_hint() -> None:
    trace = _trace()
    observed = _observed(trace)
    with pytest.raises(SnapshotError, match="observations or hints"):
        StaticDiagnosticSnapshot(
            schema_version="static-diagnostic-v1",
            scope="static.test",
            verdict=CertificateVerdict.UNKNOWN,
            evidence=EvidenceSnapshot((observed,)),
        )


def test_dynamic_snapshot_requires_same_trace_and_rejects_static_proof() -> None:
    trace = _trace()
    observed = _observed(trace)
    dynamic = DynamicDiagnosticSnapshot(
        schema_version="dynamic-diagnostic-v1",
        trace_id=trace,
        scope="trace.test",
        complete=True,
        evidence=EvidenceSnapshot((observed,)),
    )
    assert dynamic.observed_ids == (observed.id,)

    proof = ProofFact.create(
        schema_version="proof-v1",
        producer=ProducerId("test", "1"),
        subject=None,
        rule="synthetic",
        scope="trace.test",
    )
    with pytest.raises(SnapshotError, match="static proof or hint"):
        DynamicDiagnosticSnapshot(
            schema_version="dynamic-diagnostic-v1",
            trace_id=trace,
            scope="trace.test",
            complete=True,
            evidence=EvidenceSnapshot((proof,)),
        )


def test_dynamic_snapshot_rejects_foreign_trace() -> None:
    with pytest.raises(SnapshotError, match="another trace"):
        DynamicDiagnosticSnapshot(
            schema_version="dynamic-diagnostic-v1",
            trace_id=_trace(),
            scope="trace.test",
            complete=True,
            evidence=EvidenceSnapshot((_observed(TraceId.from_parts(
                "trace-v1",
                "b" * 64,
                (ModuleId.from_parts("b" * 64, "executable"),),
                ("other",),
                "b" * 64,
            )),)),
        )
