from __future__ import annotations

from dataclasses import replace

import pytest

from bmo_check_core import (
    CompletenessState,
    CompletenessStatus,
    CertificateVerdict,
    EvidenceLedger,
    ModuleId,
    ObservedFact,
    ProjectionLedger,
    ProducerId,
    TraceId,
    ThreadInstanceId,
)
from bmo_check_static.analysis.evidence import StaticMemoryEventEvidence
from bmo_check_static.analysis.shared_state_evidence import StaticSharedStateEvidence
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    ElfMetadata,
    ExecutionScope,
    EventKind,
    MemoryEvent,
    MemoryEventReport,
    ModuleFingerprint,
    ModuleRole,
    ProofObject,
    ProofReason,
    ProgramManifest,
    ProgramOrderEdge,
    ProgramRecoveryReport,
    PruningCoverage,
    SharedStateReport,
    SharedMemorySlice,
    ThreadDiscoveryReport,
    UnknownFact,
    UnknownKind,
    Verdict,
)
from bmo_check_static.proof import (
    CertificateBridgeError,
    StaticPortabilityEvidence,
    binding_from_manifest,
    build_static_certificate_from_report,
    build_static_certificate_with_evidence,
    verify_portability,
)
from bmo_check_static.adapters import (
    DiagnosticSnapshotAdapterError,
    static_snapshot_from_certificate,
)
from bmo_check_static.slicing import (
    build_shared_memory_slice_with_evidence,
    restrict_to_application_scope,
)
from bmo_check_static.threading.evidence import StaticThreadEvidence


HASH = "a" * 64
REVISION = "b" * 40


def _manifest() -> ProgramManifest:
    module = ModuleFingerprint(
        path="/bin/litmus",
        role=ModuleRole.EXECUTABLE,
        size=4096,
        sha256=HASH,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    return ProgramManifest(
        executable=module,
        execution=ExecutionScope(thread_count_min=1, thread_count_max=1),
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision=REVISION,
        closure_complete=True,
    )


def _empty_slice(scope: str):
    memory = StaticMemoryEventEvidence(
        report=MemoryEventReport(
            module_path="/bin/litmus",
            module_sha256=HASH,
        ),
        ledger=EvidenceLedger(),
    )
    shared = StaticSharedStateEvidence(
        report=SharedStateReport(),
        ledger=EvidenceLedger(),
    )
    threads = StaticThreadEvidence(
        report=ThreadDiscoveryReport(),
        ledger=EvidenceLedger(),
    )
    return build_shared_memory_slice_with_evidence(
        memory,
        shared,
        threads,
        scope=scope,
    )


def _portability(scope: str):
    report = ProgramRecoveryReport(manifest=_manifest())
    # Portability checker only needs the final slice for this no-conflict case.
    from bmo_check_static.model import (
        MemoryEventReport,
        ProgramSliceReport,
        SharedMemorySlice,
        PruningCoverage,
    )

    final = SharedMemorySlice(coverage=PruningCoverage(total_events=0))
    legacy = verify_portability(
        ProgramSliceReport(
            recovery=report,
            memory_events=MemoryEventReport(
                module_path="/bin/litmus",
                module_sha256=HASH,
            ),
            shared_state=SharedStateReport(),
            shared_slice=final,
        )
    )
    assert legacy.verdict == Verdict.SAFE
    return StaticPortabilityEvidence(legacy, EvidenceLedger())


def _empty_report(*, dbt_revision: str | None = REVISION):
    from bmo_check_static.model import (
        MemoryEventReport,
        PruningCoverage,
        ProgramSliceReport,
        SharedMemorySlice,
    )

    manifest = _manifest().model_copy(update={"dbt_revision": dbt_revision})
    return ProgramSliceReport(
        recovery=ProgramRecoveryReport(manifest=manifest),
        memory_events=MemoryEventReport(
            module_path="/bin/litmus",
            module_sha256=HASH,
        ),
        shared_state=SharedStateReport(),
        shared_slice=SharedMemorySlice(
            coverage=PruningCoverage(total_events=0),
        ),
    )


def test_bridge_rejects_legacy_safe_with_typed_slice() -> None:
    scope = "static.test"
    binding = binding_from_manifest(_manifest(), scope=scope)
    with pytest.raises(CertificateBridgeError, match="explain-only"):
        build_static_certificate_with_evidence(
            _empty_slice(scope),
            _portability(scope),
            binding,
        )


def test_bridge_rejects_determinate_incomplete_projection() -> None:
    scope = "static.test"
    incomplete = ProjectionLedger(
        stage=scope,
        input_relation_ids=(),
        entries=(),
        preservation_rule=None,
        completeness=CompletenessState(
            CompletenessStatus.INCOMPLETE,
            scope,
            reason="fixture omitted relation universe",
        ),
    )
    slice_evidence = replace(_empty_slice(scope), projection_ledger=incomplete)

    with pytest.raises(CertificateBridgeError, match="relation universe is incomplete"):
        build_static_certificate_with_evidence(
            slice_evidence,
            _portability(scope),
            binding_from_manifest(_manifest(), scope=scope),
        )


def test_report_bridge_rejects_a_legacy_static_result() -> None:
    scope = "static.test"
    report = _empty_report()
    legacy = verify_portability(report)

    with pytest.raises(CertificateBridgeError, match="explain-only"):
        build_static_certificate_from_report(
            report,
            legacy,
            binding_from_manifest(report.recovery.manifest, scope=scope),
        )


def test_report_bridge_preserves_relevant_unknowns() -> None:
    unknown = UnknownFact(
        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
        reason="opaque helper has no static effect summary",
        impact="the helper may communicate through shared memory",
        module="/bin/litmus",
        pc=0x1000,
    )
    report = _empty_report().model_copy(
        update={
            "unknowns": (unknown,),
            "memory_events": _empty_report().memory_events.model_copy(
                update={"unknowns": (unknown,)}
            ),
        }
    )
    legacy = verify_portability(report)
    scope = "static.test"

    result = build_static_certificate_from_report(
        report,
        legacy,
        binding_from_manifest(report.recovery.manifest, scope=scope),
    )

    assert legacy.verdict == Verdict.UNKNOWN
    assert result.certificate.verdict == CertificateVerdict.UNKNOWN
    assert len(result.certificate.relevant_unknowns) == 1
    assert len(result.ledger.unresolved_unknowns(scope)) == 1
    snapshot = static_snapshot_from_certificate(result)
    assert snapshot.schema_version == "static-diagnostic-v2"
    assert snapshot.blocking_unknown_ids == result.certificate.relevant_unknowns


def test_report_bridge_rejects_legacy_safe_even_after_unknown_discharge() -> None:
    event = MemoryEvent(
        id="event-1",
        module="/bin/litmus",
        module_sha256=HASH,
        pc=0x1000,
        kind=EventKind.STORE,
        address=AbstractAddress(
            kind=AddressKind.STACK,
            base="frame",
            offset=0,
        ),
        size=4,
        thread_role="main",
    )
    proof = ProofObject(
        id="proof-sequential",
        reason=ProofReason.SEQUENTIAL_BEFORE_CREATE,
        event_ids=(event.id,),
        supporting_facts=("main executes this store before pthread_create",),
    )
    unknown = UnknownFact(
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="the loop bound is unavailable",
        impact="the event write set may overlap",
        module="/bin/litmus",
        pc=event.pc,
        details={"event_id": event.id},
    )
    report = _empty_report().model_copy(
        update={
            "memory_events": MemoryEventReport(
                module_path="/bin/litmus",
                module_sha256=HASH,
                events=(event,),
                unknowns=(unknown,),
            ),
            "shared_state": SharedStateReport(
                removed_event_ids=(event.id,),
                proofs=(proof,),
                unknowns=(unknown,),
            ),
            "shared_slice": SharedMemorySlice(
                events=(event,),
                proof_objects=(proof,),
                coverage=PruningCoverage(total_events=1),
                unknowns=(unknown,),
            ),
        }
    )
    legacy = verify_portability(report)
    scope = "static.test"

    with pytest.raises(CertificateBridgeError, match="explain-only"):
        build_static_certificate_from_report(
            report,
            legacy,
            binding_from_manifest(report.recovery.manifest, scope=scope),
        )


def test_application_projection_records_removed_event_decision() -> None:
    event = MemoryEvent(
        id="runtime-effect",
        module="/lib/runtime.so",
        module_sha256="c" * 64,
        pc=0x3000,
        kind=EventKind.OPAQUE_CALL,
        address=AbstractAddress(
            kind=AddressKind.GLOBAL,
            base="runtime:private",
            provenance={"runtime_internal": True},
        ),
        thread_role="main",
        provenance={"runtime_internal": True},
    )
    scoped = restrict_to_application_scope(
        SharedMemorySlice(
            events=(event,),
            coverage=PruningCoverage(total_events=1, remaining_shared_events=1),
        ),
        executable_sha256=HASH,
    )
    unknown = UnknownFact(
        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
        reason="unmodeled runtime effect remains outside the application proof",
        impact="the full-process scope is not closed",
        module="/bin/litmus",
        pc=0x4000,
    )
    report = _empty_report().model_copy(
        update={
            "memory_events": MemoryEventReport(
                module_path="/bin/litmus",
                module_sha256=HASH,
                events=(event,),
            ),
            "shared_state": SharedStateReport(),
            "shared_slice": scoped,
            "unknowns": (unknown,),
        }
    )
    legacy = verify_portability(report, analysis_options={"scope": "application"})
    assert legacy.verdict == Verdict.UNKNOWN

    result = build_static_certificate_from_report(
        report,
        legacy,
        binding_from_manifest(report.recovery.manifest, scope="application"),
    )

    assert len(result.certificate.removal_decisions) == 1
    assert result.certificate.removal_decisions[0].scope == "application"


def test_bridge_exposes_incomplete_projection_relations() -> None:
    runtime = MemoryEvent(
        id="runtime-effect",
        module="/lib/runtime.so",
        module_sha256="c" * 64,
        pc=0x3000,
        kind=EventKind.OPAQUE_CALL,
        address=AbstractAddress(
            kind=AddressKind.GLOBAL,
            base="runtime:private",
            provenance={"runtime_internal": True},
        ),
        thread_role="worker",
        provenance={"runtime_internal": True},
    )
    application = MemoryEvent(
        id="application-load",
        module="/bin/litmus",
        module_sha256=HASH,
        pc=0x3100,
        kind=EventKind.LOAD,
        address=AbstractAddress(
            kind=AddressKind.GLOBAL,
            base="application:shared",
            offset=0,
        ),
        size=4,
        thread_role="main",
    )
    source = SharedMemorySlice(
        events=(runtime, application),
        program_order=(
            ProgramOrderEdge(
                source_event=runtime.id,
                target_event=application.id,
                thread_role="worker",
                evidence="synthetic edge",
            ),
        ),
        coverage=PruningCoverage(total_events=2, remaining_shared_events=2),
    )
    unknown = UnknownFact(
        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
        reason="an unrelated effect remains unresolved",
        impact="the full process is not closed",
        module="/bin/litmus",
        pc=0x4000,
    )
    base = _empty_report().model_copy(
        update={
            "recovery": _empty_report().recovery.model_copy(
                update={"thread_roles": ThreadDiscoveryReport()}
            ),
            "memory_events": MemoryEventReport(
                module_path="/bin/litmus",
                module_sha256=HASH,
                events=(runtime, application),
                program_order=source.program_order,
            ),
            "shared_state": SharedStateReport(
                kept_event_ids=(runtime.id, application.id),
            ),
            "shared_slice": restrict_to_application_scope(
                source,
                executable_sha256=HASH,
            ),
            "unknowns": (unknown,),
        }
    )
    legacy = verify_portability(base, analysis_options={"scope": "application"})

    result = build_static_certificate_from_report(
        base,
        legacy,
        binding_from_manifest(base.recovery.manifest, scope="application"),
    )

    assert result.projection_ledger is not None
    assert result.projection_ledger.completeness.status is CompletenessStatus.INCOMPLETE
    assert result.projection_ledger.missing_relation_ids


def test_bridge_rejects_dynamic_observation() -> None:
    scope = "static.test"
    slice_evidence = _empty_slice(scope)
    observed = ObservedFact.create(
        schema_version="trace-1",
        producer=ProducerId("test", "1"),
        trace_id=TraceId.from_parts(
            "fmt",
            HASH,
            (ModuleId.from_parts(HASH, "executable"),),
            ("synthetic",),
            HASH,
        ),
        execution_id=ThreadInstanceId.from_parts(
            TraceId.from_parts(
                "fmt",
                HASH,
                (ModuleId.from_parts(HASH, "executable"),),
                ("synthetic",),
                HASH,
            ),
            1,
        ),
        subject=None,
        observation_kind="memory",
    )
    ledger = EvidenceLedger()
    ledger.add(observed)
    portability = _portability(scope)
    portability = StaticPortabilityEvidence(portability.certificate, ledger)

    with pytest.raises(CertificateBridgeError, match="observations or hints"):
        build_static_certificate_with_evidence(
            slice_evidence,
            portability,
            binding_from_manifest(_manifest(), scope=scope),
        )


def test_legacy_certificate_cannot_reach_snapshot_replay() -> None:
    scope = "static.test"
    with pytest.raises(CertificateBridgeError, match="explain-only"):
        build_static_certificate_with_evidence(
            _empty_slice(scope),
            _portability(scope),
            binding_from_manifest(_manifest(), scope=scope),
        )
