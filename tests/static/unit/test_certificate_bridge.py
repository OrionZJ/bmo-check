from __future__ import annotations

import pytest

from bmo_check_core import (
    CertificateVerdict,
    EvidenceLedger,
    ModuleId,
    ObservedFact,
    ProducerId,
    TraceId,
    ThreadInstanceId,
)
from bmo_check_static.analysis.evidence import StaticMemoryEventEvidence
from bmo_check_static.analysis.shared_state_evidence import StaticSharedStateEvidence
from bmo_check_static.model import (
    ElfMetadata,
    ExecutionScope,
    MemoryEventReport,
    ModuleFingerprint,
    ModuleRole,
    ProgramManifest,
    ProgramRecoveryReport,
    SharedStateReport,
    ThreadDiscoveryReport,
    Verdict,
)
from bmo_check_static.proof import (
    CertificateBridgeError,
    StaticPortabilityEvidence,
    binding_from_manifest,
    build_static_certificate_with_evidence,
    verify_portability,
)
from bmo_check_static.slicing import build_shared_memory_slice_with_evidence
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


def test_bridge_replays_legacy_safe_with_typed_slice() -> None:
    scope = "static.test"
    binding = binding_from_manifest(_manifest(), scope=scope)
    result = build_static_certificate_with_evidence(
        _empty_slice(scope),
        _portability(scope),
        binding,
    )

    assert result.certificate.verdict == CertificateVerdict.SAFE
    assert result.verification.proof_closure == ()


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
