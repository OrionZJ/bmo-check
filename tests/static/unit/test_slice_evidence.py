from __future__ import annotations

import pytest

from bmo_check_core import EvidenceLedger, ProofFact
from bmo_check_static.analysis.evidence import (
    MemoryEventIdentityLink,
    StaticMemoryEventEvidence,
    memory_event_identity,
)
from bmo_check_static.binary.elf import inspect_elf
from bmo_check_static.model import (
    AddressKind,
    EventKind,
    MemoryEvent,
    MemoryEventReport,
    ModuleRole,
    ProofObject,
    ProofReason,
    SharedStateReport,
    ThreadDiscoveryReport,
    AbstractAddress,
)
from bmo_check_static.slicing import (
    SliceEvidenceError,
    StaticSliceEvidence,
    build_shared_memory_slice_with_evidence,
)
from bmo_check_static.analysis.shared_state_evidence import StaticSharedStateEvidence
from bmo_check_static.threading.evidence import StaticThreadEvidence


def _inputs(elf_fixture):
    module = inspect_elf(elf_fixture.executable, ModuleRole.EXECUTABLE)
    event = MemoryEvent(
        id="event-1",
        module=module.path,
        module_sha256=module.sha256,
        pc=0x1000,
        kind=EventKind.LOAD,
        address=AbstractAddress(
            kind=AddressKind.GLOBAL,
            base="global:x",
            offset=0,
        ),
        size=4,
        thread_role="main",
    )
    memory = StaticMemoryEventEvidence(
        report=MemoryEventReport(
            module_path=module.path,
            module_sha256=module.sha256,
            events=(event,),
        ),
        ledger=EvidenceLedger(),
        event_links=(
            MemoryEventIdentityLink(
                event.id,
                memory_event_identity(module, event),
            ),
        ),
    )
    proof = ProofObject(
        id="proof:event-1",
        reason=ProofReason.SINGLE_MAIN_ROLE,
        event_ids=(event.id,),
        supporting_facts=("synthetic closed main-only object",),
    )
    shared = StaticSharedStateEvidence(
        report=SharedStateReport(
            kept_event_ids=(),
            removed_event_ids=(event.id,),
            proofs=(proof,),
        ),
        ledger=EvidenceLedger(),
    )
    threads = StaticThreadEvidence(
        report=ThreadDiscoveryReport(),
        ledger=EvidenceLedger(),
    )
    return memory, shared, threads


def test_slice_evidence_converts_each_removed_event_to_a_decision(elf_fixture) -> None:
    memory, shared, threads = _inputs(elf_fixture)

    snapshot = build_shared_memory_slice_with_evidence(memory, shared, threads)

    assert isinstance(snapshot, StaticSliceEvidence)
    assert snapshot.report.events == ()
    assert len(snapshot.removal_decisions) == 1
    assert len(snapshot.proof_links) == 1
    proof = snapshot.ledger.get(snapshot.proof_links[0].canonical_id)
    assert isinstance(proof, ProofFact)
    assert proof.covered_events == (memory.event_links[0].canonical_id,)


def test_slice_evidence_refuses_unmapped_removed_event(elf_fixture) -> None:
    memory, shared, threads = _inputs(elf_fixture)
    memory = StaticMemoryEventEvidence(
        report=memory.report,
        ledger=memory.ledger,
        event_links=(),
    )

    with pytest.raises(SliceEvidenceError, match="unmapped event"):
        build_shared_memory_slice_with_evidence(memory, shared, threads)
