from __future__ import annotations

import ast
from pathlib import Path

import pytest

from bmo_check_core.evidence import ProofFact as CanonicalProofFact
from bmo_check_core.evidence import UnknownFact as CanonicalUnknownFact
from bmo_check_core.evidence import UnknownKind as CanonicalUnknownKind
from bmo_check_static.adapters import StaticAdapterError, adapt_static_report
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    ElfMetadata,
    EventKind,
    ExecutionScope,
    MemoryEvent,
    MemoryEventReport,
    ModuleFingerprint,
    ModuleRole,
    PruningCoverage,
    ProgramManifest,
    ProgramRecoveryReport,
    ProgramSliceReport,
    ProofObject,
    ProofReason,
    SharedMemorySlice,
    SharedStateReport,
    UnknownFact,
    UnknownKind,
)
from bmo_check_static.proof import verify_portability


HASH = "a" * 64


def _module() -> ModuleFingerprint:
    return ModuleFingerprint(
        path="/bin/adapter-fixture",
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


def _report(
    events: tuple[MemoryEvent, ...],
    unknowns: tuple[UnknownFact, ...],
    proofs: tuple[ProofObject, ...],
) -> ProgramSliceReport:
    module = _module()
    manifest = ProgramManifest(
        executable=module,
        execution=ExecutionScope(argv=(module.path,), thread_count_min=2),
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision="b" * 40,
        closure_complete=True,
    )
    return ProgramSliceReport(
        recovery=ProgramRecoveryReport(manifest=manifest),
        memory_events=MemoryEventReport(
            module_path=module.path,
            module_sha256=module.sha256,
            events=events,
            unknowns=unknowns,
        ),
        shared_state=SharedStateReport(
            removed_event_ids=tuple(
                event_id for proof in proofs for event_id in proof.event_ids
            ),
            proofs=proofs,
            unknowns=unknowns,
        ),
        shared_slice=SharedMemorySlice(
            events=events,
            proof_objects=proofs,
            coverage=PruningCoverage(
                total_events=len(events),
                remaining_shared_events=len(events),
            ),
            unknowns=unknowns,
        ),
        unknowns=unknowns,
    )


def _event(event_id: str, pc: int, role: str) -> MemoryEvent:
    return MemoryEvent(
        id=event_id,
        module="/bin/adapter-fixture",
        module_sha256=HASH,
        pc=pc,
        function="worker",
        kind=EventKind.STORE,
        address=AbstractAddress(
            kind=AddressKind.GLOBAL,
            base="shared",
            offset=0,
        ),
        size=4,
        thread_role=role,
    )


def _unknown(event_id: str) -> UnknownFact:
    return UnknownFact(
        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
        reason="loop upper bound is not closed",
        impact="the worker write set may overlap",
        module="/bin/adapter-fixture",
        pc=0x1010,
        function="worker",
        details={"event_id": event_id, "candidate": [0, 4]},
    )


def _proof(event_id: str) -> ProofObject:
    return ProofObject(
        id="proof:adapter-fixture",
        reason=ProofReason.DISJOINT_AFFINE,
        event_ids=(event_id,),
        supporting_facts=("legacy affine partition",),
    )


def test_adapter_emits_only_static_evidence_and_preserves_links() -> None:
    event = _event("event-1", 0x1010, "worker")
    report = _report((event,), (_unknown(event.id),), (_proof(event.id),))

    snapshot = adapt_static_report(report, scope="fixture")

    assert len(snapshot.event_ids) == 1
    assert len(snapshot.proof_ids) == 1
    assert len(snapshot.unknown_ids) == 1
    assert {
        link.origin for link in snapshot.event_links if link.legacy_id == "event-1"
    } == {"memory_events", "shared_slice"}
    assert snapshot.ledger.unresolved_unknowns("fixture")
    assert all(
        isinstance(node, (CanonicalProofFact, CanonicalUnknownFact))
        for node in snapshot.ledger.nodes()
    )
    assert all(link.source_type.value != "ObservedFact" for link in snapshot.unknown_links)
    assert snapshot.proof_links[0].context == ("legacy affine partition",)


def test_adapter_ids_do_not_depend_on_legacy_tuple_order() -> None:
    first = _event("event-1", 0x1010, "worker")
    second = _event("event-2", 0x1020, "worker")
    first_unknown = _unknown(first.id)
    second_unknown = _unknown(second.id).model_copy(update={"pc": 0x1020})
    first_proof = _proof(first.id)
    second_proof = _proof(second.id).model_copy(update={"id": "proof:adapter-fixture-2"})

    left = adapt_static_report(
        _report(
            (first, second),
            (first_unknown, second_unknown),
            (first_proof, second_proof),
        )
    )
    right = adapt_static_report(
        _report(
            (second, first),
            (second_unknown, first_unknown),
            (second_proof, first_proof),
        )
    )

    assert left.event_ids == right.event_ids
    assert left.proof_ids == right.proof_ids
    assert left.unknown_ids == right.unknown_ids


def test_adapter_does_not_change_legacy_verdict_or_report_payload() -> None:
    event = _event("event-1", 0x1010, "worker")
    report = _report((event,), (), ())
    before = verify_portability(report)
    before_payload = before.model_dump_json()

    adapt_static_report(report)

    after = verify_portability(report)
    assert after.model_dump_json() == before_payload
    assert report == report.model_validate_json(report.model_dump_json())


def test_adapter_rejects_proof_that_would_drop_an_event_reference() -> None:
    proof = _proof("event-not-in-report")
    with pytest.raises(StaticAdapterError, match="references missing events"):
        adapt_static_report(_report((), (), (proof,)))


def test_adapter_source_has_no_dynamic_or_diagnostics_imports() -> None:
    path = Path(__file__).resolve().parents[2] / "src" / "bmo_check_static" / "adapters" / "evidence.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    assert all(
        not name.startswith("bmo_check_dynamic")
        and not name.startswith("bmo_check_diagnostics")
        for name in imports
    )


def test_canonical_unknown_registry_covers_legacy_static_kinds() -> None:
    assert {
        item.value for item in UnknownKind
    }.issubset({item.value for item in CanonicalUnknownKind})
