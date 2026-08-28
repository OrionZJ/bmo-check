from __future__ import annotations

import hashlib
from pathlib import Path

from bmo_check.evaluation import (
    ABLATION_LEVELS,
    ablate_shared_state,
    load_evaluation_suite,
    find_publication_risks,
    run_native_benchmark,
)
from bmo_check.model import (
    AbstractAddress,
    AddressKind,
    BenchmarkDefinition,
    EventKind,
    MemoryEvent,
    MemoryEventReport,
    Ordering,
    ProofObject,
    ProofReason,
    ProgramOrderEdge,
    PruningCoverage,
    SharedMemorySlice,
    SharedStateReport,
)


def _event(event_id: str) -> MemoryEvent:
    return MemoryEvent(
        id=event_id,
        module="app",
        module_sha256="a" * 64,
        pc=0x1000,
        kind=EventKind.LOAD,
        address=AbstractAddress(kind=AddressKind.GLOBAL, base=event_id, offset=0),
        size=4,
        thread_role="worker",
    )


def test_ablation_levels_only_add_proven_pruning() -> None:
    events = tuple(_event(f"event:{index}") for index in range(4))
    reasons = (
        ProofReason.TLS_STORAGE,
        ProofReason.READ_ONLY_AFTER_CREATE,
        ProofReason.DISJOINT_AFFINE,
        ProofReason.ATOMIC_COVERED,
    )
    proofs = tuple(
        ProofObject(
            id=f"proof:{index}",
            reason=reason,
            event_ids=(events[index].id,),
            supporting_facts=("test fact",),
        )
        for index, reason in enumerate(reasons)
    )
    report = MemoryEventReport(
        module_path="app", module_sha256="a" * 64, events=events
    )
    state = SharedStateReport(
        removed_event_ids=tuple(event.id for event in events), proofs=proofs
    )

    remaining = [
        len(ablate_shared_state(report, state, level).kept_event_ids)
        for level in ABLATION_LEVELS
    ]

    assert remaining == [4, 3, 2, 1, 0]


def test_parsec_suite_contains_four_configured_programs() -> None:
    suite_path = Path(__file__).resolve().parents[2] / "specs" / "parsec-simlarge.yaml"
    suite = load_evaluation_suite(suite_path)

    assert {item.id for item in suite.benchmarks} == {
        "blackscholes",
        "swaptions",
        "dedup",
        "canneal",
    }


def test_native_exit_and_output_validation_are_separate(tmp_path: Path) -> None:
    executable = tmp_path / "copy-input"
    executable.write_text(
        "#!/bin/sh\ncp input.txt result.txt\nexit 7\n", encoding="utf-8"
    )
    executable.chmod(0o755)
    run_directory = tmp_path / "run"
    run_directory.mkdir()
    (run_directory / "input.txt").write_text("payload\n", encoding="utf-8")
    expected = hashlib.sha256(b"payload\n").hexdigest()
    definition = BenchmarkDefinition(
        id="fixture",
        executable="copy-input",
        run_directory="run",
        argv=(),
        threads=1,
        input_files=("input.txt",),
        output_files=("result.txt",),
        expected_output_sha256={"result.txt": expected},
    )

    result = run_native_benchmark(definition, tmp_path, (), 10)

    assert result.exit_code == 7
    assert result.outputs[0].matches_expected is True


def test_publication_risk_search_is_not_blocked_by_unrelated_unknowns() -> None:
    def access(event_id: str, role: str, pc: int, kind: EventKind, base: str):
        return MemoryEvent(
            id=event_id,
            module="app",
            module_sha256="a" * 64,
            pc=pc,
            kind=kind,
            address=AbstractAddress(kind=AddressKind.GLOBAL, base=base, offset=0),
            size=4,
            source_ordering=Ordering.TSO,
            target_ordering=Ordering.RELAXED,
            thread_role=role,
        )

    write_data = access("w:data", "writer", 0x1000, EventKind.STORE, "data")
    write_flag = access("w:flag", "writer", 0x1010, EventKind.STORE, "flag")
    read_flag = access("r:flag", "reader", 0x2000, EventKind.LOAD, "flag")
    read_data = access("r:data", "reader", 0x2010, EventKind.LOAD, "data")
    unrelated = MemoryEvent(
        id="other:unknown",
        module="app",
        module_sha256="a" * 64,
        pc=0x3000,
        kind=EventKind.OPAQUE_CALL,
        address=AbstractAddress(kind=AddressKind.UNKNOWN),
        thread_role="other",
    )
    shared_slice = SharedMemorySlice(
        events=(write_data, write_flag, read_flag, read_data, unrelated),
        program_order=(
            ProgramOrderEdge(
                source_event=write_data.id,
                target_event=write_flag.id,
                thread_role="writer",
                evidence="straight line",
            ),
            ProgramOrderEdge(
                source_event=read_flag.id,
                target_event=read_data.id,
                thread_role="reader",
                evidence="straight line",
            ),
        ),
        coverage=PruningCoverage(total_events=5, remaining_shared_events=5),
    )

    findings = find_publication_risks(shared_slice)

    assert len(findings) == 1
    assert findings[0].kind == "PlainStorePublication"
