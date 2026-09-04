from __future__ import annotations

from pathlib import Path

from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    CheckerConclusion,
    CheckerLimits,
    CheckerReport,
    ConflictCandidate,
    ElfMetadata,
    EventKind,
    ExecutionScope,
    MemoryEvent,
    MemoryEventReport,
    ModuleFingerprint,
    ModuleRole,
    Ordering,
    PruningCoverage,
    ProgramManifest,
    ProgramOrderEdge,
    ProgramRecoveryReport,
    ProgramSliceReport,
    SharedMemorySlice,
    SharedStateReport,
    UnknownFact,
    UnknownKind,
    Verdict,
)
from bmo_check_static.proof import (
    explain_certificate,
    verify_certificate_scope,
    verify_portability,
)


HASH = "a" * 64


def _module(sha256: str = HASH) -> ModuleFingerprint:
    return ModuleFingerprint(
        path="/bin/litmus",
        role=ModuleRole.EXECUTABLE,
        size=4096,
        sha256=sha256,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )


def _manifest(sha256: str = HASH) -> ProgramManifest:
    return ProgramManifest(
        executable=_module(sha256),
        execution=ExecutionScope(thread_count_min=2, thread_count_max=2),
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision="b" * 40,
        closure_complete=True,
    )


def _event(
    event_id: str,
    role: str,
    pc: int,
    kind: EventKind,
    base: str | None = None,
    ordering: Ordering = Ordering.RELAXED,
) -> MemoryEvent:
    address = None
    size = None
    if base is not None:
        address = AbstractAddress(
            kind=AddressKind.GLOBAL,
            base=base,
            offset=0,
        )
        size = 4
    return MemoryEvent(
        id=event_id,
        module="/bin/litmus",
        module_sha256=HASH,
        pc=pc,
        kind=kind,
        address=address,
        size=size,
        source_ordering=(
            Ordering.FULL if kind == EventKind.FENCE else Ordering.TSO
        ),
        target_ordering=ordering,
        thread_role=role,
    )


def _message_passing_events(
    middle: MemoryEvent | None = None,
) -> tuple[tuple[MemoryEvent, ...], tuple[ProgramOrderEdge, ...]]:
    write_data = _event("t0:w-data", "t0", 0x1000, EventKind.STORE, "data")
    write_flag = _event("t0:w-flag", "t0", 0x1010, EventKind.STORE, "flag")
    read_flag = _event("t1:r-flag", "t1", 0x2000, EventKind.LOAD, "flag")
    read_data = _event("t1:r-data", "t1", 0x2010, EventKind.LOAD, "data")
    events = [write_data]
    if middle is not None:
        events.append(middle)
    events.extend((write_flag, read_flag, read_data))

    writer_ids = [write_data.id]
    if middle is not None:
        writer_ids.append(middle.id)
    writer_ids.append(write_flag.id)
    edges = [
        ProgramOrderEdge(
            source_event=source,
            target_event=target,
            thread_role="t0",
            evidence="litmus straight line",
        )
        for source, target in zip(writer_ids, writer_ids[1:])
    ]
    edges.append(
        ProgramOrderEdge(
            source_event=read_flag.id,
            target_event=read_data.id,
            thread_role="t1",
            evidence="litmus straight line",
        )
    )
    return tuple(events), tuple(edges)


def _report(
    events: tuple[MemoryEvent, ...],
    edges: tuple[ProgramOrderEdge, ...],
    *,
    conflicts: bool = True,
    unknowns: tuple[UnknownFact, ...] = (),
    manifest: ProgramManifest | None = None,
) -> ProgramSliceReport:
    conflict_items = ()
    if conflicts:
        conflict_items = (
            ConflictCandidate(
                first_event=events[0].id,
                second_event=events[-1].id,
                first_role=events[0].thread_role or "t0",
                second_role=events[-1].thread_role or "t1",
                alias="MayAlias",
            ),
        )
    shared_slice = SharedMemorySlice(
        events=events,
        program_order=edges,
        conflicts=conflict_items,
        coverage=PruningCoverage(
            total_events=len(events),
            remaining_shared_events=len(events),
        ),
        unknowns=unknowns,
    )
    return ProgramSliceReport(
        recovery=ProgramRecoveryReport(manifest=manifest or _manifest()),
        memory_events=MemoryEventReport(
            module_path="/bin/litmus",
            module_sha256=HASH,
            events=events,
            program_order=edges,
            unknowns=unknowns,
        ),
        shared_state=SharedStateReport(
            kept_event_ids=tuple(event.id for event in events),
            unknowns=unknowns,
        ),
        shared_slice=shared_slice,
    )


def test_plain_store_publication_has_target_only_execution() -> None:
    events, edges = _message_passing_events()
    certificate = verify_portability(_report(events, edges))

    assert certificate.verdict == Verdict.COUNTEREXAMPLE
    assert certificate.checker.conclusion == CheckerConclusion.TARGET_ONLY
    assert certificate.counterexample is not None
    choices = {
        item.load_event: item.store_event
        for item in certificate.counterexample.read_from
    }
    assert choices["t1:r-flag"] == "t0:w-flag"
    assert choices["t1:r-data"] is None
    assert "t0:w-data" in certificate.counterexample.source_cycle
    assert any(
        "t0:w-data -> t0:w-flag" in item
        for item in certificate.counterexample.missing_ordering
    )


def test_full_fence_blocks_counterexample_but_bounded_result_is_unknown() -> None:
    fence = _event(
        "t0:mfence",
        "t0",
        0x1008,
        EventKind.FENCE,
        ordering=Ordering.FULL,
    )
    events, edges = _message_passing_events(fence)
    read_fence = _event(
        "t1:mfence",
        "t1",
        0x2008,
        EventKind.FENCE,
        ordering=Ordering.FULL,
    )
    events = (*events[:-1], read_fence, events[-1])
    edges = (
        *edges[:-1],
        ProgramOrderEdge(
            source_event="t1:r-flag",
            target_event=read_fence.id,
            thread_role="t1",
            evidence="litmus straight line",
        ),
        ProgramOrderEdge(
            source_event=read_fence.id,
            target_event="t1:r-data",
            thread_role="t1",
            evidence="litmus straight line",
        ),
    )
    certificate = verify_portability(_report(events, edges))

    assert certificate.verdict == Verdict.UNKNOWN
    assert certificate.checker.conclusion == CheckerConclusion.BOUNDED_EXHAUSTED
    assert certificate.counterexample is None


def test_acq_rel_atomic_publication_blocks_plain_message_counterexample() -> None:
    write_data = _event("t0:w-data", "t0", 0x1000, EventKind.STORE, "data")
    publish = _event(
        "t0:publish",
        "t0",
        0x1010,
        EventKind.ATOMIC_RMW,
        "flag",
        Ordering.ACQ_REL,
    )
    acquire = _event(
        "t1:acquire",
        "t1",
        0x2000,
        EventKind.ATOMIC_RMW,
        "flag",
        Ordering.ACQ_REL,
    )
    read_data = _event("t1:r-data", "t1", 0x2010, EventKind.LOAD, "data")
    events = (write_data, publish, acquire, read_data)
    edges = (
        ProgramOrderEdge(
            source_event=write_data.id,
            target_event=publish.id,
            thread_role="t0",
            evidence="litmus straight line",
        ),
        ProgramOrderEdge(
            source_event=acquire.id,
            target_event=read_data.id,
            thread_role="t1",
            evidence="litmus straight line",
        ),
    )

    certificate = verify_portability(_report(events, edges))

    assert certificate.verdict == Verdict.UNKNOWN
    assert certificate.checker.conclusion == CheckerConclusion.BOUNDED_EXHAUSTED


def test_empty_conflict_slice_is_structurally_safe() -> None:
    events, edges = _message_passing_events()
    certificate = verify_portability(_report(events, edges, conflicts=False))

    assert certificate.verdict == Verdict.SAFE
    assert certificate.checker.conclusion == CheckerConclusion.STRUCTURAL_SAFE
    assert not certificate.checker.bounded


def test_relevant_unknown_blocks_checker_and_safe() -> None:
    events, edges = _message_passing_events()
    unknown = UnknownFact(
        kind=UnknownKind.UNRESOLVED_INDIRECT_CALL,
        reason="indirect target set is open",
        impact="callee may access shared state",
        module="/bin/litmus",
        pc=0x3000,
    )
    certificate = verify_portability(_report(events, edges, unknowns=(unknown,)))

    assert certificate.verdict == Verdict.UNKNOWN
    assert unknown in certificate.relevant_unknowns
    assert certificate.checker.examined_executions == 0


def test_opaque_event_does_not_duplicate_its_extraction_unknown() -> None:
    event = _event("t0:call", "t0", 0x3000, EventKind.OPAQUE_CALL)
    unknown = UnknownFact(
        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
        reason="call 'helper' has no complete memory-effect summary",
        impact="the call may read or write any shared object",
        module="/bin/litmus",
        pc=event.pc,
        details={"event_id": event.id},
    )

    certificate = verify_portability(
        _report((event,), (), conflicts=False, unknowns=(unknown,))
    )

    assert certificate.verdict == Verdict.UNKNOWN
    assert certificate.relevant_unknowns == (unknown,)


def test_event_bound_is_unknown_not_safe() -> None:
    events, edges = _message_passing_events()
    certificate = verify_portability(
        _report(events, edges), CheckerLimits(max_events=2)
    )

    assert certificate.verdict == Verdict.UNKNOWN
    assert certificate.checker.unsupported_events
    assert certificate.relevant_unknowns[0].kind == UnknownKind.UNSUPPORTED_PORTABILITY_INPUT


def test_checker_timeout_is_unknown(monkeypatch) -> None:
    events, edges = _message_passing_events()

    def timed_out(_shared_slice, limits):
        return (
            CheckerReport(
                backend="test",
                backend_version="1",
                limits=limits,
                conclusion=CheckerConclusion.INCOMPLETE,
                reason="the portability checker reached its timeout",
            ),
            None,
        )

    monkeypatch.setattr(
        "bmo_check_static.proof.verifier.check_finite_portability", timed_out
    )
    certificate = verify_portability(_report(events, edges))

    assert certificate.verdict == Verdict.UNKNOWN
    assert certificate.relevant_unknowns[0].kind == UnknownKind.PORTABILITY_CHECK_TIMEOUT


def test_certificate_scope_detects_stale_binary_and_explain_lists_pcs() -> None:
    events, edges = _message_passing_events()
    limits = CheckerLimits()
    certificate = verify_portability(_report(events, edges), limits)
    stale = verify_certificate_scope(certificate, _manifest("c" * 64), limits)
    explanation = explain_certificate(certificate)

    assert stale[0].kind == UnknownKind.STALE_CERTIFICATE
    assert "0x1000" in explanation
    assert "source=TSO target=Relaxed" in explanation
    assert "missing order" in explanation


def test_only_verifier_module_constructs_final_verdict() -> None:
    root = Path(__file__).resolve().parents[3] / "src" / "bmo_check_static"
    offenders = []
    for path in root.rglob("*.py"):
        if path.name == "verifier.py" or "model" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "verdict=Verdict." in text:
            offenders.append(path)
    assert not offenders
