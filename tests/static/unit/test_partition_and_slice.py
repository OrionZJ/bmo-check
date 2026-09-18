from __future__ import annotations

from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    CallKind,
    CallSite,
    CFGCoverage,
    CodeLocation,
    ControlFlowReport,
    EventKind,
    IndirectTargetSet,
    MemoryEvent,
    MemoryEventReport,
    Ordering,
    ProofObject,
    ProofReason,
    PruningCoverage,
    ProgramOrderEdge,
    SharedMemorySlice,
    SharedStateReport,
    SynchronizationEdge,
    ThreadDiscoveryReport,
    UnknownFact,
    UnknownKind,
)
from bmo_check_static.pruning import prove_affine_partition
from bmo_check_static.slicing import (
    build_shared_memory_slice,
    restrict_to_application_scope,
)
from bmo_check_static.analysis.shared_state import (
    _addresses_may_alias,
    _fresh_worker_event,
    _worker_allocation_bases,
    _readonly_after_create,
)


def _affine(thread_stride: int, index_upper: int) -> AbstractAddress:
    return AbstractAddress(
        kind=AddressKind.AFFINE,
        offset=0,
        expression=f"{thread_stride}*tid+index",
        thread_coefficient=thread_stride,
        index_coefficient=1,
        index_lower=0,
        index_upper=index_upper,
        thread_lower=0,
        thread_upper=3,
    )


def test_z3_proves_disjoint_and_rejects_overlapping_affine_partitions() -> None:
    disjoint, evidence = prove_affine_partition(_affine(16, 15))
    overlapping, counterexample = prove_affine_partition(_affine(8, 15))

    assert disjoint
    assert "Z3 proved" in evidence[0]
    assert not overlapping
    assert "overlapping" in counterexample[0]


def test_missing_affine_bounds_remains_unproved() -> None:
    proved, evidence = prove_affine_partition(
        AbstractAddress(
            kind=AddressKind.AFFINE,
            expression="chunk*tid+index",
            thread_coefficient=16,
            index_coefficient=1,
        )
    )
    assert not proved
    assert "incomplete" in evidence[0]


def test_runtime_internal_object_does_not_alias_application_arrays() -> None:
    runtime = AbstractAddress(
        kind=AddressKind.GLOBAL,
        base="runtime:allocator",
    )
    application = AbstractAddress(
        kind=AddressKind.AFFINE,
        base="app@0x2000",
        expression="app@0x2000+i*8",
        provenance={"base_indirect": True},
    )

    assert not _addresses_may_alias(runtime, application)
    assert _addresses_may_alias(runtime, runtime)

    heap_union = AbstractAddress(
        kind=AddressKind.HEAP,
        base="heap-union:argument@0x3000:rdi",
    )
    concrete_heap = AbstractAddress(
        kind=AddressKind.HEAP,
        base="heap:malloc@0x1000",
    )
    assert _addresses_may_alias(heap_union, concrete_heap)
    assert not _addresses_may_alias(heap_union, application)


def test_heap_union_candidates_only_alias_matching_allocation_site() -> None:
    heap_union = AbstractAddress(
        kind=AddressKind.HEAP,
        base="heap-union:argument@0x3000:rdi",
        provenance={
            "candidate_bases": ["heap:malloc@0x1000", "heap:malloc@0x2000"]
        },
    )
    included = AbstractAddress(
        kind=AddressKind.HEAP,
        base="heap:malloc@0x1000",
    )
    excluded = AbstractAddress(
        kind=AddressKind.HEAP,
        base="heap:malloc@0x4000",
    )

    assert _addresses_may_alias(heap_union, included)
    assert not _addresses_may_alias(heap_union, excluded)


def test_fresh_worker_event_requires_non_main_role() -> None:
    worker = MemoryEvent(
        id="worker:fresh",
        module="app",
        module_sha256="a" * 64,
        pc=0x1000,
        kind=EventKind.STORE,
        address=AbstractAddress(
            kind=AddressKind.AFFINE,
            base="heap:function@0x2000@0x3000",
            expression="heap:function@0x2000@0x3000+i*8",
            provenance={"base_indirect": False},
        ),
        thread_role="worker",
    )
    main = worker.model_copy(update={"id": "main:fresh", "thread_role": "main"})

    assert _fresh_worker_event(worker)
    assert not _fresh_worker_event(main)


def test_worker_allocation_bases_accept_every_fresh_allocator_name() -> None:
    event = MemoryEvent(
        id="worker:calloc",
        module="app",
        module_sha256="a" * 64,
        pc=0x1200,
        kind=EventKind.STORE,
        address=AbstractAddress(
            kind=AddressKind.AFFINE,
            base="heap:calloc@0x1100",
            expression="heap:calloc@0x1100+i*4",
            provenance={"base_indirect": False},
        ),
        thread_role="worker",
    )
    call = CallSite(
        location=CodeLocation(module_path="app", module_sha256="a" * 64, pc=0x1100),
        containing_function_pc=0x2000,
        block_pc=0x2000,
        kind=CallKind.PLT,
        target_symbol="calloc",
        targets=IndirectTargetSet(complete=True),
    )
    cfg = ControlFlowReport(
        module_path="app",
        module_sha256="a" * 64,
        entry_pc=0x2000,
        functions=(),
        basic_blocks=(),
        call_sites=(call,),
        coverage=CFGCoverage(
            angr_version="test",
            functions=0,
            basic_blocks=0,
            call_sites=1,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    assert _worker_allocation_bases((event,), cfg, {0x2000}) == {
        "heap:calloc@0x1100"
    }


def test_fresh_worker_union_requires_only_worker_allocation_sites() -> None:
    worker = MemoryEvent(
        id="worker:union-fresh",
        module="app",
        module_sha256="a" * 64,
        pc=0x1000,
        kind=EventKind.LOAD,
        address=AbstractAddress(
            kind=AddressKind.AFFINE,
            base="heap-union:argument@0x3000:rdi",
            expression="heap-union:argument@0x3000:rdi+i*8",
            provenance={
                "base_indirect": False,
                "candidate_bases": [
                    "heap:function@0x1c49@0x24ea",
                    "heap:function@0x1c49@0x2518",
                ],
            },
        ),
        thread_role="worker",
    )
    mixed = worker.model_copy(
        update={
            "id": "worker:union-mixed",
            "address": worker.address.model_copy(
                update={
                    "provenance": {
                        **worker.address.provenance,
                        "candidate_bases": [
                            "heap:function@0x1c49@0x24ea",
                            "heap:malloc@0x2518",
                        ],
                    }
                }
            ),
        }
    )

    assert _fresh_worker_event(worker)
    assert not _fresh_worker_event(mixed)


def test_unknown_memory_effect_remains_in_slice_and_conflicts() -> None:
    unknown = MemoryEvent(
        id="worker:unknown",
        module="app",
        module_sha256="a" * 64,
        pc=0x1000,
        kind=EventKind.UNKNOWN_MEMORY_EFFECT,
        address=AbstractAddress(kind=AddressKind.UNKNOWN),
        thread_role="worker",
    )
    store = MemoryEvent(
        id="main:store",
        module="app",
        module_sha256="a" * 64,
        pc=0x2000,
        kind=EventKind.STORE,
        address=AbstractAddress(kind=AddressKind.GLOBAL, base="g", offset=0),
        size=4,
        source_ordering=Ordering.TSO,
        target_ordering=Ordering.RELAXED,
        thread_role="main",
    )
    fact = UnknownFact(
        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
        reason="opaque helper",
        impact="may access shared memory",
        module="app",
        pc=0x1000,
    )
    report = MemoryEventReport(
        module_path="app",
        module_sha256="a" * 64,
        events=(unknown, store),
        unknowns=(fact,),
    )
    state = SharedStateReport(kept_event_ids=(unknown.id, store.id))

    shared_slice = build_shared_memory_slice(
        report, state, ThreadDiscoveryReport()
    )

    assert {event.id for event in shared_slice.events} == {unknown.id, store.id}
    assert shared_slice.coverage.unknown_events == 1
    assert shared_slice.conflicts
    assert shared_slice.unknowns == (fact,)


def test_application_scope_removes_runtime_sync_edges_with_their_call() -> None:
    runtime = MemoryEvent(
        id="worker:malloc",
        module="app",
        module_sha256="a" * 64,
        pc=0x1000,
        kind=EventKind.OPAQUE_CALL,
        address=AbstractAddress(
            kind=AddressKind.GLOBAL,
            base="runtime:allocator",
            provenance={"runtime_internal": True},
        ),
        thread_role="worker",
        provenance={"runtime_internal": True},
    )
    join = MemoryEvent(
        id="main:join",
        module="app",
        module_sha256="a" * 64,
        pc=0x2000,
        kind=EventKind.THREAD_JOIN,
        thread_role="main",
    )
    scoped = restrict_to_application_scope(
        SharedMemorySlice(
            events=(runtime, join),
            coverage=PruningCoverage(total_events=2, remaining_shared_events=2),
            synchronization=(
                SynchronizationEdge(
                    source_event=runtime.id,
                    target_event=join.id,
                    kind="pthread_join",
                    complete=True,
                ),
            ),
        ),
        executable_sha256="a" * 64,
    )

    assert tuple(event.id for event in scoped.events) == (join.id,)
    assert scoped.synchronization == ()
    assert scoped.proof_objects[-1].reason == ProofReason.APPLICATION_RUNTIME_BOUNDARY


def test_application_scope_keeps_dependency_event_without_ownership_proof() -> None:
    """外部模块身份不能证明它没有读写应用拥有的对象。"""

    dependency_load = MemoryEvent(
        id="lib:load-app-object",
        module="/lib/libworker.so",
        module_sha256="b" * 64,
        pc=0x3000,
        kind=EventKind.LOAD,
        address=AbstractAddress(
            kind=AddressKind.GLOBAL,
            base="application:shared",
            offset=0,
        ),
        size=4,
        thread_role="worker",
    )
    scoped = restrict_to_application_scope(
        SharedMemorySlice(
            events=(dependency_load,),
            coverage=PruningCoverage(total_events=1, remaining_shared_events=1),
        ),
        executable_sha256="a" * 64,
    )

    assert tuple(event.id for event in scoped.events) == (dependency_load.id,)
    assert scoped.proof_objects == ()


def test_shared_state_proof_round_trip() -> None:
    proof = ProofObject(
        id="proof:tls",
        reason=ProofReason.TLS_STORAGE,
        event_ids=("event",),
        supporting_facts=("fs segment override",),
    )
    state = SharedStateReport(
        removed_event_ids=("event",),
        proofs=(proof,),
    )
    assert SharedStateReport.model_validate_json(state.model_dump_json()) == state


def test_readonly_pruning_requires_concrete_create_release_ordering() -> None:
    address = AbstractAddress(kind=AddressKind.GLOBAL, base="g", offset=0)
    writer = MemoryEvent(
        id="main:write",
        module="app",
        module_sha256="a" * 64,
        pc=0x1000,
        kind=EventKind.STORE,
        address=address,
        size=4,
        thread_role="main",
    )
    create = MemoryEvent(
        id="main:create",
        module="app",
        module_sha256="a" * 64,
        pc=0x1010,
        kind=EventKind.THREAD_CREATE,
        thread_role="main",
    )
    reader = MemoryEvent(
        id="worker:read",
        module="app",
        module_sha256="a" * 64,
        pc=0x2000,
        kind=EventKind.LOAD,
        address=address,
        size=4,
        thread_role="worker",
    )
    report = MemoryEventReport(
        module_path="app",
        module_sha256="a" * 64,
        events=(writer, create, reader),
        program_order=(
            ProgramOrderEdge(
                source_event=writer.id,
                target_event=create.id,
                thread_role="main",
                evidence="same block",
            ),
        ),
    )

    unproved, _ = _readonly_after_create((writer, reader), report)
    release_create = create.model_copy(update={"target_ordering": Ordering.RELEASE})
    proved, evidence = _readonly_after_create(
        (writer, reader),
        report.model_copy(update={"events": (writer, release_create, reader)}),
    )

    assert not unproved
    assert proved
    assert any("Release-or-stronger" in item for item in evidence)
