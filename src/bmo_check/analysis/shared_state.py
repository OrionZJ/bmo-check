from __future__ import annotations

from collections import defaultdict, deque

from capstone.x86 import X86_OP_MEM, X86_OP_REG

from bmo_check.binary.angr_backend import AngrBackendError, load_cfg
from bmo_check.model import (
    AddressKind,
    ControlFlowReport,
    EscapeKind,
    EventKind,
    MemoryEvent,
    MemoryEventReport,
    ModuleFingerprint,
    Ordering,
    ProofObject,
    ProofReason,
    SharedObject,
    SharedStateReport,
    SharingClass,
    ThreadDiscoveryReport,
    UnknownFact,
    UnknownKind,
)
from bmo_check.pruning import prove_affine_partition


_WRITE_KINDS = {
    EventKind.STORE,
    EventKind.ATOMIC_RMW,
    EventKind.OPAQUE_CALL,
    EventKind.SYSCALL,
    EventKind.UNKNOWN_MEMORY_EFFECT,
}
_READ_KINDS = {
    EventKind.LOAD,
    EventKind.ATOMIC_RMW,
    EventKind.OPAQUE_CALL,
    EventKind.SYSCALL,
    EventKind.UNKNOWN_MEMORY_EFFECT,
}


def _object_key(event: MemoryEvent) -> tuple[object, ...]:
    address = event.address
    if address is None:
        return ("no-address", event.id)
    if address.kind in {AddressKind.UNKNOWN, AddressKind.AFFINE}:
        # 未封闭的地址放进同一保守对象，防止不同表达式被误当成 NoAlias。
        if address.kind == AddressKind.UNKNOWN:
            return (AddressKind.UNKNOWN,)
        return (
            AddressKind.AFFINE,
            address.base,
            address.expression,
            address.offset,
            address.thread_coefficient,
            address.index_coefficient,
            address.index_lower,
            address.index_upper,
            address.thread_lower,
            address.thread_upper,
        )
    return (address.kind, address.base, address.offset)


def _stack_escape_by_function(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    relevant_functions: set[int],
) -> tuple[dict[int, EscapeKind], dict[int, tuple[str, ...]], tuple[str, ...]]:
    try:
        context = load_cfg(module)
    except AngrBackendError:
        return (
            {item.location.pc: EscapeKind.UNKNOWN for item in control_flow.functions},
            {},
            ("CFG backend failed while checking TLS address materialization",),
        )
    escapes: dict[int, EscapeKind] = {}
    evidence: dict[int, tuple[str, ...]] = {}
    tls_escape_evidence: list[str] = []
    for function in control_flow.functions:
        if function.location.pc not in relevant_functions:
            continue
        reasons: list[str] = []
        for block_pc in function.block_pcs:
            try:
                block = context.project.factory.block(context.to_rebased(block_pc))
            except Exception:
                reasons.append(f"block 0x{block_pc:x} could not be inspected")
                continue
            for wrapped in block.capstone.insns:
                instruction = wrapped.insn
                operands = list(instruction.operands)
                for operand in operands:
                    if operand.type == X86_OP_MEM:
                        base = instruction.reg_name(operand.mem.base)
                        segment = instruction.reg_name(operand.mem.segment)
                        if base in {"rsp", "rbp"} and instruction.mnemonic == "lea":
                            reasons.append(
                                f"0x{context.to_elf_pc(instruction.address):x}: stack address materialized by lea"
                            )
                        if segment in {"fs", "gs"} and (
                            instruction.mnemonic == "lea"
                            or (operand.mem.disp == 0 and operand.size >= 8)
                        ):
                            tls_escape_evidence.append(
                                f"0x{context.to_elf_pc(instruction.address):x}: TLS base may be materialized"
                            )
                    elif operand.type == X86_OP_REG:
                        register = instruction.reg_name(operand.reg)
                        if register not in {"rsp", "rbp"}:
                            continue
                        op = instruction.mnemonic
                        names = [
                            instruction.reg_name(item.reg)
                            for item in operands
                            if item.type == X86_OP_REG
                        ]
                        frame_setup = op == "mov" and names[:2] in (
                            ["rbp", "rsp"],
                            ["rsp", "rbp"],
                        )
                        stack_adjust = op in {"add", "sub", "and"} and names[:1] == ["rsp"]
                        frame_control = op in {"push", "pop", "leave", "call", "ret"}
                        if not (frame_setup or stack_adjust or frame_control):
                            reasons.append(
                                f"0x{context.to_elf_pc(instruction.address):x}: {register} used as a value by {op}"
                            )
        if reasons:
            escapes[function.location.pc] = EscapeKind.OPAQUE_ESCAPE
            evidence[function.location.pc] = tuple(sorted(set(reasons)))
        else:
            escapes[function.location.pc] = EscapeKind.NO_ESCAPE
            evidence[function.location.pc] = (
                "all recovered uses of rsp/rbp are frame control or direct stack operands",
            )
    return escapes, evidence, tuple(sorted(set(tls_escape_evidence)))


def _path_exists(edges: dict[str, set[str]], source: str, target: str) -> bool:
    pending: deque[str] = deque([source])
    seen: set[str] = set()
    while pending:
        current = pending.popleft()
        if current == target:
            return True
        if current in seen:
            continue
        seen.add(current)
        pending.extend(edges.get(current, ()))
    return False


def _readonly_after_create(
    grouped_events: tuple[MemoryEvent, ...], report: MemoryEventReport
) -> tuple[bool, tuple[str, ...]]:
    writers = [event for event in grouped_events if event.kind in _WRITE_KINDS]
    worker_readers = [
        event
        for event in grouped_events
        if event.kind in _READ_KINDS and event.thread_role not in {None, "main"}
    ]
    if not writers or not worker_readers:
        return False, ()
    if any(event.thread_role != "main" for event in writers):
        return False, ()
    # 任意 opaque effect 都可能是隐藏 writer；此时不能批准 read-only 剪枝。
    if any(
        event.kind in {EventKind.OPAQUE_CALL, EventKind.SYSCALL, EventKind.UNKNOWN_MEMORY_EFFECT}
        or (
            event.address is not None
            and event.address.kind in {AddressKind.UNKNOWN, AddressKind.AFFINE}
        )
        for event in report.events
    ):
        return False, ()
    creates = [event for event in report.events if event.kind == EventKind.THREAD_CREATE]
    if not creates:
        return False, ()
    if any(
        event.target_ordering
        not in {Ordering.RELEASE, Ordering.ACQ_REL, Ordering.FULL}
        for event in creates
    ):
        return False, ()
    edges: dict[str, set[str]] = defaultdict(set)
    for edge in report.program_order:
        edges[edge.source_event].add(edge.target_event)
    if not all(
        _path_exists(edges, writer.id, create.id)
        for writer in writers
        for create in creates
    ):
        return False, ()
    return True, tuple(
        [f"main writer {writer.id} precedes every pthread_create" for writer in writers]
        + [
            "no worker writer or opaque memory effect was recovered",
            "every pthread_create has a concrete Release-or-stronger target summary",
        ]
    )


def analyze_shared_state(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    threads: ThreadDiscoveryReport,
    memory_events: MemoryEventReport,
) -> SharedStateReport:
    relevant_functions = {
        event.function_pc
        for event in memory_events.events
        if event.function_pc is not None
    }
    stack_escape, stack_evidence, tls_escape_evidence = _stack_escape_by_function(
        module, control_flow, relevant_functions
    )
    groups: dict[tuple[object, ...], list[MemoryEvent]] = defaultdict(list)
    for event in memory_events.events:
        if event.address is not None:
            groups[_object_key(event)].append(event)

    objects: list[SharedObject] = []
    proofs: list[ProofObject] = []
    removed: set[str] = set()
    unknowns: list[UnknownFact] = []
    wildcard_events = {
        event.id
        for event in memory_events.events
        if event.kind in {EventKind.OPAQUE_CALL, EventKind.SYSCALL, EventKind.UNKNOWN_MEMORY_EFFECT}
        or (
            event.address is not None
            and event.address.kind in {AddressKind.UNKNOWN, AddressKind.AFFINE}
        )
    }
    for index, (_, items) in enumerate(sorted(groups.items(), key=lambda item: str(item[0]))):
        events = tuple(items)
        address = events[0].address
        assert address is not None
        roles = tuple(sorted({event.thread_role or "unknown" for event in events}))
        readers = tuple(event.id for event in events if event.kind in _READ_KINDS)
        writers = tuple(event.id for event in events if event.kind in _WRITE_KINDS)
        sharing = SharingClass.SHARED_KNOWN
        escape = EscapeKind.UNKNOWN
        proof: ProofObject | None = None

        external_wildcards = wildcard_events - {event.id for event in events}
        if (
            address.kind == AddressKind.TLS
            and not tls_escape_evidence
        ):
            sharing = SharingClass.THREAD_LOCAL
            escape = EscapeKind.NO_ESCAPE
            proof = ProofObject(
                id=f"proof:tls:{index}",
                reason=ProofReason.TLS_STORAGE,
                event_ids=tuple(event.id for event in events),
                supporting_facts=(
                    f"x86 segment override {address.base} identifies per-thread storage",
                    "TLS bases differ between dynamic thread instances",
                ),
            )
        elif address.kind == AddressKind.TLS:
            sharing = SharingClass.SHARED_UNKNOWN
            escape = EscapeKind.UNKNOWN
            unknowns.append(
                UnknownFact(
                    kind=UnknownKind.UNKNOWN_ESCAPE,
                    reason=(
                        tls_escape_evidence[0]
                        if tls_escape_evidence
                        else "an unknown address or opaque effect may reference escaped TLS storage"
                    ),
                    impact="direct TLS events remain in the shared-memory slice",
                    module=module.path,
                    pc=min(event.pc for event in events),
                    details={"event_ids": [event.id for event in events]},
                )
            )
        elif address.kind == AddressKind.STACK:
            function_pcs = {event.function_pc for event in events if event.function_pc is not None}
            if function_pcs and all(stack_escape.get(pc) == EscapeKind.NO_ESCAPE for pc in function_pcs):
                sharing = SharingClass.THREAD_LOCAL
                escape = EscapeKind.NO_ESCAPE
                proof = ProofObject(
                    id=f"proof:stack:{index}",
                    reason=ProofReason.UNESCAPED_STACK,
                    event_ids=tuple(event.id for event in events),
                    supporting_facts=tuple(
                        fact
                        for pc in sorted(function_pcs)
                        for fact in stack_evidence.get(pc, ())
                    ),
                )
            else:
                sharing = SharingClass.SHARED_UNKNOWN
                escape = EscapeKind.OPAQUE_ESCAPE
                unknowns.append(
                    UnknownFact(
                        kind=UnknownKind.UNKNOWN_ESCAPE,
                        reason="stack address may be materialized or escape the owning frame",
                        impact="stack events remain shared MayAlias candidates",
                        module=module.path,
                        pc=min(event.pc for event in events),
                        details={"event_ids": [event.id for event in events]},
                    )
                )
        elif address.kind == AddressKind.GLOBAL:
            escape = EscapeKind.THREAD_ESCAPE if len(roles) > 1 else EscapeKind.NO_ESCAPE
            if roles == ("main",) and not external_wildcards:
                sharing = SharingClass.THREAD_LOCAL
                proof = ProofObject(
                    id=f"proof:main:{index}",
                    reason=ProofReason.SINGLE_MAIN_ROLE,
                    event_ids=tuple(event.id for event in events),
                    supporting_facts=("only the unique main thread role reaches this object",),
                )
            else:
                readonly, evidence = _readonly_after_create(events, memory_events)
                if readonly:
                    sharing = SharingClass.READ_ONLY_AFTER_CREATE
                    proof = ProofObject(
                        id=f"proof:readonly:{index}",
                        reason=ProofReason.READ_ONLY_AFTER_CREATE,
                        event_ids=tuple(event.id for event in events),
                        supporting_facts=evidence,
                    )
        elif address.kind == AddressKind.AFFINE:
            escape = EscapeKind.UNKNOWN
            disjoint, evidence = prove_affine_partition(address)
            if disjoint and writers and not external_wildcards:
                sharing = SharingClass.DISJOINT_PARTITION
                proof = ProofObject(
                    id=f"proof:affine:{index}",
                    reason=ProofReason.DISJOINT_AFFINE,
                    event_ids=tuple(event.id for event in events),
                    supporting_facts=evidence,
                )
            else:
                sharing = SharingClass.SHARED_UNKNOWN
                unknowns.append(
                    UnknownFact(
                        kind=UnknownKind.UNKNOWN_AFFINE_BOUNDS,
                        reason=evidence[0] if evidence else "affine partition is not closed",
                        impact="different thread instances may access overlapping bytes",
                        module=module.path,
                        pc=min(event.pc for event in events),
                        details={"event_ids": [event.id for event in events]},
                    )
                )
        else:
            sharing = SharingClass.SHARED_UNKNOWN
            escape = EscapeKind.UNKNOWN

        if proof is not None:
            proofs.append(proof)
            removed.update(proof.event_ids)
        objects.append(
            SharedObject(
                id=f"object:{index}",
                address=address,
                event_ids=tuple(event.id for event in events),
                roles=roles,
                reader_events=readers,
                writer_events=writers,
                sharing=sharing,
                escape=escape,
            )
        )

    event_ids = {event.id for event in memory_events.events}
    kept = tuple(sorted(event_ids - removed))
    return SharedStateReport(
        objects=tuple(objects),
        kept_event_ids=kept,
        removed_event_ids=tuple(sorted(removed)),
        proofs=tuple(proofs),
        unknowns=tuple(unknowns),
    )
