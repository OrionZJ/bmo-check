from __future__ import annotations

from collections import deque
from pathlib import Path

from bmo_check.binary.capstone_backend import collect_instruction_facts
from bmo_check.model import (
    AbstractAddress,
    AddressKind,
    CallKind,
    ControlFlowReport,
    EventKind,
    FenceKind,
    InstructionFact,
    MemoryAccessKind,
    MemoryEvent,
    MemoryEventReport,
    MemoryOperandFact,
    ModuleFingerprint,
    Ordering,
    ProgramOrderEdge,
    SynchronizationReport,
    ThreadDiscoveryReport,
    UnknownFact,
    UnknownKind,
)


_ACQUIRE_APIS = {"pthread_mutex_lock", "pthread_spin_lock"}
_RELEASE_APIS = {"pthread_mutex_unlock", "pthread_spin_unlock"}
_BARRIER_APIS = {"pthread_barrier_wait"}
def _function_graph(report: ControlFlowReport) -> dict[int, set[int]]:
    function_pcs = {item.location.pc for item in report.functions}
    graph: dict[int, set[int]] = {}
    for call in report.call_sites:
        for target in call.targets.known_targets:
            if target.module_sha256 == report.module_sha256 and target.pc in function_pcs:
                graph.setdefault(call.containing_function_pc, set()).add(target.pc)
    return graph


def _role_functions(
    report: ControlFlowReport, threads: ThreadDiscoveryReport
) -> dict[str, set[int]]:
    graph = _function_graph(report)
    result: dict[str, set[int]] = {}
    for role in threads.roles:
        roots = [
            target.pc
            for target in role.start_targets.known_targets
            if target.module_sha256 == report.module_sha256
        ]
        pending = list(roots)
        seen: set[int] = set()
        while pending:
            function_pc = pending.pop()
            if function_pc in seen:
                continue
            seen.add(function_pc)
            pending.extend(graph.get(function_pc, ()))
        result[role.id] = seen
    return result


def _block_maps(
    report: ControlFlowReport,
) -> tuple[dict[int, int], dict[int, int], dict[int, str | None]]:
    instruction_to_block: dict[int, int] = {}
    block_to_function: dict[int, int] = {}
    function_names: dict[int, str | None] = {}
    for function in report.functions:
        function_names[function.location.pc] = function.location.symbol
        for block_pc in function.block_pcs:
            block_to_function[block_pc] = function.location.pc
    for block in report.basic_blocks:
        for pc in block.instruction_pcs:
            instruction_to_block[pc] = block.location.pc
    return instruction_to_block, block_to_function, function_names


def _address(
    module: ModuleFingerprint,
    fact: InstructionFact,
    operand: MemoryOperandFact,
    function_pc: int,
) -> AbstractAddress:
    base = (operand.base or "").lower()
    segment = (operand.segment or "").lower()
    provenance = {
        "base_register": operand.base,
        "index_register": operand.index,
        "scale": operand.scale,
        "displacement": operand.displacement,
        "segment": operand.segment,
        "implicit": operand.implicit,
    }
    if segment in {"fs", "gs"}:
        return AbstractAddress(
            kind=AddressKind.TLS,
            base=segment,
            offset=operand.displacement,
            provenance=provenance,
        )
    if base == "rip":
        instruction_size = len(fact.raw_bytes) // 2
        target = fact.pc + instruction_size + operand.displacement
        return AbstractAddress(
            kind=AddressKind.GLOBAL,
            base=f"{Path(module.path).name}@0x{target:x}",
            offset=0,
            provenance={**provenance, "absolute_pc": target},
        )
    if not operand.base and not operand.index and operand.displacement:
        return AbstractAddress(
            kind=AddressKind.GLOBAL,
            base=f"{Path(module.path).name}@0x{operand.displacement:x}",
            offset=0,
            provenance={**provenance, "absolute_pc": operand.displacement},
        )
    if base in {"rsp", "rbp"} and not operand.index:
        return AbstractAddress(
            kind=AddressKind.STACK,
            base=f"frame@0x{function_pc:x}",
            offset=operand.displacement,
            provenance=provenance,
        )
    if operand.base or operand.index:
        terms = [item for item in (operand.base, operand.index) if item]
        expression = "+".join(terms)
        if operand.index and operand.scale != 1:
            expression = f"{operand.base or '0'}+{operand.index}*{operand.scale}"
        if operand.displacement:
            expression += f"{operand.displacement:+d}"
        return AbstractAddress(
            kind=AddressKind.AFFINE,
            expression=expression,
            offset=operand.displacement,
            provenance=provenance,
        )
    return AbstractAddress(
        kind=AddressKind.UNKNOWN,
        expression=fact.op_str or None,
        provenance=provenance,
    )


def _event_ordering(fact: InstructionFact) -> tuple[Ordering, Ordering]:
    if fact.has_lock_prefix or fact.is_memory_xchg:
        return Ordering.FULL, Ordering.ACQ_REL
    if fact.fence == FenceKind.LFENCE:
        return Ordering.FENCE_RR, Ordering.FENCE_RR
    if fact.fence == FenceKind.SFENCE:
        return Ordering.FENCE_WW, Ordering.FENCE_WW
    if fact.fence == FenceKind.MFENCE:
        return Ordering.FULL, Ordering.FULL
    return Ordering.TSO, Ordering.RELAXED


def _memory_kinds(
    fact: InstructionFact, operand: MemoryOperandFact
) -> tuple[EventKind, ...]:
    if fact.has_lock_prefix or fact.is_memory_xchg:
        return (EventKind.ATOMIC_RMW,)
    if operand.access == MemoryAccessKind.READ:
        return (EventKind.LOAD,)
    if operand.access == MemoryAccessKind.WRITE:
        return (EventKind.STORE,)
    if operand.access == MemoryAccessKind.READ_WRITE:
        return (EventKind.LOAD, EventKind.STORE)
    return (EventKind.UNKNOWN_MEMORY_EFFECT,)


def _summary_ordering(
    symbol: str, reports: tuple[SynchronizationReport, ...]
) -> Ordering | None:
    summaries = [
        summary
        for report in reports
        for summary in report.summaries
        if summary.api == symbol
    ]
    if not summaries or any(not summary.complete for summary in summaries):
        return None
    orderings = {summary.target_ordering for summary in summaries}
    return next(iter(orderings)) if len(orderings) == 1 else None


def _call_event_kind(symbol: str, ordering: Ordering | None) -> EventKind:
    if symbol == "pthread_create":
        return EventKind.THREAD_CREATE
    if symbol == "pthread_join":
        return EventKind.THREAD_JOIN
    if ordering is None:
        return EventKind.OPAQUE_CALL
    if symbol in _ACQUIRE_APIS:
        return EventKind.ACQUIRE
    if symbol in _RELEASE_APIS:
        return EventKind.RELEASE
    if symbol in _BARRIER_APIS:
        return EventKind.BARRIER
    return EventKind.OPAQUE_CALL


def extract_memory_events(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    threads: ThreadDiscoveryReport,
    synchronization: tuple[SynchronizationReport, ...] = (),
) -> MemoryEventReport:
    try:
        if not control_flow.functions or not control_flow.basic_blocks:
            raise RuntimeError("CFG contains no recoverable functions or basic blocks")
        instruction_report = collect_instruction_facts(module)
        instruction_to_block, block_to_function, function_names = _block_maps(
            control_flow
        )
        role_functions = _role_functions(control_flow, threads)
        roles_by_function: dict[int, set[str]] = {}
        for role, functions in role_functions.items():
            for function_pc in functions:
                roles_by_function.setdefault(function_pc, set()).add(role)

        events: list[MemoryEvent] = []
        unknowns: list[UnknownFact] = list(instruction_report.unknowns)
        block_events: dict[tuple[str, int], list[MemoryEvent]] = {}

        def append_event(event: MemoryEvent) -> None:
            events.append(event)
            if event.block_pc is not None and event.thread_role is not None:
                block_events.setdefault((event.thread_role, event.block_pc), []).append(event)

        for role in threads.roles:
            if role.start_targets.complete and role.start_targets.known_targets:
                continue
            event_id = f"{role.id}:unknown-thread-entry"
            append_event(
                MemoryEvent(
                    id=event_id,
                    module=module.path,
                    module_sha256=module.sha256,
                    pc=role.create_site.pc if role.create_site else control_flow.entry_pc,
                    kind=EventKind.UNKNOWN_MEMORY_EFFECT,
                    address=AbstractAddress(kind=AddressKind.UNKNOWN),
                    thread_role=role.id,
                    provenance={"reason": role.start_targets.reason},
                )
            )
            unknowns.append(
                UnknownFact(
                    kind=UnknownKind.UNKNOWN_THREAD_ROLE,
                    reason=role.start_targets.reason or "thread entry is incomplete",
                    impact="the unknown worker may access any shared object",
                    module=module.path,
                    pc=role.create_site.pc if role.create_site else None,
                    details={"event_id": event_id, "role": role.id},
                )
            )

        for fact in instruction_report.facts:
            block_pc = instruction_to_block.get(fact.pc)
            if block_pc is None:
                continue
            function_pc = block_to_function.get(block_pc)
            if function_pc is None:
                continue
            roles = roles_by_function.get(function_pc, set())
            if not roles:
                continue
            source_ordering, target_ordering = _event_ordering(fact)
            for role in sorted(roles):
                for operand in fact.memory_operands:
                    address = _address(module, fact, operand, function_pc)
                    for effect_index, kind in enumerate(_memory_kinds(fact, operand)):
                        event_id = (
                            f"{role}:0x{fact.pc:x}:m{operand.operand_index}:{effect_index}"
                        )
                        event = MemoryEvent(
                            id=event_id,
                            module=module.path,
                            module_sha256=module.sha256,
                            pc=fact.pc,
                            block_pc=block_pc,
                            function=function_names.get(function_pc),
                            function_pc=function_pc,
                            kind=kind,
                            address=address,
                            size=operand.size,
                            source_ordering=source_ordering,
                            target_ordering=target_ordering,
                            thread_role=role,
                            operand_index=operand.operand_index,
                            provenance={
                                "raw_bytes": fact.raw_bytes,
                                "mnemonic": fact.mnemonic,
                                "op_str": fact.op_str,
                                "dbt_rule": (
                                    "lock_rmw"
                                    if fact.has_lock_prefix
                                    else "memory_xchg"
                                    if fact.is_memory_xchg
                                    else "plain_memory"
                                ),
                            },
                        )
                        append_event(event)
                        if address.kind in {AddressKind.UNKNOWN, AddressKind.AFFINE}:
                            unknowns.append(
                                UnknownFact(
                                    kind=UnknownKind.UNKNOWN_SHARED_ADDRESS,
                                    reason="memory address is not reduced to a bounded object",
                                    impact="the event must remain a MayAlias communication candidate",
                                    module=module.path,
                                    pc=fact.pc,
                                    function=function_names.get(function_pc),
                                    details={"event_id": event_id, "expression": address.expression},
                                )
                            )
                if fact.fence is not None:
                    append_event(
                        MemoryEvent(
                            id=f"{role}:0x{fact.pc:x}:fence",
                            module=module.path,
                            module_sha256=module.sha256,
                            pc=fact.pc,
                            block_pc=block_pc,
                            function=function_names.get(function_pc),
                            function_pc=function_pc,
                            kind=EventKind.FENCE,
                            source_ordering=source_ordering,
                            target_ordering=target_ordering,
                            thread_role=role,
                            provenance={"mnemonic": fact.mnemonic, "raw_bytes": fact.raw_bytes},
                        )
                    )
                if fact.is_syscall:
                    event_id = f"{role}:0x{fact.pc:x}:syscall"
                    append_event(
                        MemoryEvent(
                            id=event_id,
                            module=module.path,
                            module_sha256=module.sha256,
                            pc=fact.pc,
                            block_pc=block_pc,
                            function=function_names.get(function_pc),
                            function_pc=function_pc,
                            kind=EventKind.SYSCALL,
                            address=AbstractAddress(kind=AddressKind.UNKNOWN),
                            thread_role=role,
                            provenance={"mnemonic": "syscall"},
                        )
                    )
                    unknowns.append(
                        UnknownFact(
                            kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
                            reason="syscall memory effects are not summarized",
                            impact="the syscall remains in the shared-memory slice",
                            module=module.path,
                            pc=fact.pc,
                            details={"event_id": event_id},
                        )
                    )

        for call in control_flow.call_sites:
            roles = roles_by_function.get(call.containing_function_pc, set())
            external_or_incomplete = (
                not call.targets.complete
                or call.kind == CallKind.PLT
                or any(
                    target.module_sha256 != module.sha256
                    for target in call.targets.known_targets
                )
            )
            if not external_or_incomplete:
                continue
            symbol = call.target_symbol or "<indirect>"
            ordering = _summary_ordering(symbol, synchronization)
            kind = _call_event_kind(symbol, ordering)
            for role in sorted(roles):
                event_id = f"{role}:0x{call.location.pc:x}:call"
                address = (
                    AbstractAddress(kind=AddressKind.UNKNOWN)
                    if kind == EventKind.OPAQUE_CALL
                    else None
                )
                append_event(
                    MemoryEvent(
                        id=event_id,
                        module=module.path,
                        module_sha256=module.sha256,
                        pc=call.location.pc,
                        block_pc=call.block_pc,
                        function=function_names.get(call.containing_function_pc),
                        function_pc=call.containing_function_pc,
                        kind=kind,
                        address=address,
                        source_ordering=(
                            Ordering.FULL if kind in _lifecycle_or_sync_kinds() else Ordering.UNKNOWN
                        ),
                        target_ordering=ordering or Ordering.UNKNOWN,
                        thread_role=role,
                        provenance={
                            "target_symbol": call.target_symbol,
                            "target_set_complete": call.targets.complete,
                            "target_evidence": list(call.targets.evidence),
                        },
                    )
                )
                if kind == EventKind.OPAQUE_CALL:
                    unknowns.append(
                        UnknownFact(
                            kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
                            reason=f"call {symbol!r} has no complete memory-effect summary",
                            impact="the call may read or write any shared object",
                            module=module.path,
                            pc=call.location.pc,
                            function=function_names.get(call.containing_function_pc),
                            details={"event_id": event_id},
                        )
                    )

        incomplete_call_pcs = {
            call.location.pc
            for call in control_flow.call_sites
            if not call.targets.complete
        }
        for site in control_flow.indirect_sites:
            if site.targets.complete or site.location.pc in incomplete_call_pcs:
                continue
            roles = roles_by_function.get(site.containing_function_pc or -1, set())
            if not roles:
                # 不可达函数中的间接站点不属于任何线程角色；为它造 unknown role
                # 会反过来污染所有共享对象。未知线程入口已有独立哨兵覆盖。
                continue
            for role in sorted(roles):
                event_id = f"{role}:0x{site.location.pc:x}:indirect"
                append_event(
                    MemoryEvent(
                        id=event_id,
                        module=module.path,
                        module_sha256=module.sha256,
                        pc=site.location.pc,
                        function_pc=site.containing_function_pc,
                        kind=EventKind.UNKNOWN_MEMORY_EFFECT,
                        address=AbstractAddress(kind=AddressKind.UNKNOWN),
                        thread_role=role,
                        provenance={
                            "control_flow": site.control_flow,
                            "target_set_complete": False,
                            "known_targets": [target.pc for target in site.targets.known_targets],
                        },
                    )
                )
                unknowns.append(
                    UnknownFact(
                        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
                        reason=site.targets.reason or "indirect jump target set is incomplete",
                        impact="unrecovered target code may access any shared object",
                        module=module.path,
                        pc=site.location.pc,
                        details={"event_id": event_id},
                    )
                )

        program_order = _program_order_edges(
            control_flow, block_events
        )
        unique_unknowns = {
            (item.kind, item.module, item.pc, item.reason, str(item.details)): item
            for item in unknowns
        }
        return MemoryEventReport(
            module_path=module.path,
            module_sha256=module.sha256,
            events=tuple(sorted(events, key=lambda item: (item.thread_role or "", item.pc, item.id))),
            program_order=program_order,
            unknowns=tuple(unique_unknowns.values()),
        )
    except Exception as error:
        unknown = UnknownFact(
            kind=UnknownKind.MEMORY_EVENT_RECOVERY_FAILURE,
            reason=str(error),
            impact="shared-memory effects are unavailable; later analysis must not use an empty slice",
            module=module.path,
        )
        sentinel = MemoryEvent(
            id="unknown:memory-event-recovery",
            module=module.path,
            module_sha256=module.sha256,
            pc=control_flow.entry_pc,
            kind=EventKind.UNKNOWN_MEMORY_EFFECT,
            address=AbstractAddress(kind=AddressKind.UNKNOWN),
            provenance={"failure": str(error)},
        )
        return MemoryEventReport(
            module_path=module.path,
            module_sha256=module.sha256,
            events=(sentinel,),
            unknowns=(unknown,),
        )


def _lifecycle_or_sync_kinds() -> set[EventKind]:
    return {
        EventKind.THREAD_CREATE,
        EventKind.THREAD_JOIN,
        EventKind.ACQUIRE,
        EventKind.RELEASE,
        EventKind.BARRIER,
    }


def _event_order_key(event: MemoryEvent) -> tuple[int, int, str]:
    call_boundary = event.kind in _lifecycle_or_sync_kinds() | {EventKind.OPAQUE_CALL}
    # call 的隐式 stack write 发生在进入 callee 前，生命周期/同步 effect 随后才成立。
    return event.pc, 1 if call_boundary else 0, event.id


def _program_order_edges(
    report: ControlFlowReport,
    block_events: dict[tuple[str, int], list[MemoryEvent]],
) -> tuple[ProgramOrderEdge, ...]:
    block_by_pc = {item.location.pc: item for item in report.basic_blocks}
    edges: dict[tuple[str, str, str], ProgramOrderEdge] = {}
    for (role, block_pc), events in block_events.items():
        ordered = sorted(events, key=_event_order_key)
        for first, second in zip(ordered, ordered[1:]):
            edge = ProgramOrderEdge(
                source_event=first.id,
                target_event=second.id,
                thread_role=role,
                evidence="instruction order inside one CFG block",
            )
            edges[(edge.source_event, edge.target_event, role)] = edge
        if not ordered:
            continue
        source = ordered[-1]
        pending: deque[int] = deque(block_by_pc.get(block_pc).successor_pcs if block_pc in block_by_pc else ())
        visited: set[int] = set()
        while pending:
            successor = pending.popleft()
            if successor in visited:
                continue
            visited.add(successor)
            next_events = block_events.get((role, successor), ())
            if next_events:
                target = min(next_events, key=_event_order_key)
                edge = ProgramOrderEdge(
                    source_event=source.id,
                    target_event=target.id,
                    thread_role=role,
                    evidence="CFG successor through zero or more empty blocks",
                )
                edges[(edge.source_event, edge.target_event, role)] = edge
                continue
            block = block_by_pc.get(successor)
            if block is not None:
                pending.extend(block.successor_pcs)
    return tuple(sorted(edges.values(), key=lambda item: (item.thread_role, item.source_event, item.target_event)))
