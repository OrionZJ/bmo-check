from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path

from bmo_check.binary.capstone_backend import collect_instruction_facts
from bmo_check.model import (
    AbstractAddress,
    AddressKind,
    CallKind,
    CallSite,
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

from .address_provenance import recover_address_provenance


_ACQUIRE_APIS = {"pthread_mutex_lock", "pthread_spin_lock"}
_RELEASE_APIS = {"pthread_mutex_unlock", "pthread_spin_unlock"}
_BARRIER_APIS = {"pthread_barrier_wait"}


def _ordering_covers(actual: Ordering, required: Ordering) -> bool:
    directions = {
        Ordering.RELAXED: frozenset(),
        Ordering.ACQUIRE: frozenset({"acquire"}),
        Ordering.RELEASE: frozenset({"release"}),
        Ordering.ACQ_REL: frozenset({"acquire", "release"}),
        Ordering.FULL: frozenset({"acquire", "release"}),
    }
    return required in directions and directions[required] <= directions.get(
        actual, frozenset()
    )


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


def _blocks_reaching_return(
    report: ControlFlowReport,
    facts: tuple[InstructionFact, ...],
) -> set[int]:
    """反向标记能到达 ret 的块；没有恢复完整返回路径时不作乐观判断。"""

    return_pcs = {
        fact.pc
        for fact in facts
        if fact.control_flow is not None and fact.control_flow.value == "return"
    }
    result: set[int] = set()
    blocks = {item.location.pc: item for item in report.basic_blocks}
    for function in report.functions:
        function_blocks = set(function.block_pcs)
        exits = {
            block_pc
            for block_pc in function_blocks
            if block_pc in blocks
            and any(pc in return_pcs for pc in blocks[block_pc].instruction_pcs)
        }
        # 没有 ret 也可能是 tail call 或 CFG 缺口；这种情况不删任何事件。
        if not exits:
            continue
        predecessors: dict[int, set[int]] = {}
        for block_pc in function_blocks:
            if block_pc not in blocks:
                continue
            for successor in blocks[block_pc].successor_pcs:
                if successor in function_blocks:
                    predecessors.setdefault(successor, set()).add(block_pc)
        pending = list(exits)
        while pending:
            block_pc = pending.pop()
            if block_pc in result:
                continue
            result.add(block_pc)
            pending.extend(predecessors.get(block_pc, ()))
    return result


def _functions_only_called_from_nonreturning_paths(
    report: ControlFlowReport,
    return_reachable_blocks: set[int],
    role_roots: set[int],
    role_reachable_functions: set[int],
) -> set[int]:
    """只有所有调用点都无法返回时，才把这个 callee 纳入失败路径。"""

    functions = {item.location.pc: item for item in report.functions}
    # 未闭合的应用间接调用可能绕过已知 call site 进入 callee。
    # PLT 桁只跳到依赖库 relocation，不会反向调用主 ELF 的本地函数。
    if any(
        not site.targets.complete
        and site.containing_function_pc in functions
        and site.containing_function_pc in role_reachable_functions
        and not functions[site.containing_function_pc].is_plt
        for site in report.indirect_sites
    ):
        return set()

    incoming: dict[int, list[CallSite]] = defaultdict(list)
    for call in report.call_sites:
        if len(call.targets.known_targets) != 1:
            continue
        target = call.targets.known_targets[0]
        if target.module_sha256 == report.module_sha256 and target.pc in functions:
            incoming[target.pc].append(call)

    result: set[int] = set()
    changed = True
    while changed:
        changed = False
        for function_pc, calls in incoming.items():
            if function_pc in result or function_pc in role_roots or not calls:
                continue
            if all(
                call.containing_function_pc in result
                or (
                    call.block_pc not in return_reachable_blocks
                    and call.containing_function_pc in functions
                    and functions[call.containing_function_pc].returning is not None
                )
                for call in calls
            ):
                result.add(function_pc)
                changed = True
    return result


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
) -> tuple[Ordering | None, str | None]:
    summaries = [
        summary
        for report in reports
        for summary in report.summaries
        if summary.api == symbol
    ]
    if not summaries:
        return None, "no concrete library summary was found"
    incomplete = [summary for summary in summaries if not summary.complete]
    if incomplete:
        reasons = sorted(
            {summary.reason or "return paths are incomplete" for summary in incomplete}
        )
        return None, "; ".join(reasons)
    weak = [
        summary
        for summary in summaries
        if not _ordering_covers(
            summary.target_ordering, summary.required_ordering
        )
    ]
    if weak:
        # API 名称只说明 source 需要什么。实际库路径达不到该强度时，
        # 后续层必须看到 Unknown，不能把“分析完整但过弱”当成同步边界。
        return None, "; ".join(
            sorted(
                {
                    f"target {summary.target_ordering.value} does not cover required "
                    f"{summary.required_ordering.value}"
                    for summary in weak
                }
            )
        )
    orderings = {summary.target_ordering for summary in summaries}
    if len(orderings) != 1:
        return None, "versioned implementations have different target orderings"
    return next(iter(orderings)), None


def _summary_provenance(
    symbol: str, reports: tuple[SynchronizationReport, ...]
) -> dict[str, object]:
    summaries = [
        summary
        for report in reports
        for summary in report.summaries
        if summary.api == symbol
    ]
    if not summaries:
        return {}
    return {
        "summary_required_orderings": sorted(
            {summary.required_ordering.value for summary in summaries}
        ),
        "summary_target_orderings": sorted(
            {summary.target_ordering.value for summary in summaries}
        ),
        "summary_complete": all(summary.complete for summary in summaries),
        "summary_evidence_pcs": sorted(
            {item.pc for summary in summaries for item in summary.evidence}
        ),
        "summary_issue_pcs": sorted(
            {
                int(match, 16)
                for summary in summaries
                for match in re.findall(r"0x[0-9a-fA-F]+", summary.reason or "")
            }
        ),
    }


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
    *,
    function_effects: dict[str, str] | None = None,
    function_integer_arguments: dict[str, tuple[int, ...]] | None = None,
    function_internal_objects: dict[str, str] | None = None,
    worker_argument_base: str | None = None,
) -> MemoryEventReport:
    try:
        if not control_flow.functions or not control_flow.basic_blocks:
            raise RuntimeError("CFG contains no recoverable functions or basic blocks")
        effect_contract = function_effects or {}
        integer_argument_contract = function_integer_arguments or {}
        internal_object_contract = function_internal_objects or {}
        instruction_report = collect_instruction_facts(module)
        return_reachable_blocks = _blocks_reaching_return(
            control_flow, instruction_report.facts
        )
        functions_with_return = {
            function.location.pc
            for function in control_flow.functions
            if any(block_pc in return_reachable_blocks for block_pc in function.block_pcs)
        }
        known_nonreturn_functions = {
            function.location.pc
            for function in control_flow.functions
            if function.returning is False
        }
        allocation_calls = {
            call.location.pc: call.target_symbol
            for call in control_flow.call_sites
            if call.target_symbol is not None
            and effect_contract.get(call.target_symbol) == "fresh_allocation"
        }
        base_address_provenance = recover_address_provenance(
            module, control_flow, instruction_report.facts, allocation_calls
        )
        role_functions = _role_functions(control_flow, threads)
        role_address_provenance = {}
        for role in threads.roles:
            function_entry_arguments: dict[int, dict[str, AbstractAddress]] = {}
            seeded_function_pcs: set[int] = set()
            if role.create_site is not None and len(role.start_targets.known_targets) == 1:
                worker_pc = role.start_targets.known_targets[0].pc
                seeded_function_pcs.add(worker_pc)
                call_arguments = base_address_provenance.call_arguments.get(
                    role.create_site.pc, ()
                )
                if len(call_arguments) > 3 and call_arguments[3] is not None:
                    function_entry_arguments[worker_pc] = {
                        "rdi": call_arguments[3]
                    }
                elif worker_argument_base is not None:
                    # lifecycle 已逐个记录 create 的第四实参并证明它们互异。
                    # 这里只恢复 worker 的入口对象，不猜测 main 栈布局。
                    function_entry_arguments[worker_pc] = {
                        "rdi": AbstractAddress(
                            kind=AddressKind.GLOBAL,
                            base=worker_argument_base,
                            provenance={
                                "base_indirect": False,
                                "scope": "symbolic-lifecycle",
                            },
                        )
                    }
            role_address_provenance[role.id] = recover_address_provenance(
                module,
                control_flow,
                instruction_report.facts,
                allocation_calls,
                function_entry_arguments,
                seeded_function_pcs,
                role_functions.get(role.id, set()),
            )
        instruction_to_block, block_to_function, function_names = _block_maps(
            control_flow
        )
        role_roots = {
            target.pc
            for role in threads.roles
            for target in role.start_targets.known_targets
            if target.module_sha256 == module.sha256
        }
        nonreturning_context_functions = (
            _functions_only_called_from_nonreturning_paths(
                control_flow,
                return_reachable_blocks,
                role_roots,
                set().union(*role_functions.values()),
            )
        )
        roles_by_function: dict[int, set[str]] = {}
        for role, functions in role_functions.items():
            for function_pc in functions:
                roles_by_function.setdefault(function_pc, set()).add(role)

        events: list[MemoryEvent] = []
        # InstructionModuleFacts 还包含不可达函数的解码缺口；这里只传播线程可达事实。
        unknowns: list[UnknownFact] = []
        block_events: dict[tuple[str, int], list[MemoryEvent]] = {}

        def append_event(event: MemoryEvent) -> None:
            if (
                event.function_pc in nonreturning_context_functions
                and event.function_pc not in role_roots
            ):
                # callee 自身虽能 ret，但它的所有调用点都位于失败分支。
                # 必须先于函数内的 ret 可达性判断，否则会把这种路径重新标为正常。
                event = event.model_copy(
                    update={
                        "provenance": {
                            **event.provenance,
                            "can_reach_function_return": False,
                        }
                    }
                )
            elif (
                event.function_pc in known_nonreturn_functions
                and event.function_pc not in role_roots
            ):
                # 这些 callee 的 CFG 已明确不返回。但线程入口可以
                # 通过 exit 正常结束进程，所以不能套用这条规则。
                event = event.model_copy(
                    update={
                        "provenance": {
                            **event.provenance,
                            "can_reach_function_return": False,
                        }
                    }
                )
            elif (
                event.block_pc is not None
                and event.function_pc in functions_with_return
            ):
                event = event.model_copy(
                    update={
                        "provenance": {
                            **event.provenance,
                            "can_reach_function_return": (
                                event.block_pc in return_reachable_blocks
                            ),
                        }
                    }
                )
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
            unknowns.extend(fact.unknowns)
            source_ordering, target_ordering = _event_ordering(fact)
            for role in sorted(roles):
                provenance_addresses = role_address_provenance[role].addresses
                for operand in fact.memory_operands:
                    address = provenance_addresses.get(
                        (fact.pc, operand.operand_index)
                    ) or _address(module, fact, operand, function_pc)
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
                        if address.kind == AddressKind.UNKNOWN:
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
            contracted_effect = effect_contract.get(symbol)
            ordering, summary_reason = _summary_ordering(symbol, synchronization)
            kind = _call_event_kind(symbol, ordering)
            for role in sorted(roles):
                role_call_arguments = role_address_provenance[
                    role
                ].call_arguments.get(
                    call.location.pc,
                    base_address_provenance.call_arguments.get(
                        call.location.pc, ()
                    ),
                )
                call_argument_details = [
                    item.model_dump(mode="json") if item is not None else None
                    for item in role_call_arguments
                ]
                event_id = f"{role}:0x{call.location.pc:x}:call"
                if contracted_effect == "thread_local":
                    # libm 可能更新 errno/fenv；把它保留为 TLS 读写，而不是假装无 effect。
                    # 后续只有在 TLS 地址没有逃逸时才能剪除这两个事件。
                    for suffix, effect_kind in (
                        ("tls-read", EventKind.LOAD),
                        ("tls-write", EventKind.STORE),
                    ):
                        append_event(
                            MemoryEvent(
                                id=f"{event_id}:{suffix}",
                                module=module.path,
                                module_sha256=module.sha256,
                                pc=call.location.pc,
                                block_pc=call.block_pc,
                                function=function_names.get(
                                    call.containing_function_pc
                                ),
                                function_pc=call.containing_function_pc,
                                kind=effect_kind,
                                address=AbstractAddress(
                                    kind=AddressKind.TLS,
                                    base=f"function-effect:{symbol}",
                                    offset=0,
                                    provenance={
                                        "contracted_effect": contracted_effect,
                                        "target_symbol": symbol,
                                    },
                                ),
                                source_ordering=Ordering.TSO,
                                target_ordering=Ordering.RELAXED,
                                thread_role=role,
                                provenance={
                                    "target_symbol": symbol,
                                    "contracted_effect": contracted_effect,
                                    "integer_arguments": list(
                                        integer_argument_contract.get(symbol, ())
                                    ),
                                },
                            )
                        )
                    continue
                internal_object = internal_object_contract.get(symbol)
                address = None
                if kind == EventKind.OPAQUE_CALL:
                    address = AbstractAddress(
                        kind=(
                            AddressKind.GLOBAL
                            if internal_object is not None
                            else AddressKind.UNKNOWN
                        ),
                        base=internal_object,
                        provenance={
                            "contracted_effect": contracted_effect,
                            "target_symbol": symbol,
                            "runtime_internal": internal_object is not None,
                        },
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
                            "contracted_effect": contracted_effect,
                            "integer_arguments": list(
                                integer_argument_contract.get(symbol, ())
                            ),
                            "call_arguments": call_argument_details,
                            "target_set_complete": call.targets.complete,
                            "target_evidence": list(call.targets.evidence),
                            "summary_reason": summary_reason,
                            **_summary_provenance(symbol, synchronization),
                        },
                    )
                )
                if kind == EventKind.OPAQUE_CALL:
                    unknowns.append(
                        UnknownFact(
                            kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
                            reason=(
                                f"call {symbol!r} has no usable memory-effect summary: "
                                f"{summary_reason or 'unknown reason'}"
                            ),
                            impact=(
                                f"the call may read or write runtime object {internal_object}"
                                if internal_object is not None
                                else "the call may read or write any shared object"
                            ),
                            module=module.path,
                            pc=call.location.pc,
                            function=function_names.get(call.containing_function_pc),
                            details={
                                "event_id": event_id,
                                "target_symbol": call.target_symbol,
                                "contracted_effect": contracted_effect,
                                "internal_object": internal_object,
                                "call_arguments": call_argument_details,
                            },
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
