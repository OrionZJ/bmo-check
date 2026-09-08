from __future__ import annotations

from collections import defaultdict, deque

from capstone import CS_AC_WRITE
from capstone.x86 import X86_OP_MEM, X86_OP_REG

from bmo_check_static.analysis.escape_summary import prove_register_parameter_nocapture
from bmo_check_static.analysis.lifecycle_symbolic import SymbolicLifecycleProof
from bmo_check_static.analysis.partition_symbolic import SymbolicPartitionProof
from bmo_check_static.binary.angr_backend import AngrBackendError, load_cfg
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    CallSite,
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
from bmo_check_static.pruning import prove_affine_partition


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


def _register_names(instruction: object) -> list[str]:
    return [
        instruction.reg_name(operand.reg)
        for operand in instruction.operands
        if operand.type == X86_OP_REG
    ]


def _frame_stack_value_pcs(instructions: list[object]) -> set[int]:
    exempt: set[int] = set()
    for index, instruction in enumerate(instructions):
        names = _register_names(instruction)
        if instruction.mnemonic != "mov" or len(names) < 2 or names[1] != "rsp":
            continue

        # 编译器在 alloca/VLA 后读取 rsp，得到的是新分配区域的基址。
        # 该对象可能逃逸，但它不代表原有 rbp 固定栈槽一起逃逸。
        if index > 0:
            previous = instructions[index - 1]
            previous_names = _register_names(previous)
            if (
                int(previous.address) + int(previous.size) == int(instruction.address)
                and previous.mnemonic == "sub"
                and previous_names[:1] == ["rsp"]
            ):
                exempt.add(int(instruction.address))
                continue

        # 有些函数保存入口 rsp，退出前再恢复。只有保存寄存器在中间未被
        # 当作普通值使用时才认可该模式，防止漏掉真正传出的栈地址。
        if index + 1 >= len(instructions):
            continue
        copy = instructions[index + 1]
        copy_names = _register_names(copy)
        if (
            int(instruction.address) + int(instruction.size) != int(copy.address)
            or copy.mnemonic != "mov"
            or len(copy_names) < 2
            or copy_names[1] != names[0]
        ):
            continue
        saved = copy_names[0]
        for candidate in instructions[index + 2 :]:
            candidate_names = _register_names(candidate)
            if candidate.mnemonic == "mov" and candidate_names[:2] == ["rsp", saved]:
                exempt.add(int(instruction.address))
                exempt.add(int(candidate.address))
                break
            if saved in candidate_names:
                break
    return exempt


def _local_direct_call_does_not_capture(
    instructions: list[object],
    start_index: int,
    context: object,
    control_flow: ControlFlowReport,
    scalar_external_symbols: frozenset[str],
) -> tuple[bool, str | None]:
    instruction = instructions[start_index]
    operands = list(instruction.operands)
    if not operands or operands[0].type != X86_OP_REG:
        return False, None
    tainted = {instruction.reg_name(operands[0].reg)}
    calls = {item.location.pc: item for item in control_flow.call_sites}
    argument_registers = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    caller_saved = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
    tainted_stack_argument: int | None = None
    evidence: str | None = None
    for candidate in instructions[start_index + 1 :]:
        candidate_operands = list(candidate.operands)
        names = [
            candidate.reg_name(item.reg)
            for item in candidate_operands
            if item.type == X86_OP_REG
        ]
        if candidate.mnemonic == "mov" and len(names) >= 2:
            destination, source = names[0], names[1]
            tainted.discard(destination)
            if source in tainted:
                tainted.add(destination)
            continue
        if candidate.mnemonic == "push":
            if tainted_stack_argument is not None:
                tainted_stack_argument += 1
            if any(name in tainted for name in names):
                tainted_stack_argument = 6
            continue
        call_pc = context.to_elf_pc(candidate.address)
        call = calls.get(call_pc)
        if call is not None:
            tainted_arguments = [
                index for index, name in enumerate(argument_registers) if name in tainted
            ]
            if tainted_stack_argument is not None:
                tainted_arguments.append(tainted_stack_argument)
            if tainted_arguments:
                if call.kind.value != "direct" or len(call.targets.known_targets) != 1:
                    return False, None
                target = call.targets.known_targets[0]
                if target.module_sha256 != context.module.sha256:
                    return False, None
                results = [
                    prove_register_parameter_nocapture(
                        context,
                        control_flow,
                        target.pc,
                        argument_index,
                        scalar_external_symbols,
                    )
                    for argument_index in tainted_arguments
                ]
                if not all(result.proven for result in results):
                    failure = next(result for result in results if not result.proven)
                    return False, f"0x{call_pc:x}: {failure.evidence[0]}"
                evidence = (
                    f"0x{call_pc:x}: direct callee 0x{target.pc:x} does not capture "
                    f"argument(s) {','.join(str(item) for item in tainted_arguments)}"
                )
            else:
                evidence = None
            tainted.difference_update(caller_saved)
        if not tainted:
            return True, evidence
            continue
        memory_bases = {
            candidate.reg_name(item.mem.base)
            for item in candidate_operands
            if item.type == X86_OP_MEM and item.mem.base
        }
        used = set(names) & tainted
        if used - memory_bases:
            return False, None
        written = {
            candidate.reg_name(item.reg)
            for item in candidate_operands
            if item.type == X86_OP_REG and item.access & CS_AC_WRITE
        }
        tainted.difference_update(written)
        if not tainted:
            return True, "materialized stack address is overwritten before it can escape"
    if tainted.isdisjoint(caller_saved):
        # SysV 规定 callee-saved 寄存器在返回前恢复原值。若地址只剩在这类
        # 寄存器里，调用者拿不到它；把这种局部保存误报成 escape 会让整个
        # worker 的栈访问退回 wildcard。
        return True, "materialized stack address remains only in callee-saved registers"
    return False, None


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


def _addresses_may_alias(
    first: AbstractAddress, second: AbstractAddress
) -> bool:
    first_base = first.base
    second_base = second.base
    if first_base is None or second_base is None:
        return True
    if first_base.startswith("runtime:") or second_base.startswith("runtime:"):
        # runtime effect 契约把库的隐藏状态划入独立命名空间。
        # 它自身仍是 Unknown，但不能因此声称会覆盖主 ELF 的数组。
        return first_base == second_base
    first_candidates = {
        str(item)
        for item in first.provenance.get("candidate_bases", ())
        if isinstance(item, str) and not item.startswith("heap-union:")
    }
    second_candidates = {
        str(item)
        for item in second.provenance.get("candidate_bases", ())
        if isinstance(item, str) and not item.startswith("heap-union:")
    }
    if first_base.startswith("heap-union:") and first_candidates:
        if second_base.startswith("heap-union:") and second_candidates:
            # 两个 union 都保留了真实 allocation site；候选集合不相交时，
            # 它们不能指向同一个活跃对象。
            return bool(first_candidates & second_candidates)
        if second_base.startswith("heap:") or second.kind == AddressKind.HEAP:
            return second_base in first_candidates
    if second_base.startswith("heap-union:") and second_candidates:
        if first_base.startswith("heap:") or first.kind == AddressKind.HEAP:
            return first_base in second_candidates
    if first_base.startswith("heap-union:") or second_base.startswith("heap-union:"):
        # union 与任意 heap 仍可能重叠；它只能排除静态/global 对象。
        heap_prefixes = ("heap:", "heap-union:")
        return first_base.startswith(heap_prefixes) and second_base.startswith(
            heap_prefixes
        )
    if first_base.startswith("heap:") and second_base.startswith("heap:"):
        # fresh_allocation 契约让不同 call site 的返回对象在存活期内不重叠。
        return first_base == second_base
    if (
        first_base.startswith("heap:")
        and second.provenance.get("base_indirect") is False
    ):
        return False
    if (
        second_base.startswith("heap:")
        and first.provenance.get("base_indirect") is False
    ):
        return False
    if (
        first.provenance.get("base_indirect") is False
        and second.provenance.get("base_indirect") is False
    ):
        return first_base == second_base
    if first.kind == AddressKind.GLOBAL and second.kind == AddressKind.GLOBAL:
        return first_base == second_base
    return True


def _symbolic_partition_covers_event(
    proof: SymbolicPartitionProof,
    event: MemoryEvent,
    control_flow: ControlFlowReport,
) -> bool:
    address = event.address
    if (
        not proof.proven
        or address is None
        or event.function_pc != proof.worker_pc
        or address.base != proof.object_base
        or address.index_coefficient != proof.element_size
        or address.provenance.get("index_term") != proof.index_term
    ):
        return False

    function = next(
        (
            item
            for item in control_flow.functions
            if item.location.pc == proof.worker_pc
        ),
        None,
    )
    if function is None or proof.loop_pc not in function.block_pcs:
        return False
    blocks = {
        block.location.pc: block
        for block in control_flow.basic_blocks
        if block.location.pc in function.block_pcs
    }
    event_block = next(
        (
            block.location.pc
            for block in blocks.values()
            if block.location.pc <= event.pc < block.location.pc + block.size
        ),
        None,
    )
    if event_block is None:
        return False

    successors = {
        pc: set(block.successor_pcs) & blocks.keys()
        for pc, block in blocks.items()
    }
    predecessors: dict[int, set[int]] = defaultdict(set)
    for source, targets in successors.items():
        for target in targets:
            predecessors[target].add(source)

    def reachable(start: int, edges: dict[int, set[int]]) -> set[int]:
        visited: set[int] = set()
        pending = [start]
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            pending.extend(edges.get(current, ()))
        return visited

    # 只有既能从 header 到达、又能回到 header 的块才属于循环体。
    # 这样不会把退出块中已经等于 end 的归纳变量误当成分片下标。
    loop_blocks = reachable(proof.loop_pc, successors) & reachable(
        proof.loop_pc, predecessors
    )
    return event_block in loop_blocks


def _post_join_covers_pc(
    proof: SymbolicLifecycleProof,
    pc: int,
    control_flow: ControlFlowReport,
) -> bool:
    if not proof.proven:
        return False
    post_block = min(
        (
            block
            for block in control_flow.basic_blocks
            if block.location.pc <= proof.post_join_pc
            < block.location.pc + block.size
        ),
        key=lambda block: block.size,
        default=None,
    )
    event_block = min(
        (
            block
            for block in control_flow.basic_blocks
            if block.location.pc <= pc < block.location.pc + block.size
        ),
        key=lambda block: block.size,
        default=None,
    )
    if post_block is None or event_block is None:
        return False
    if post_block.location.pc == event_block.location.pc:
        # 同一 basic block 内的指令顺序已经闭合，不依赖 angr 是否把
        # 这个尾块重复挂进 FunctionFact。
        return pc >= proof.post_join_pc
    function = next(
        (
            item
            for item in control_flow.functions
            if post_block.location.pc in item.block_pcs
            and event_block.location.pc in item.block_pcs
        ),
        None,
    )
    if function is None:
        return False
    nodes = set(function.block_pcs)
    successors = {
        block.location.pc: set(block.successor_pcs) & nodes
        for block in control_flow.basic_blocks
        if block.location.pc in nodes
    }
    predecessors: dict[int, set[int]] = defaultdict(set)
    for source, targets in successors.items():
        for target in targets:
            predecessors[target].add(source)
    dominators = {pc: ({pc} if pc == function.location.pc else set(nodes)) for pc in nodes}
    changed = True
    while changed:
        changed = False
        for pc in nodes - {function.location.pc}:
            incoming = predecessors.get(pc, set())
            updated = {pc} | (
                set.intersection(*(dominators[item] for item in incoming))
                if incoming
                else set()
            )
            if updated != dominators[pc]:
                dominators[pc] = updated
                changed = True
    if post_block.location.pc not in dominators[event_block.location.pc]:
        return False
    pending = [post_block.location.pc]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if current == event_block.location.pc:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(successors.get(current, ()))
    return False


def _lifecycle_covers_event(
    proof: SymbolicLifecycleProof,
    event: MemoryEvent,
    control_flow: ControlFlowReport,
) -> bool:
    return event.thread_role == "main" and _post_join_covers_pc(
        proof, event.pc, control_flow
    )


def _stack_escape_by_function(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    relevant_functions: set[int],
    scalar_external_symbols: frozenset[str],
) -> tuple[
    dict[tuple[int, int | None], EscapeKind],
    dict[tuple[int, int | None], tuple[str, ...]],
    tuple[str, ...],
]:
    try:
        context = load_cfg(module)
    except AngrBackendError:
        return (
            {
                (item.location.pc, None): EscapeKind.UNKNOWN
                for item in control_flow.functions
            },
            {},
            ("CFG backend failed while checking TLS address materialization",),
        )
    escapes: dict[tuple[int, int | None], EscapeKind] = {}
    evidence_lists: dict[tuple[int, int | None], list[str]] = defaultdict(list)
    tls_escape_evidence: list[str] = []
    for function in control_flow.functions:
        if function.location.pc not in relevant_functions:
            continue
        function_instructions: list[object] = []
        blocks: list[tuple[int, object]] = []
        for block_pc in function.block_pcs:
            try:
                block = context.project.factory.block(context.to_rebased(block_pc))
            except Exception:
                evidence_lists[(function.location.pc, None)].append(
                    f"block 0x{block_pc:x} could not be inspected"
                )
                continue
            blocks.append((block_pc, block))
            function_instructions.extend(
                wrapped.insn for wrapped in block.capstone.insns
            )
        function_instructions.sort(key=lambda item: int(item.address))
        frame_stack_value_pcs = _frame_stack_value_pcs(function_instructions)
        for _, block in blocks:
            block_instructions = [wrapped.insn for wrapped in block.capstone.insns]
            for instruction_index, instruction in enumerate(block_instructions):
                operands = list(instruction.operands)
                for operand in operands:
                    if operand.type == X86_OP_MEM:
                        base = instruction.reg_name(operand.mem.base)
                        segment = instruction.reg_name(operand.mem.segment)
                        if base in {"rsp", "rbp"} and instruction.mnemonic == "lea":
                            destination = operands[0] if operands else None
                            destination_name = (
                                instruction.reg_name(destination.reg)
                                if destination is not None
                                and destination.type == X86_OP_REG
                                else None
                            )
                            if destination_name != "rsp":
                                key = (function.location.pc, int(operand.mem.disp))
                                no_capture, no_capture_evidence = (
                                    _local_direct_call_does_not_capture(
                                        block_instructions,
                                        instruction_index,
                                        context,
                                        control_flow,
                                        scalar_external_symbols,
                                    )
                                )
                                if not no_capture:
                                    evidence_lists[key].append(
                                        f"0x{context.to_elf_pc(instruction.address):x}: "
                                        "this stack slot address is materialized by lea"
                                        + (
                                            f"; nocapture stopped at {no_capture_evidence}"
                                            if no_capture_evidence
                                            else ""
                                        )
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
                        frame_stack_value = int(instruction.address) in frame_stack_value_pcs
                        frame_adjust_lea = (
                            op == "lea"
                            and names[:1] == ["rsp"]
                            and any(
                                item.type == X86_OP_MEM
                                and instruction.reg_name(item.mem.base) in {"rsp", "rbp"}
                                for item in operands
                            )
                        )
                        if not (
                            frame_setup
                            or stack_adjust
                            or frame_control
                            or frame_stack_value
                            or frame_adjust_lea
                        ):
                            evidence_lists[(function.location.pc, None)].append(
                                f"0x{context.to_elf_pc(instruction.address):x}: {register} used as a value by {op}"
                            )
    evidence = {
        key: tuple(sorted(set(reasons)))
        for key, reasons in evidence_lists.items()
    }
    escapes.update({key: EscapeKind.OPAQUE_ESCAPE for key in evidence})
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


def _cfg_path_exists(
    control_flow: ControlFlowReport,
    source_block: int,
    target_block: int,
) -> bool:
    successors = {
        block.location.pc: block.successor_pcs
        for block in control_flow.basic_blocks
    }
    pending = [source_block]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if current == target_block:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(successors.get(current, ()))
    return False


def _terminates_before_first_create(
    event: MemoryEvent,
    creates: list[MemoryEvent],
    control_flow: ControlFlowReport,
) -> bool:
    if event.thread_role != "main" or event.block_pc is None:
        return False
    function_pc = event.function_pc
    if function_pc is None or any(
        site.containing_function_pc == function_pc and not site.targets.complete
        for site in control_flow.indirect_sites
    ):
        return False
    relevant_creates = [
        create
        for create in creates
        if create.function_pc == function_pc and create.block_pc is not None
    ]
    if not relevant_creates:
        return False
    for create in relevant_creates:
        assert create.block_pc is not None
        if create.block_pc == event.block_pc and create.pc <= event.pc:
            return False
        if _cfg_path_exists(control_flow, create.block_pc, event.block_pc):
            return False
    # 没有 create 能到达该事件时，它只会发生在线程创建前或不可达分支。
    # 失败分支即使调用 I/O/exit，也不会与尚未存在的 worker 通信。
    return True


def _main_functions_outside_concurrent_phase(
    control_flow: ControlFlowReport,
    lifecycle_proof: SymbolicLifecycleProof | None,
) -> set[int]:
    if lifecycle_proof is None or not lifecycle_proof.proven:
        return set()
    main = next(
        (
            function.location.pc
            for function in control_flow.functions
            if function.location.symbol == "main"
        ),
        None,
    )
    if main is None:
        return set()
    local_calls = [
        call
        for call in control_flow.call_sites
        if len(call.targets.known_targets) == 1
        and call.targets.known_targets[0].module_sha256
        == control_flow.module_sha256
    ]
    graph: dict[int, set[int]] = defaultdict(set)
    for call in local_calls:
        graph[call.containing_function_pc].add(call.targets.known_targets[0].pc)
    main_reachable: set[int] = set()
    pending = [main]
    while pending:
        function_pc = pending.pop()
        if function_pc in main_reachable:
            continue
        main_reachable.add(function_pc)
        pending.extend(graph.get(function_pc, ()))

    create_sites = [
        call
        for call in control_flow.call_sites
        if call.target_symbol == "pthread_create"
        and call.containing_function_pc == main
    ]
    if not create_sites:
        return set()

    def main_site_is_nonconcurrent(call: CallSite) -> bool:
        if _post_join_covers_pc(
            lifecycle_proof, call.location.pc, control_flow
        ):
            return True
        for create in create_sites:
            if create.block_pc == call.block_pc:
                if create.location.pc <= call.location.pc:
                    return False
            elif _cfg_path_exists(
                control_flow, create.block_pc, call.block_pc
            ):
                return False
        return True

    calls_by_target: dict[int, list[CallSite]] = defaultdict(list)
    for call in local_calls:
        target_pc = call.targets.known_targets[0].pc
        if call.containing_function_pc in main_reachable:
            calls_by_target[target_pc].append(call)
    incomplete_callers = {
        site.containing_function_pc
        for site in control_flow.indirect_sites
        if not site.targets.complete
        and site.containing_function_pc in main_reachable
    }
    nonconcurrent: set[int] = set()
    changed = True
    while changed:
        changed = False
        for target_pc, sites in calls_by_target.items():
            if target_pc == main or target_pc in nonconcurrent:
                continue
            # 未闭合间接调用可能在并发阶段进入任意本地 callee。
            # 只要这种 caller 尚未被证明处于非并发阶段，就不能传播阶段标签。
            if any(
                caller not in nonconcurrent
                for caller in incomplete_callers
            ):
                continue
            if all(
                site.containing_function_pc in nonconcurrent
                or (
                    site.containing_function_pc == main
                    and main_site_is_nonconcurrent(site)
                )
                for site in sites
            ):
                nonconcurrent.add(target_pc)
                changed = True
    return nonconcurrent


def _readonly_after_create(
    grouped_events: tuple[MemoryEvent, ...],
    report: MemoryEventReport,
    nonconcurrent_event_ids: set[str] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    nonconcurrent_event_ids = nonconcurrent_event_ids or set()
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
        if event.id not in nonconcurrent_event_ids
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
    partition_proofs: tuple[SymbolicPartitionProof, ...] = (),
    lifecycle_proof: SymbolicLifecycleProof | None = None,
    normal_completion_only: bool = False,
) -> SharedStateReport:
    relevant_functions = {
        event.function_pc
        for event in memory_events.events
        if event.function_pc is not None
    }
    scalar_external_symbols = frozenset(
        str(event.provenance["target_symbol"])
        for event in memory_events.events
        if event.provenance.get("contracted_effect") == "thread_local"
        and event.provenance.get("integer_arguments") == []
        and isinstance(event.provenance.get("target_symbol"), str)
    )
    stack_escape, stack_evidence, tls_escape_evidence = _stack_escape_by_function(
        module, control_flow, relevant_functions, scalar_external_symbols
    )
    groups: dict[tuple[object, ...], list[MemoryEvent]] = defaultdict(list)
    for event in memory_events.events:
        if event.address is not None:
            groups[_object_key(event)].append(event)

    objects: list[SharedObject] = []
    proofs: list[ProofObject] = []
    removed: set[str] = set()
    unknowns: list[UnknownFact] = []
    creates = [
        event for event in memory_events.events if event.kind == EventKind.THREAD_CREATE
    ]
    order_edges: dict[str, set[str]] = defaultdict(set)
    for edge in memory_events.program_order:
        order_edges[edge.source_event].add(edge.target_event)
    after_join_ids = {
        event.id
        for event in memory_events.events
        if lifecycle_proof is not None
        and lifecycle_proof.proven
        and _lifecycle_covers_event(lifecycle_proof, event, control_flow)
    }
    before_create_ids = {
        event.id
        for event in memory_events.events
        if event.thread_role == "main"
        and creates
        and (
            all(_path_exists(order_edges, event.id, create.id) for create in creates)
            or _terminates_before_first_create(event, creates, control_flow)
        )
    }
    nonreturning_ids = {
        event.id
        for event in memory_events.events
        if normal_completion_only
        and event.provenance.get("can_reach_function_return") is False
    }
    main_nonconcurrent_functions = _main_functions_outside_concurrent_phase(
        control_flow, lifecycle_proof
    )
    main_callee_ids = {
        event.id
        for event in memory_events.events
        if event.thread_role == "main"
        and event.function_pc in main_nonconcurrent_functions
    }
    nonconcurrent_event_ids = (
        after_join_ids
        | before_create_ids
        | nonreturning_ids
        | main_callee_ids
    )
    wildcard_events = {
        event.id: event
        for event in memory_events.events
        if event.id not in nonconcurrent_event_ids
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

        external_wildcards = {
            event_id
            for event_id, wildcard in wildcard_events.items()
            if event_id not in {event.id for event in events}
            and wildcard.address is not None
            and _addresses_may_alias(address, wildcard.address)
        }
        if (
            roles == ("main",)
            and address.kind in {AddressKind.GLOBAL, AddressKind.AFFINE, AddressKind.HEAP}
            and not any(
                event.kind
                in {
                    EventKind.OPAQUE_CALL,
                    EventKind.SYSCALL,
                    EventKind.UNKNOWN_MEMORY_EFFECT,
                }
                for event in events
            )
            and not external_wildcards
        ):
            sharing = SharingClass.THREAD_LOCAL
            escape = EscapeKind.NO_ESCAPE
            proof = ProofObject(
                id=f"proof:main:{index}",
                reason=ProofReason.SINGLE_MAIN_ROLE,
                event_ids=tuple(event.id for event in events),
                supporting_facts=(
                    "only main reaches this object during the concurrent phase",
                    "every remaining wildcard has a checked NoAlias address base",
                ),
            )
        elif not writers and not external_wildcards:
            sharing = SharingClass.READ_ONLY_AFTER_CREATE
            escape = EscapeKind.THREAD_ESCAPE
            proof = ProofObject(
                id=f"proof:read-only:{index}",
                reason=ProofReason.READ_ONLY_AFTER_CREATE,
                event_ids=tuple(event.id for event in events),
                supporting_facts=(
                    "all concurrent accesses in this alias class are reads",
                    "every remaining writer has a checked NoAlias address base",
                ),
            )
        elif (
            lifecycle_proof is not None
            and lifecycle_proof.proven
            and lifecycle_proof.worker_argument_base is not None
            and address.base == lifecycle_proof.worker_argument_base
            and roles
            and "main" not in roles
        ):
            sharing = SharingClass.DISJOINT_PARTITION
            escape = EscapeKind.THREAD_ESCAPE
            proof = ProofObject(
                id=f"proof:worker-argument:{index}",
                reason=ProofReason.DISJOINT_AFFINE,
                event_ids=tuple(event.id for event in events),
                supporting_facts=lifecycle_proof.evidence
                + (
                    "each worker dereferences only its own fourth pthread_create argument",
                ),
            )
        elif (
            lifecycle_proof is not None
            and lifecycle_proof.proven
            and lifecycle_proof.worker_argument_base is not None
            and address.base == lifecycle_proof.worker_argument_base
            and writers
            and readers
            and all(event.thread_role == "main" for event in events if event.id in writers)
            and all(event.thread_role != "main" for event in events if event.id in readers)
            and all(
                _path_exists(order_edges, writer, create.id)
                for writer in writers
                for create in creates
            )
            and any(
                len(create.provenance.get("call_arguments", ())) > 3
                and create.provenance["call_arguments"][3] is not None
                and create.provenance["call_arguments"][3].get("base")
                == lifecycle_proof.worker_argument_base
                for create in creates
            )
        ):
            sharing = SharingClass.DISJOINT_PARTITION
            escape = EscapeKind.THREAD_ESCAPE
            proof = ProofObject(
                id=f"proof:thread-argument:{index}",
                reason=ProofReason.DISJOINT_AFFINE,
                event_ids=tuple(event.id for event in events),
                supporting_facts=lifecycle_proof.evidence
                + (
                    "each main write precedes the pthread_create that publishes its argument",
                    f"argument allocation site is {lifecycle_proof.worker_argument_base}",
                ),
            )
        elif (
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
        elif (
            address.kind == AddressKind.HEAP
            and isinstance(address.base, str)
            and address.base.startswith("heap:function@")
            and all(role != "main" for role in roles)
            and not external_wildcards
            and all(
                event.address is not None
                and event.address.provenance.get("base_indirect") is False
                for event in events
            )
        ):
            # 这个 allocation site 位于 worker 调用树内。malloc 每次调用
            # 返回新对象；只要地址没有经过未知存储逃逸，不同 worker 的
            # 同一 site 也不会指向同一活跃对象。
            sharing = SharingClass.THREAD_LOCAL
            escape = EscapeKind.NO_ESCAPE
            proof = ProofObject(
                id=f"proof:fresh-allocation:{index}",
                reason=ProofReason.FRESH_ALLOCATION,
                event_ids=tuple(event.id for event in events),
                supporting_facts=(
                    f"allocation site {address.base} is inside a worker call path",
                    "fresh_allocation contract gives every dynamic call a new object",
                    "all retained addresses use the direct allocation base",
                    "no unknown wildcard may alias this allocation site",
                ),
            )
        elif address.kind == AddressKind.STACK:
            function_pcs = {event.function_pc for event in events if event.function_pc is not None}
            escaping_keys = {
                (pc, offset)
                for pc in function_pcs
                for offset in (None, address.offset)
                if stack_escape.get((pc, offset))
                in {EscapeKind.OPAQUE_ESCAPE, EscapeKind.UNKNOWN}
            }
            if function_pcs and not escaping_keys:
                sharing = SharingClass.THREAD_LOCAL
                escape = EscapeKind.NO_ESCAPE
                proof = ProofObject(
                    id=f"proof:stack:{index}",
                    reason=ProofReason.UNESCAPED_STACK,
                    event_ids=tuple(event.id for event in events),
                    supporting_facts=tuple(
                        fact
                        for pc in sorted(function_pcs)
                        for fact in stack_evidence.get((pc, address.offset), ())
                        or (
                            "this slot is never materialized as an address",
                        )
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
                        details={
                            "event_ids": [event.id for event in events],
                            "escape_evidence": [
                                fact
                                for key in sorted(
                                    escaping_keys,
                                    key=lambda item: (item[0], item[1] is not None, item[1] or 0),
                                )
                                for fact in stack_evidence.get(key, ())
                            ],
                        },
                    )
                )
        elif address.kind == AddressKind.GLOBAL:
            escape = EscapeKind.THREAD_ESCAPE if len(roles) > 1 else EscapeKind.NO_ESCAPE
            readonly, evidence = _readonly_after_create(
                events, memory_events, nonconcurrent_event_ids
            )
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
            # main 在 create 前或 join 后访问同一数组时已经被生命周期证明
            # 移出并发阶段。它们不能阻止 worker 循环的分片证明匹配，
            # 否则一个对象会把两个不同的 PC/栈槽混成未闭合的 Unknown。
            concurrent_events = tuple(
                event
                for event in events
                if event.id not in nonconcurrent_event_ids
            )
            fresh_worker_allocation = (
                isinstance(address.base, str)
                and address.base.startswith("heap:function@")
                and bool(concurrent_events)
                and all(
                    event.thread_role not in {None, "main"}
                    and event.address is not None
                    and event.address.provenance.get("base_indirect") is False
                    for event in concurrent_events
                )
                and not external_wildcards
            )
            symbolic_proof = (
                next(
                    (
                        item
                        for item in partition_proofs
                        if all(
                            _symbolic_partition_covers_event(
                                item, event, control_flow
                            )
                            for event in concurrent_events
                        )
                    ),
                    None,
                )
                if concurrent_events
                else None
            )
            if symbolic_proof is not None:
                disjoint = True
                evidence = symbolic_proof.evidence + (
                    f"proof applies to {symbolic_proof.object_base}",
                    f"index term {symbolic_proof.index_term} has stride "
                    f"{symbolic_proof.element_size}",
                )
            uncovered_wildcards = external_wildcards
            if symbolic_proof is not None:
                # 同一循环的不同字段会被分到多个 alias group。
                # Z3 已证明整个 item 区间按线程不重叠，这些组不应再互相当 wildcard。
                uncovered_wildcards = {
                    event_id
                    for event_id in external_wildcards
                    if not _symbolic_partition_covers_event(
                        symbolic_proof,
                        wildcard_events[event_id],
                        control_flow,
                    )
                }
            if fresh_worker_allocation:
                sharing = SharingClass.THREAD_LOCAL
                escape = EscapeKind.NO_ESCAPE
                proof = ProofObject(
                    id=f"proof:fresh-affine-allocation:{index}",
                    reason=ProofReason.FRESH_ALLOCATION,
                    event_ids=tuple(event.id for event in events),
                    supporting_facts=(
                        f"allocation site {address.base} is reached only by worker instances",
                        "fresh_allocation call results are distinct while alive",
                        "all concurrent addresses retain the direct allocation base",
                        "no unknown wildcard may alias this allocation site",
                    ),
                )
            elif disjoint and writers and not uncovered_wildcards:
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
                        details={
                            "event_ids": [event.id for event in events],
                            # 证书必须指出是哪条未闭合访问阻止了当前对象证明，
                            # 否则地址恢复变精确后仍无法判断下一步该收敛哪条数据流。
                            "uncovered_wildcard_event_ids": sorted(
                                uncovered_wildcards
                            ),
                            "event_contexts": [
                                {
                                    "id": event.id,
                                    "pc": event.pc,
                                    "function": event.function,
                                    "function_pc": event.function_pc,
                                    "role": event.thread_role,
                                    "kind": event.kind.value,
                                }
                                for event in events
                            ],
                            "address": address.model_dump(mode="json"),
                        },
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
    if nonreturning_ids:
        proofs.append(
            ProofObject(
                id="proof:non-returning-path",
                reason=ProofReason.NON_RETURNING_PATH,
                event_ids=tuple(sorted(nonreturning_ids)),
                supporting_facts=(
                    "the certificate scope is restricted to normally returning executions",
                    "each removed block cannot reach a recovered return in its function CFG",
                ),
            )
        )
        removed.update(nonreturning_ids)
    if lifecycle_proof is not None and lifecycle_proof.proven:
        after_join = tuple(
            sorted(event_id for event_id in after_join_ids if event_id not in removed)
        )
        if after_join:
            proofs.append(
                ProofObject(
                    id="proof:sequential-after-join",
                    reason=ProofReason.SEQUENTIAL_AFTER_JOIN,
                    event_ids=after_join,
                    supporting_facts=lifecycle_proof.evidence,
                )
            )
            removed.update(after_join)
        main_callees = tuple(
            sorted(
                event_id
                for event_id in main_callee_ids
                if event_id not in removed
            )
        )
        if main_callees:
            proofs.append(
                ProofObject(
                    id="proof:sequential-main-callees",
                    reason=ProofReason.SEQUENTIAL_MAIN_CALLEE,
                    event_ids=main_callees,
                    supporting_facts=lifecycle_proof.evidence
                    + (
                        "every direct main call path enters these functions before create or after join",
                        "worker-role events for the same functions remain in the shared slice",
                    ),
                )
            )
            removed.update(main_callees)
    if creates:
        sequential = tuple(
            sorted(event_id for event_id in before_create_ids if event_id not in removed)
        )
        if sequential:
            proofs.append(
                ProofObject(
                    id="proof:sequential-before-create",
                    reason=ProofReason.SEQUENTIAL_BEFORE_CREATE,
                    event_ids=sequential,
                    supporting_facts=(
                        "each event either precedes every create or lies on a branch no create can reach",
                        "no worker thread exists before its pthread_create call",
                    ),
                )
            )
            removed.update(sequential)
    kept = tuple(sorted(event_ids - removed))
    return SharedStateReport(
        objects=tuple(objects),
        kept_event_ids=kept,
        removed_event_ids=tuple(sorted(removed)),
        proofs=tuple(proofs),
        unknowns=tuple(unknowns),
    )
