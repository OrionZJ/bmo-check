from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bmo_check.model import (
    AbstractAddress,
    AddressKind,
    ControlFlowReport,
    InstructionFact,
    MemoryAccessKind,
    MemoryOperandFact,
    ModuleFingerprint,
)


_REGISTER_ROOTS = {
    name: root
    for root, aliases in {
        "rax": ("rax", "eax", "ax", "al", "ah"),
        "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
        "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
        "rdx": ("rdx", "edx", "dx", "dl", "dh"),
        "rsi": ("rsi", "esi", "si", "sil"),
        "rdi": ("rdi", "edi", "di", "dil"),
        "rbp": ("rbp", "ebp", "bp", "bpl"),
        "rsp": ("rsp", "esp", "sp", "spl"),
        **{
            f"r{index}": (
                f"r{index}",
                f"r{index}d",
                f"r{index}w",
                f"r{index}b",
            )
            for index in range(8, 16)
        },
    }.items()
    for name in aliases
}
_CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
_INTEGER_ARGUMENTS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


@dataclass(frozen=True)
class AddressProvenanceReport:
    # addresses 保存普通访存 operand 的对象与仿射来源。
    addresses: dict[tuple[int, int], AbstractAddress]
    # call_arguments 保存 call 前六个 SysV 整数参数的地址来源；None 表示无法恢复。
    call_arguments: dict[int, tuple[AbstractAddress | None, ...]]
    # published_globals 记录 pthread_create 前已稳定写入全局槽的指针。
    # worker 只能使用这些在所有 create 状态中都相同的值。
    published_globals: dict[str, AbstractAddress]


def _frame_key(function_pc: int, displacement: int) -> str:
    return f"frame-value@0x{function_pc:x}{displacement:+d}"


def _global_key(pc: int) -> str:
    return f"global-pointer@0x{pc:x}"


@dataclass(frozen=True)
class _SymbolicValue:
    # base 标识直接 global 地址或保存动态指针的 global slot。
    base: str | None = None
    # indirect=True 表示 base 的内容才是实际对象地址，不能按 ELF 对象直接 NoAlias。
    indirect: bool = False
    # term 标识仍未求值的栈变量或寄存器来源。
    term: str | None = None
    # coefficient 保存 term 对最终字节地址的线性系数。
    coefficient: int = 0
    # offset 保存已经折叠的常量字节偏移。
    offset: int = 0
    # evidence_pcs 记录这条值链依赖的机器指令。
    evidence_pcs: tuple[int, ...] = ()
    # object_kind 区分 allocation site 与普通 global pointer slot。
    object_kind: AddressKind | None = None


def _root(register: str | None) -> str | None:
    if register is None:
        return None
    return _REGISTER_ROOTS.get(register.lower(), register.lower())


def _global_name(module: ModuleFingerprint, pc: int) -> str:
    return f"{Path(module.path).name}@0x{pc:x}"


def _with_evidence(value: _SymbolicValue, pc: int) -> _SymbolicValue:
    return _SymbolicValue(
        base=value.base,
        indirect=value.indirect,
        term=value.term,
        coefficient=value.coefficient,
        offset=value.offset,
        evidence_pcs=tuple(dict.fromkeys((*value.evidence_pcs, pc))),
        object_kind=value.object_kind,
    )


def _scaled(value: _SymbolicValue, scale: int, pc: int) -> _SymbolicValue | None:
    # 对象基址不能参与乘法；出现这种运算时继续猜测会制造错误别名证明。
    if value.base is not None:
        return _with_evidence(value, pc) if scale == 1 else None
    return _SymbolicValue(
        term=value.term,
        coefficient=value.coefficient * scale,
        offset=value.offset * scale,
        evidence_pcs=tuple(dict.fromkeys((*value.evidence_pcs, pc))),
        object_kind=value.object_kind,
    )


def _added(
    left: _SymbolicValue, right: _SymbolicValue, pc: int
) -> _SymbolicValue | None:
    if left.base is not None and right.base is not None:
        return None
    if left.term is not None and right.term is not None and left.term != right.term:
        return None
    return _SymbolicValue(
        base=left.base or right.base,
        indirect=left.indirect if left.base is not None else right.indirect,
        term=left.term or right.term,
        coefficient=left.coefficient + right.coefficient,
        offset=left.offset + right.offset,
        evidence_pcs=tuple(
            dict.fromkeys((*left.evidence_pcs, *right.evidence_pcs, pc))
        ),
        object_kind=left.object_kind or right.object_kind,
    )


def _memory_value(
    module: ModuleFingerprint,
    fact: InstructionFact,
    operand: MemoryOperandFact,
    function_pc: int,
    state: dict[str, _SymbolicValue],
) -> _SymbolicValue | None:
    base = _root(operand.base)
    index = _root(operand.index)
    if base == "rip":
        target = fact.pc + len(fact.raw_bytes) // 2 + operand.displacement
        saved = state.get(_global_key(target))
        if saved is not None:
            return _with_evidence(saved, fact.pc)
        # 64 位 RIP-relative load 常用于读取 GOT/global pointer slot。
        # 这里只保留来源，不据此声明两个 slot 的内容 NoAlias。
        return _SymbolicValue(
            base=_global_name(module, target) if operand.size == 8 else None,
            indirect=operand.size == 8,
            term=None if operand.size == 8 else f"global-value@0x{target:x}",
            coefficient=0 if operand.size == 8 else 1,
            evidence_pcs=(fact.pc,),
        )
    if base in {"rsp", "rbp"} and index is None:
        saved = state.get(_frame_key(function_pc, operand.displacement))
        if saved is not None:
            return _with_evidence(saved, fact.pc)
        return _SymbolicValue(
            term=f"frame@0x{function_pc:x}{operand.displacement:+d}",
            coefficient=1,
            evidence_pcs=(fact.pc,),
        )
    value = state.get(base) if base is not None else _SymbolicValue()
    if value is None:
        return None
    if index is not None:
        index_value = state.get(index)
        if index_value is None:
            return None
        scaled = _scaled(index_value, operand.scale, fact.pc)
        if scaled is None:
            return None
        value = _added(value, scaled, fact.pc)
        if value is None:
            return None
    return _added(
        value,
        _SymbolicValue(offset=operand.displacement),
        fact.pc,
    )


def _source_value(
    module: ModuleFingerprint,
    fact: InstructionFact,
    function_pc: int,
    state: dict[str, _SymbolicValue],
    operand_index: int,
) -> _SymbolicValue | None:
    register = next(
        (
            item
            for item in fact.register_operands
            if item.operand_index == operand_index
        ),
        None,
    )
    if register is not None:
        value = state.get(_root(register.register_name) or "")
        return _with_evidence(value, fact.pc) if value is not None else None
    memory = next(
        (
            item
            for item in (*fact.memory_operands, *fact.address_operands)
            if item.operand_index == operand_index
        ),
        None,
    )
    if memory is not None:
        value = _memory_value(module, fact, memory, function_pc, state)
        if value is not None and memory.size < 8 and value.base is not None:
            # 32 位 load 从已知对象取出的是标量，不是该对象的地址。
            # 若继续携带 base，tid 等整数运算会被误当成指针运算。
            return _SymbolicValue(
                term=f"loaded-value@0x{fact.pc:x}",
                coefficient=1,
                evidence_pcs=tuple(
                    dict.fromkeys((*value.evidence_pcs, fact.pc))
                ),
            )
        if value is not None and memory.size == 8 and value.base is not None:
            base = _root(memory.base)
            saved_pointer = (
                base == "rip"
                and state.get(
                    _global_key(
                        fact.pc
                        + len(fact.raw_bytes) // 2
                        + memory.displacement
                    )
                )
                is not None
            ) or (
                base in {"rsp", "rbp"}
                and memory.index is None
                and state.get(
                    _frame_key(function_pc, memory.displacement)
                )
                is not None
            )
            if not saved_pointer:
                # 容器字段的地址不是字段中保存的指针。保留 load PC 作为
                # 新的 MayAlias 来源，后续 ownership 证明可再绑定其写入点。
                return _SymbolicValue(
                    base=f"loaded-pointer@0x{fact.pc:x}",
                    indirect=True,
                    evidence_pcs=tuple(
                        dict.fromkeys((*value.evidence_pcs, fact.pc))
                    ),
                )
        return value
    immediate = next(
        (
            item
            for item in fact.immediate_operands
            if item.operand_index == operand_index
        ),
        None,
    )
    if immediate is not None:
        return _SymbolicValue(offset=immediate.value, evidence_pcs=(fact.pc,))
    return None


def _abstract_value(value: _SymbolicValue | None) -> AbstractAddress | None:
    if value is None or value.base is None:
        return None
    expression = value.base
    if value.term is not None:
        expression += f"+({value.term})*{value.coefficient}"
    if value.offset:
        expression += f"{value.offset:+d}"
    if value.object_kind == AddressKind.HEAP and value.term is None:
        kind = AddressKind.HEAP
    elif not value.indirect and value.term is None:
        kind = AddressKind.GLOBAL
    else:
        kind = AddressKind.AFFINE
    return AbstractAddress(
        kind=kind,
        base=value.base,
        offset=value.offset,
        expression=expression,
        index_coefficient=(value.coefficient if value.term is not None else None),
        provenance={
            "pointer_slot": value.base,
            "base_indirect": value.indirect,
            "index_term": value.term,
            "evidence_pcs": list(value.evidence_pcs),
            "scope": "function-cfg",
        },
    )


def _symbolic_value(address: AbstractAddress) -> _SymbolicValue | None:
    if address.base is None:
        return None
    return _SymbolicValue(
        base=address.base,
        indirect=address.kind == AddressKind.AFFINE,
        term=(
            str(address.provenance["index_term"])
            if address.provenance.get("index_term") is not None
            else None
        ),
        coefficient=address.index_coefficient or 0,
        offset=address.offset or 0,
        evidence_pcs=tuple(
            int(item) for item in address.provenance.get("evidence_pcs", ())
        ),
        object_kind=(
            AddressKind.HEAP
            if address.kind == AddressKind.HEAP
            or address.base.startswith("heap:")
            else None
        ),
    )


def _transfer(
    module: ModuleFingerprint,
    fact: InstructionFact,
    function_pc: int,
    state: dict[str, _SymbolicValue],
    allocation_symbol: str | None = None,
) -> None:
    if fact.control_flow is not None and fact.control_flow.value.endswith("call"):
        for register in _CALLER_SAVED:
            state.pop(register, None)
        if allocation_symbol is not None:
            state["rax"] = _SymbolicValue(
                base=f"heap:{allocation_symbol}@0x{fact.pc:x}",
                indirect=False,
                evidence_pcs=(fact.pc,),
                object_kind=AddressKind.HEAP,
            )
        return
    writes = {
        _root(item.register_name)
        for item in fact.register_operands
        if item.access in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
    }
    writes.discard(None)
    frame_writes = [
        item
        for item in fact.memory_operands
        if item.access in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
        and _root(item.base) in {"rsp", "rbp"}
        and item.index is None
    ]
    for item in frame_writes:
        # 未建模的算术写会改变 spill/归纳变量。继续沿用旧值会把循环中的
        # 当前 i 误认成初始化 start，因此任何非简单 mov 都先杀死该槽。
        if fact.mnemonic not in {"mov", "movabs"} or item.operand_index != 0:
            state.pop(_frame_key(function_pc, item.displacement), None)
    destination = next(
        (
            _root(item.register_name)
            for item in fact.register_operands
            if item.operand_index == 0
            and item.access in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
        ),
        None,
    )
    value: _SymbolicValue | None = None
    if destination is not None and fact.mnemonic in {
        "mov",
        "movabs",
        "movsx",
        "movsxd",
        "movzx",
    }:
        value = _source_value(module, fact, function_pc, state, 1)
    elif destination is not None and fact.mnemonic == "lea" and fact.address_operands:
        value = _memory_value(
            module, fact, fact.address_operands[0], function_pc, state
        )
        if value is not None and _root(fact.address_operands[0].base) == "rip":
            value = _SymbolicValue(
                base=value.base,
                indirect=False,
                offset=value.offset,
                evidence_pcs=value.evidence_pcs,
            )
    elif destination is not None and fact.mnemonic in {"add", "sub"}:
        left = state.get(destination)
        right = _source_value(module, fact, function_pc, state, 1)
        if left is not None and right is not None:
            if fact.mnemonic == "sub":
                right = _scaled(right, -1, fact.pc)
            value = _added(left, right, fact.pc) if right is not None else None
    elif destination is not None and fact.mnemonic in {"shl", "sal"}:
        left = state.get(destination)
        immediate = next(iter(fact.immediate_operands), None)
        if left is not None and immediate is not None:
            value = _scaled(left, 1 << immediate.value, fact.pc)
    elif destination is not None and fact.mnemonic == "and":
        left = state.get(destination)
        immediate = next(iter(fact.immediate_operands), None)
        if (
            left is not None
            and left.object_kind == AddressKind.HEAP
            and immediate is not None
            and immediate.value < 0
        ):
            # 对齐只会在同一 malloc 对象内移动基址。精确 offset 丢失，
            # 但 allocation site 仍可用于排除与另一 malloc 返回对象别名。
            value = _SymbolicValue(
                base=left.base,
                indirect=left.indirect,
                term=left.term,
                coefficient=left.coefficient,
                evidence_pcs=tuple(
                    dict.fromkeys((*left.evidence_pcs, fact.pc))
                ),
                object_kind=left.object_kind,
            )
    elif destination is not None and fact.mnemonic == "imul":
        source = _source_value(module, fact, function_pc, state, 1)
        immediate = next(
            (item for item in fact.immediate_operands if item.operand_index == 2),
            None,
        )
        if source is not None and immediate is not None:
            value = _scaled(source, immediate.value, fact.pc)

    for register in writes:
        state.pop(register, None)
    if destination is not None and value is not None:
        state[destination] = _with_evidence(value, fact.pc)

    if fact.mnemonic in {"mov", "movabs"}:
        memory_destination = next(
            (
                item
                for item in fact.memory_operands
                if item.operand_index == 0
                and _root(item.base) in {"rsp", "rbp"}
                and item.index is None
            ),
            None,
        )
        if memory_destination is not None:
            key = _frame_key(function_pc, memory_destination.displacement)
            stored = _source_value(module, fact, function_pc, state, 1)
            if stored is None:
                state.pop(key, None)
            else:
                state[key] = stored
        global_destination = next(
            (
                item
                for item in fact.memory_operands
                if item.operand_index == 0 and _root(item.base) == "rip"
            ),
            None,
        )
        if global_destination is not None:
            target = fact.pc + len(fact.raw_bytes) // 2 + global_destination.displacement
            stored = _source_value(module, fact, function_pc, state, 1)
            key = _global_key(target)
            if stored is None:
                state.pop(key, None)
            else:
                if stored.object_kind == AddressKind.HEAP:
                    # global 槽保存的是已经算好的指针。它依赖 numOptions 的旧
                    # 算式不应在 worker 中再次当作循环下标；保留 allocation
                    # site 即可排除另一 malloc 对象，槽内偏移仍按 Unknown 合并。
                    stored = _SymbolicValue(
                        base=stored.base,
                        indirect=False,
                        evidence_pcs=stored.evidence_pcs,
                        object_kind=stored.object_kind,
                    )
                state[key] = stored


def recover_address_provenance(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    facts: tuple[InstructionFact, ...],
    allocation_calls: dict[int, str] | None = None,
    function_entry_arguments: dict[int, dict[str, AbstractAddress]] | None = None,
    seeded_function_pcs: set[int] | None = None,
    reachable_function_pcs: set[int] | None = None,
) -> AddressProvenanceReport:
    """在函数 CFG 上传播唯一地址值；路径合流不一致时退回 Unknown。"""

    allocation_calls = allocation_calls or {}
    function_entry_arguments = function_entry_arguments or {}
    seeded_function_pcs = seeded_function_pcs or set()
    facts_by_pc = {fact.pc: fact for fact in facts}
    blocks = {block.location.pc: block for block in control_flow.basic_blocks}
    functions = {function.location.pc: function for function in control_flow.functions}
    # main 和 worker 可以调用同一个 helper，但传入完全不同的对象。
    # 按 role 闭包过滤 call site，避免另一个线程角色的参数污染当前入口 meet。
    reachable_functions = (
        set(functions)
        if reachable_function_pcs is None
        else set(reachable_function_pcs) & functions.keys()
    )
    entry_values: dict[int, dict[str, _SymbolicValue]] = {
        function_pc: {
            register: value
            for register, address in registers.items()
            if (value := _symbolic_value(address)) is not None
        }
        for function_pc, registers in function_entry_arguments.items()
    }
    function_instruction_pcs = {
        function_pc: {
            pc
            for block_pc in function.block_pcs
            if block_pc in blocks
            for pc in blocks[block_pc].instruction_pcs
        }
        for function_pc, function in functions.items()
    }

    create_call_pcs = {
        call.location.pc
        for call in control_flow.call_sites
        if call.target_symbol == "pthread_create"
    }

    def flow(
        function_pc: int,
        seeded_globals: dict[str, _SymbolicValue] | None = None,
    ) -> tuple[
        dict[int, dict[str, _SymbolicValue]],
        bool,
        dict[str, _SymbolicValue],
    ]:
        function = functions[function_pc]
        local_allocation_bases = {
            f"heap:{symbol}@0x{call_pc:x}"
            for call_pc, symbol in allocation_calls.items()
            if call_pc in function_instruction_pcs.get(function_pc, set())
        }
        incoming: dict[int, dict[str, _SymbolicValue]] = {
            function_pc: {
                **(seeded_globals or {}),
                **entry_values.get(function_pc, {}),
            }
        }
        edge_states: dict[tuple[int, int], dict[str, _SymbolicValue]] = {}
        pending = [function_pc]
        while pending:
            block_pc = pending.pop()
            block = blocks.get(block_pc)
            if block is None:
                continue
            state = dict(incoming[block_pc])
            for pc in block.instruction_pcs:
                fact = facts_by_pc.get(pc)
                if fact is None:
                    state.clear()
                    continue
                _transfer(module, fact, function_pc, state, allocation_calls.get(pc))
            for successor in block.successor_pcs:
                if successor not in function.block_pcs:
                    continue
                edge_states[(block_pc, successor)] = dict(state)
                predecessor_states = [
                    edge_state
                    for (source, target), edge_state in edge_states.items()
                    if target == successor
                ]
                joined = dict(predecessor_states[0])
                for predecessor_state in predecessor_states[1:]:
                    joined = {
                        key: value
                        for key, value in joined.items()
                        if predecessor_state.get(key) == value
                    }
                previous = incoming.get(successor)
                if previous != joined:
                    incoming[successor] = joined
                    pending.append(successor)

        returns: list[_SymbolicValue | None] = []
        published = False
        create_globals: list[dict[str, _SymbolicValue]] = []
        for block_pc, entry_state in incoming.items():
            state = dict(entry_state)
            for pc in blocks[block_pc].instruction_pcs:
                fact = facts_by_pc.get(pc)
                if fact is None:
                    state.clear()
                    continue
                if fact.control_flow is not None and fact.control_flow.value.endswith("call"):
                    if fact.pc in create_call_pcs:
                        create_globals.append(
                            {
                                key: value
                                for key, value in state.items()
                                if key.startswith("global-pointer@")
                            }
                        )
                    if any(
                        state.get(register) is not None
                        and state[register].object_kind == AddressKind.HEAP
                        for register in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
                    ):
                        published = True
                if fact.mnemonic in {"mov", "movabs"}:
                    destination = next(
                        (item for item in fact.memory_operands if item.operand_index == 0),
                        None,
                    )
                    source = _source_value(module, fact, function_pc, state, 1)
                    if (
                        destination is not None
                        and _root(destination.base) not in {"rsp", "rbp"}
                        and source is not None
                        and source.object_kind == AddressKind.HEAP
                    ):
                        destination_value = _memory_value(
                            module,
                            fact,
                            destination,
                            function_pc,
                            state,
                        )
                        contained_in_fresh_graph = (
                            destination_value is not None
                            and destination_value.base
                            in local_allocation_bases
                            and source.base in local_allocation_bases
                        )
                        if not contained_in_fresh_graph:
                            published = True
                if fact.mnemonic == "ret":
                    returns.append(state.get("rax"))
                _transfer(module, fact, function_pc, state, allocation_calls.get(pc))
        fresh_return = bool(returns) and not published and all(
            value is not None
            and value.object_kind == AddressKind.HEAP
            and value.base in local_allocation_bases
            for value in returns
        )
        common_globals = (
            {
                key: value
                for key, value in create_globals[0].items()
                if all(item.get(key) == value for item in create_globals[1:])
            }
            if create_globals
            else {}
        )
        return incoming, fresh_return, common_globals

    internal_calls = {
        call.location.pc: call.targets.known_targets[0].pc
        for call in control_flow.call_sites
        if call.containing_function_pc in reachable_functions
        if len(call.targets.known_targets) == 1
        and call.targets.known_targets[0].module_sha256 == module.sha256
        and call.targets.known_targets[0].pc in reachable_functions
    }
    changed = True
    while changed:
        changed = False
        fresh_functions = {
            function_pc
            for function_pc in reachable_functions
            if function_pc in blocks and flow(function_pc)[1]
        }
        for call_pc, target_pc in internal_calls.items():
            if target_pc in fresh_functions and call_pc not in allocation_calls:
                allocation_calls[call_pc] = f"function@0x{target_pc:x}"
                changed = True

    published_globals: dict[str, _SymbolicValue] = {}
    for function_pc in {
        call.containing_function_pc
        for call in control_flow.call_sites
        if call.location.pc in create_call_pcs
    }:
        if function_pc in blocks:
            _, _, globals_at_create = flow(function_pc)
            published_globals.update(globals_at_create)

    internal_call_sites = {
        call.location.pc: call
        for call in control_flow.call_sites
        if call.location.pc in internal_calls
    }
    calls_by_target: dict[int, set[int]] = {}
    for call_pc, target_pc in internal_calls.items():
        calls_by_target.setdefault(target_pc, set()).add(call_pc)

    # worker 入口的指针已由 pthread_create 绑定，但它还会继续传给
    # 多层 helper。只有目标函数的每个已恢复 call site 都给出同一条
    # 地址来源时才写入口，路径分歧会自动退回 Unknown。
    propagated = True
    while propagated:
        propagated = False
        observed: dict[int, dict[str, _SymbolicValue]] = {}
        for function_pc in reachable_functions:
            if function_pc not in blocks:
                continue
            incoming, _, _ = flow(
                function_pc,
                published_globals if function_pc in seeded_function_pcs else None,
            )
            for block_pc, entry_state in incoming.items():
                state = dict(entry_state)
                for pc in blocks[block_pc].instruction_pcs:
                    fact = facts_by_pc.get(pc)
                    if fact is None:
                        state.clear()
                        continue
                    if pc in internal_call_sites:
                        observed[pc] = {
                            register: state[register]
                            for register in _INTEGER_ARGUMENTS
                            if register in state
                        }
                    _transfer(
                        module,
                        fact,
                        function_pc,
                        state,
                        allocation_calls.get(pc),
                    )
        for target_pc, call_pcs in calls_by_target.items():
            if not call_pcs <= observed.keys():
                continue
            target_values = entry_values.setdefault(target_pc, {})
            for register in _INTEGER_ARGUMENTS:
                values = [observed[pc].get(register) for pc in call_pcs]
                if any(value is None for value in values):
                    continue
                first = values[0]
                if first is None:
                    continue
                if any(value != first for value in values[1:]):
                    if not all(
                        value is not None
                        and value.object_kind == AddressKind.HEAP
                        for value in values
                    ):
                        continue
                    # 多个 call site 可以传入不同 malloc 对象。这里只保留
                    # “一定是 heap”，不声称这些 allocation site 彼此 NoAlias。
                    first = _SymbolicValue(
                        base=f"heap-union:argument@0x{target_pc:x}:{register}",
                        indirect=False,
                        evidence_pcs=tuple(
                            dict.fromkeys(
                                pc
                                for value in values
                                if value is not None
                                for pc in value.evidence_pcs
                            )
                        ),
                        object_kind=AddressKind.HEAP,
                    )
                if register not in target_values:
                    target_values[register] = first
                    propagated = True

    result: dict[tuple[int, int], AbstractAddress] = {}
    call_arguments: dict[int, tuple[AbstractAddress | None, ...]] = {}
    for function in control_flow.functions:
        if function.location.pc not in reachable_functions:
            continue
        if function.location.pc not in blocks:
            continue
        incoming, _, _ = flow(
            function.location.pc,
            published_globals
            if function.location.pc in seeded_function_pcs
            else None,
        )

        for block_pc, entry_state in incoming.items():
            block = blocks[block_pc]
            state = dict(entry_state)
            for pc in block.instruction_pcs:
                fact = facts_by_pc.get(pc)
                if fact is None:
                    state.clear()
                    continue
                if fact.control_flow is not None and fact.control_flow.value.endswith("call"):
                    call_arguments[pc] = tuple(
                        _abstract_value(state.get(register))
                        for register in _INTEGER_ARGUMENTS
                    )
                for operand in fact.memory_operands:
                    if _root(operand.base) in {"rip", "rsp", "rbp"} and operand.index is None:
                        continue
                    value = _memory_value(
                        module, fact, operand, function.location.pc, state
                    )
                    if (
                        value is None
                        or value.base is None
                    ):
                        continue
                    address = _abstract_value(value)
                    if address is not None:
                        result[(fact.pc, operand.operand_index)] = address
                _transfer(
                    module,
                    fact,
                    function.location.pc,
                    state,
                    allocation_calls.get(pc),
                )
    return AddressProvenanceReport(
        addresses=result,
        call_arguments=call_arguments,
        published_globals={
            key: address
            for key, value in published_globals.items()
            if (address := _abstract_value(value)) is not None
        },
    )


def recover_block_local_addresses(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    facts: tuple[InstructionFact, ...],
    allocation_calls: dict[int, str] | None = None,
) -> dict[tuple[int, int], AbstractAddress]:
    """保留旧入口；调用参数来源由完整 report 的调用方使用。"""

    return recover_address_provenance(
        module, control_flow, facts, allocation_calls
    ).addresses
