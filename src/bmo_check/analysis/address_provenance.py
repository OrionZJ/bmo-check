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
    )


def _scaled(value: _SymbolicValue, scale: int, pc: int) -> _SymbolicValue | None:
    # 对象基址不能参与乘法；出现这种运算时继续猜测会制造错误别名证明。
    if value.base is not None:
        return None
    return _SymbolicValue(
        term=value.term,
        coefficient=value.coefficient * scale,
        offset=value.offset * scale,
        evidence_pcs=tuple(dict.fromkeys((*value.evidence_pcs, pc))),
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
        # 64 位 RIP-relative load 常用于读取 GOT/global pointer slot。
        # 这里只保留来源，不据此声明两个 slot 的内容 NoAlias。
        return _SymbolicValue(
            base=_global_name(module, target),
            indirect=operand.size == 8,
            term=None if operand.size == 8 else f"global-value@0x{target:x}",
            coefficient=0 if operand.size == 8 else 1,
            evidence_pcs=(fact.pc,),
        )
    if base in {"rsp", "rbp"} and index is None:
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
        return _memory_value(module, fact, memory, function_pc, state)
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


def _transfer(
    module: ModuleFingerprint,
    fact: InstructionFact,
    function_pc: int,
    state: dict[str, _SymbolicValue],
) -> None:
    writes = {
        _root(item.register_name)
        for item in fact.register_operands
        if item.access in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
    }
    writes.discard(None)
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


def recover_block_local_addresses(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    facts: tuple[InstructionFact, ...],
) -> dict[tuple[int, int], AbstractAddress]:
    """只接受块内唯一 reaching definition；跨块值保持 Unknown。"""

    facts_by_pc = {fact.pc: fact for fact in facts}
    block_function = {
        block_pc: function.location.pc
        for function in control_flow.functions
        for block_pc in function.block_pcs
    }
    result: dict[tuple[int, int], AbstractAddress] = {}
    for block in control_flow.basic_blocks:
        function_pc = block_function.get(block.location.pc)
        if function_pc is None:
            continue
        state: dict[str, _SymbolicValue] = {}
        for pc in block.instruction_pcs:
            fact = facts_by_pc.get(pc)
            if fact is None:
                state.clear()
                continue
            for operand in fact.memory_operands:
                if _root(operand.base) in {"rip", "rsp", "rbp"} and operand.index is None:
                    # 直接 global/stack operand 已由基础分类器精确表示。
                    # provenance 只接管寄存器中转后的动态对象地址。
                    continue
                value = _memory_value(module, fact, operand, function_pc, state)
                if value is None or value.base is None or not value.indirect:
                    continue
                expression = value.base
                if value.term is not None:
                    expression += f"+({value.term})*{value.coefficient}"
                if value.offset:
                    expression += f"{value.offset:+d}"
                result[(fact.pc, operand.operand_index)] = AbstractAddress(
                    kind=AddressKind.AFFINE,
                    base=value.base,
                    offset=value.offset,
                    expression=expression,
                    index_coefficient=(
                        value.coefficient if value.term is not None else None
                    ),
                    provenance={
                        "pointer_slot": value.base,
                        "index_term": value.term,
                        "evidence_pcs": list(value.evidence_pcs),
                        "scope": "basic-block",
                    },
                )
            _transfer(module, fact, function_pc, state)
    return result
