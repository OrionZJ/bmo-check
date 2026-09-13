"""从普通 SysV 调用边传播 pthread/OpenMP callback 的代码指针。

生成的测试 harness 往往把 callback 先交给一个 wrapper，再由 wrapper
转发给 ``pthread_create``。这里的值传播只接受能从本 ELF 机器码和 loader
内容闭合的指针；遇到可写槽、未知间接调用或未覆盖的路径仍返回不完整集合。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from bmo_check_static.model import (
    CallSite,
    ControlFlowReport,
    IndirectTargetSet,
    ModuleFingerprint,
)
from bmo_check_static.binary.elf import executable_segments


_ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_CALLER_SAVED = {
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
}
_VECTOR_REGISTERS = frozenset({f"xmm{index}" for index in range(16)})
_MAX_RECURSION = 12


@dataclass(frozen=True, slots=True)
class CallbackResolution:
    """一个 callback 参数的闭合集合或明确的不完整结果。"""

    # targets 是已经落入主 ELF 可执行段的函数 PC；重复值在这里合并。
    targets: tuple[int, ...] = ()
    # complete 只有在所有可达调用点和参数路径都被闭合时才为真。
    complete: bool = False
    # origin 说明值经过了哪些机器码边界，供 ThreadRole 报告解释。
    origin: str | None = None
    # reason 描述不能继续证明的具体边界，而不是把它伪装成空集合。
    reason: str | None = None
    # contexts 记录每个 callback 是由哪个本 ELF caller 传入 wrapper。
    # 父线程角色需要这条上下文边，不能只看 pthread_create 所在 wrapper。
    contexts: tuple[tuple[int, int], ...] = ()
    # call_contexts 在旧的 caller/function 对之外保留实际传参 call site。
    # 同一个 wrapper 被多个调用点复用时，后续生命周期分析不能把这些路径合并。
    call_contexts: tuple[tuple[int, int, int | None], ...] = ()
    # locations 是已闭合的栈槽身份；pthread_t 句柄和 callback 参数共用这套传播。
    locations: tuple[str, ...] = ()
    # location_contexts 把栈槽绑定到传参 caller/call site，避免不同调用点的同偏移混淆。
    location_contexts: tuple[tuple[str, int, int | None], ...] = ()


@dataclass(frozen=True, slots=True)
class _Token:
    # kind=pc 表示已解析的 ELF 函数地址，kind=param 表示当前函数形参。
    kind: str
    # value 是函数 PC 或 SysV 整数形参下标。
    value: int
    # stack token 用 base 保存 rsp/rbp；其它 token 不需要该字段。
    base: str | None = None


_Value = frozenset[_Token] | None
_VectorValue = tuple[_Value, _Value]


def _root(register: str | None) -> str | None:
    if register is None:
        return None
    register = register.lower()
    aliases = {
        "eax": "rax",
        "ax": "rax",
        "al": "rax",
        "ah": "rax",
        "ebx": "rbx",
        "bx": "rbx",
        "bl": "rbx",
        "bh": "rbx",
        "ecx": "rcx",
        "cx": "rcx",
        "cl": "rcx",
        "ch": "rcx",
        "edx": "rdx",
        "dx": "rdx",
        "dl": "rdx",
        "dh": "rdx",
        "esi": "rsi",
        "si": "rsi",
        "sil": "rsi",
        "edi": "rdi",
        "di": "rdi",
        "dil": "rdi",
        "ebp": "rbp",
        "bp": "rbp",
        "bpl": "rbp",
        "esp": "rsp",
        "sp": "rsp",
        "spl": "rsp",
    }
    return aliases.get(register, register)


def _is_vector(register: str | None) -> bool:
    return register is not None and register.lower() in _VECTOR_REGISTERS


def _entry_block(control_flow: ControlFlowReport, function_pc: int) -> int | None:
    function = next(
        (item for item in control_flow.functions if item.location.pc == function_pc),
        None,
    )
    if function is None:
        return None
    if function_pc in function.block_pcs:
        return function_pc
    return min(function.block_pcs) if function.block_pcs else None


def _block_instructions(context: object, block_pc: int, call_pc: int) -> tuple[object, ...]:
    try:
        block = context.project.factory.block(context.to_rebased(block_pc))
        return tuple(
            item.insn
            for item in block.capstone.insns
            if context.to_elf_pc(item.insn.address) < call_pc
        )
    except Exception:
        return ()


def _function_instructions(
    context: object,
    control_flow: ControlFlowReport,
    function_pc: int,
    call_pc: int,
) -> tuple[object, ...]:
    """按地址收集调用者函数在目标 call 前的指令。"""

    function = next(
        (item for item in control_flow.functions if item.location.pc == function_pc),
        None,
    )
    if function is None:
        return ()
    instructions: list[object] = []
    for block_pc in function.block_pcs:
        instructions.extend(_block_instructions(context, block_pc, call_pc))
    return tuple(
        sorted(
            {
                int(context.to_elf_pc(instruction.address)): instruction
                for instruction in instructions
            }.values(),
            key=lambda instruction: int(context.to_elf_pc(instruction.address)),
        )
    )


def _pc_token(context: object, module: ModuleFingerprint, value: int) -> _Token | None:
    try:
        pc = context.to_elf_pc(int(value))
        if any(
            segment.virtual_address <= pc < segment.virtual_address + len(segment.data)
            for segment in executable_segments(Path(module.path))
        ):
            return _Token("pc", pc)
    except Exception:
        return None
    return None


def _effective_address(context: object, instruction: object, operand: object) -> int | None:
    if operand.type != X86_OP_MEM:
        return None
    if instruction.reg_name(operand.mem.base) != "rip" or operand.mem.index != 0:
        return None
    return int(instruction.address + instruction.size + operand.mem.disp)


def _load_static_pointer(
    context: object,
    module: ModuleFingerprint,
    instruction: object,
    operand: object,
) -> _Value:
    address = _effective_address(context, instruction, operand)
    if address is None:
        return None
    try:
        width = int(operand.size) or 8
        raw = context.project.loader.memory.load(address, width)
        value = int.from_bytes(bytes(raw), "little", signed=False)
    except Exception:
        return None
    token = _pc_token(context, module, value)
    return frozenset((token,)) if token is not None else frozenset()


def _lea_pointer(
    context: object,
    module: ModuleFingerprint,
    instruction: object,
    operand: object,
) -> _Value:
    address = _effective_address(context, instruction, operand)
    if address is None:
        return None
    token = _pc_token(context, module, address)
    return frozenset((token,)) if token is not None else frozenset()


def _stack_pointer(instruction: object, operand: object) -> _Value:
    """把栈上的地址保留为槽位身份，而不是把它误判成未知整数。"""

    if operand.type != X86_OP_MEM:
        return None
    base = instruction.reg_name(operand.mem.base)
    if base not in {"rsp", "rbp"} or operand.mem.index != 0:
        return None
    return frozenset((_Token("stack", int(operand.mem.disp), base),))


def _memory_key(instruction: object, operand: object) -> tuple[str, int] | None:
    if operand.type != X86_OP_MEM:
        return None
    base = instruction.reg_name(operand.mem.base)
    if base not in {"rsp", "rbp"} or operand.mem.index != 0:
        return None
    return base, int(operand.mem.disp)


def _value_from_operand(
    context: object,
    module: ModuleFingerprint,
    instruction: object,
    operand: object,
    registers: dict[str, _Value],
    vectors: dict[str, _VectorValue],
    stack: dict[tuple[str, int], _VectorValue],
) -> _Value:
    if operand.type == X86_OP_IMM:
        token = _pc_token(context, module, int(operand.imm))
        return frozenset((token,)) if token is not None else frozenset()
    if operand.type == X86_OP_REG:
        register = instruction.reg_name(operand.reg)
        if _is_vector(register):
            return vectors.get(register, (None, None))[0]
        return registers.get(_root(register) or "")
    if operand.type != X86_OP_MEM:
        return None
    if instruction.reg_name(operand.mem.base) == "rip":
        return _load_static_pointer(context, module, instruction, operand)
    base_register = instruction.reg_name(operand.mem.base)
    if base_register not in {"rsp", "rbp"}:
        # join wrapper 常执行 mov rdi,[rdi]。这里保留“形参指向的槽位”
        # 而不是把一次未建模的间接内存读取伪装成普通 callback 值。
        base_value = registers.get(_root(base_register) or "")
        if base_value:
            dereferenced = {
                _Token("param_deref", token.value)
                for token in base_value
                if token.kind == "param"
            }
            if dereferenced:
                return frozenset(dereferenced)
    key = _memory_key(instruction, operand)
    if key is None:
        return None
    base, displacement = key
    exact = stack.get(key)
    if exact is not None:
        return exact[0]
    # movaps/movdqa 常把两个 callback 指针一次写入 16 字节栈槽；
    # 后续按 +8 读取时仍应取第二个 lane，而不是把整个槽判成 Unknown。
    for (stored_base, stored_offset), lanes in stack.items():
        if stored_base != base or not stored_offset <= displacement < stored_offset + 16:
            continue
        lane = 1 if displacement - stored_offset >= 8 else 0
        return lanes[lane]
    return None


def _vector_from_operand(
    context: object,
    module: ModuleFingerprint,
    instruction: object,
    operand: object,
    registers: dict[str, _Value],
    vectors: dict[str, _VectorValue],
    stack: dict[tuple[str, int], _VectorValue],
) -> _VectorValue:
    """读取 128 位 callback 表时保留两个 64 位 lane。"""

    if operand.type == X86_OP_REG:
        register = instruction.reg_name(operand.reg)
        if _is_vector(register):
            return vectors.get(register, (None, None))
    if operand.type == X86_OP_MEM:
        key = _memory_key(instruction, operand)
        if key is not None:
            exact = stack.get(key)
            if exact is not None:
                return exact
            base, displacement = key
            for (stored_base, stored_offset), lanes in stack.items():
                if (
                    stored_base == base
                    and stored_offset <= displacement < stored_offset + 16
                ):
                    lane = 1 if displacement - stored_offset >= 8 else 0
                    return (lanes[lane], None)
        if int(getattr(operand, "size", 0) or 0) >= 16:
            address = _effective_address(context, instruction, operand)
            if address is not None:
                lanes: list[_Value] = []
                for lane in (0, 1):
                    try:
                        raw = context.project.loader.memory.load(address + lane * 8, 8)
                        value = int.from_bytes(bytes(raw), "little", signed=False)
                    except Exception:
                        return (None, None)
                    token = _pc_token(context, module, value)
                    lanes.append(frozenset((token,)) if token is not None else frozenset())
                return lanes[0], lanes[1]
    return (
        _value_from_operand(
            context, module, instruction, operand, registers, vectors, stack
        ),
        None,
    )


def _set_destination(
    instruction: object,
    source: object | None,
    value: _Value,
    registers: dict[str, _Value],
    vectors: dict[str, _VectorValue],
    stack: dict[tuple[str, int], _VectorValue],
) -> None:
    if not instruction.operands:
        return
    destination = instruction.operands[0]
    if destination.type == X86_OP_REG:
        register = instruction.reg_name(destination.reg)
        if _is_vector(register):
            source_register = (
                instruction.reg_name(source.reg)
                if source is not None and source.type == X86_OP_REG
                else None
            )
            if source_register is not None and _is_vector(source_register):
                vectors[register] = vectors.get(source_register, (None, None))
            else:
                vectors[register] = (value, None)
            return
        root = _root(register)
        if root is not None:
            registers[root] = value
        return
    key = _memory_key(instruction, destination)
    if key is None:
        return
    source_register = (
        instruction.reg_name(source.reg)
        if source is not None and source.type == X86_OP_REG
        else None
    )
    if source_register is not None and _is_vector(source_register):
        vectors_value = vectors.get(source_register, (None, None))
        stack[key] = vectors_value
    else:
        stack[key] = (value, None)


def _kill_callers(registers: dict[str, _Value], vectors: dict[str, _VectorValue]) -> None:
    for register in _CALLER_SAVED:
        registers.pop(register, None)
    for register in _VECTOR_REGISTERS:
        vectors.pop(register, None)


def _local_argument_value(
    context: object,
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    call: CallSite,
    register: str,
) -> tuple[_Value, str | None, bool]:
    """提取调用前某个具体寄存器；单独保留 wanted 避免误读其它定义。"""

    instructions = _function_instructions(
        context, control_flow, call.containing_function_pc, call.location.pc
    )
    if not instructions:
        return None, None, False
    entry = _entry_block(control_flow, call.containing_function_pc)
    registers: dict[str, _Value] = {}
    vectors: dict[str, _VectorValue] = {}
    stack: dict[tuple[str, int], _VectorValue] = {}
    has_entry = entry is not None and any(
        context.to_elf_pc(instruction.address) == entry
        for instruction in instructions
    )
    if has_entry:
        # rsp/rbp 是当前函数栈帧的稳定锚点。若丢掉它们，编译器常见的
        # ``mov rdi,rsp`` 就会把 pthread_t 槽位错误降成 Unknown。
        registers.update(
            {
                "rsp": frozenset((_Token("stack", 0, "rsp"),)),
                "rbp": frozenset((_Token("stack", 0, "rbp"),)),
            }
        )
        registers.update(
            {
                argument: frozenset((_Token("param", index),))
                for index, argument in enumerate(_ARGUMENT_REGISTERS)
            }
        )
    for instruction in instructions:
        operands = instruction.operands
        if operands:
            destination = operands[0]
            source = operands[1] if len(operands) > 1 else None
            if destination.type == X86_OP_REG:
                destination_name = instruction.reg_name(destination.reg)
                destination_root = _root(destination_name) or destination_name
                mnemonic = instruction.mnemonic.lower()
                if (
                    destination_root == "rsp"
                    and mnemonic in {"add", "sub"}
                    and source is not None
                    and source.type == X86_OP_IMM
                ):
                    current = registers.get("rsp")
                    delta = int(source.imm)
                    if mnemonic == "sub":
                        delta = -delta
                    registers["rsp"] = (
                        frozenset(
                            _Token("stack", token.value + delta, token.base)
                            if token.kind == "stack"
                            else token
                            for token in current
                        )
                        if current is not None
                        else None
                    )
                elif _is_vector(destination_name):
                    if mnemonic in {"movaps", "movdqa", "movdqu"} and source is not None:
                        vectors[destination_name] = _vector_from_operand(
                            context,
                            module,
                            instruction,
                            source,
                            registers,
                            vectors,
                            stack,
                        )
                    elif mnemonic == "punpcklqdq" and source is not None:
                        right = (
                            vectors.get(instruction.reg_name(source.reg), (None, None))
                            if source.type == X86_OP_REG
                            else (None, None)
                        )
                        left = vectors.get(destination_name, (None, None))
                        vectors[destination_name] = (left[0], right[0])
                    elif mnemonic == "movq" and source is not None:
                        vectors[destination_name] = (
                            _value_from_operand(
                                context,
                                module,
                                instruction,
                                source,
                                registers,
                                vectors,
                                stack,
                            ),
                            None,
                        )
                    else:
                        vectors[destination_name] = (None, None)
                elif instruction.mnemonic.lower() in {
                    "mov",
                    "movabs",
                    "movzx",
                    "movsx",
                    "movsxd",
                    "lea",
                } and source is not None:
                    registers[destination_root] = (
                        _lea_pointer(context, module, instruction, source)
                        if instruction.mnemonic.lower() == "lea"
                        and source.type == X86_OP_MEM
                        and instruction.reg_name(source.mem.base) == "rip"
                        else _stack_pointer(instruction, source)
                        if instruction.mnemonic.lower() == "lea"
                        and source.type == X86_OP_MEM
                        and instruction.reg_name(source.mem.base) in {"rsp", "rbp"}
                        else _value_from_operand(
                            context,
                            module,
                            instruction,
                            source,
                            registers,
                            vectors,
                            stack,
                        )
                    )
                else:
                    registers.pop(destination_root, None)
            elif destination.type == X86_OP_MEM:
                value = (
                    _value_from_operand(
                        context,
                        module,
                        instruction,
                        source,
                        registers,
                        vectors,
                        stack,
                    )
                    if source is not None
                    else None
                )
                _set_destination(instruction, source, value, registers, vectors, stack)
        if instruction.mnemonic.lower() in {"call", "callq"}:
            _kill_callers(registers, vectors)
    return registers.get(_root(register) or register), None, has_entry


def _callers_of(
    control_flow: ControlFlowReport,
    function_pc: int,
    module_sha256: str,
) -> tuple[CallSite, ...]:
    return tuple(
        call
        for call in control_flow.call_sites
        if any(
            target.module_sha256 == module_sha256 and target.pc == function_pc
            for target in call.targets.known_targets
        )
        and call.targets.complete
    )


def _resolve_tokens(
    context: object,
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    tokens: _Value,
    function_pc: int,
    stack: tuple[tuple[int, int], ...],
    current_call_pc: int | None,
) -> CallbackResolution:
    if tokens is None:
        return CallbackResolution(reason="callback value is not recoverable")
    pcs = sorted(token.value for token in tokens if token.kind == "pc")
    locations = [
        f"frame@0x{function_pc:x}:{token.base or 'unknown'}:{token.value}"
        for token in tokens
        if token.kind == "stack"
    ]
    params = sorted(
        {
            (token.value, token.kind == "param_deref")
            for token in tokens
            if token.kind in {"param", "param_deref"}
        }
    )
    if not params:
        if pcs or locations:
            unique_pcs = tuple(dict.fromkeys(pcs))
            unique_locations = tuple(dict.fromkeys(locations))
            return CallbackResolution(
                targets=unique_pcs,
                complete=True,
                origin="closed ELF callback value",
                contexts=tuple((pc, function_pc) for pc in unique_pcs),
                call_contexts=tuple(
                    (pc, function_pc, current_call_pc) for pc in unique_pcs
                ),
                locations=unique_locations,
                location_contexts=tuple(
                    (location, function_pc, current_call_pc)
                    for location in unique_locations
                ),
            )
        return CallbackResolution(reason="callback value is not an executable address")
    if len(stack) >= _MAX_RECURSION:
        return CallbackResolution(
            targets=tuple(dict.fromkeys(pcs)),
            reason="callback argument propagation exceeded recursion bound",
            contexts=tuple((pc, function_pc) for pc in dict.fromkeys(pcs)),
            call_contexts=tuple(
                (pc, function_pc, current_call_pc) for pc in dict.fromkeys(pcs)
            ),
            locations=tuple(dict.fromkeys(locations)),
            location_contexts=tuple(
                (location, function_pc, current_call_pc)
                for location in dict.fromkeys(locations)
            ),
        )
    if any(
        function_pc == current
        and any(parameter == candidate for candidate, _ in params)
        for current, parameter in stack
    ):
        return CallbackResolution(
            targets=tuple(dict.fromkeys(pcs)),
            reason="callback argument propagation encountered a recursive call path",
            contexts=tuple((pc, function_pc) for pc in dict.fromkeys(pcs)),
            call_contexts=tuple(
                (pc, function_pc, current_call_pc) for pc in dict.fromkeys(pcs)
            ),
            locations=tuple(dict.fromkeys(locations)),
            location_contexts=tuple(
                (location, function_pc, current_call_pc)
                for location in dict.fromkeys(locations)
            ),
        )
    # 当前 token 来自一个函数形参。找到所有已封闭的本 ELF caller，
    # 只有每个 caller 都能给出同一参数的闭合集合时才继续声明 complete。
    callers = _callers_of(control_flow, function_pc, module.sha256)
    if not callers:
        return CallbackResolution(
            targets=tuple(dict.fromkeys(pcs)),
            reason="callback parameter has no closed local caller",
            contexts=tuple((pc, function_pc) for pc in dict.fromkeys(pcs)),
            call_contexts=tuple(
                (pc, function_pc, current_call_pc) for pc in dict.fromkeys(pcs)
            ),
            locations=tuple(dict.fromkeys(locations)),
            location_contexts=tuple(
                (location, function_pc, current_call_pc)
                for location in dict.fromkeys(locations)
            ),
        )
    all_complete = True
    origins: list[str] = []
    context_pairs: list[tuple[int, int]] = []
    call_contexts: list[tuple[int, int, int | None]] = []
    location_contexts: list[tuple[str, int, int | None]] = []
    for parameter, dereferenced in params:
        if parameter >= len(_ARGUMENT_REGISTERS):
            all_complete = False
            continue
        for caller in callers:
            value, _, local_complete = _local_argument_value(
                context,
                module,
                control_flow,
                caller,
                _ARGUMENT_REGISTERS[parameter],
            )
            if not local_complete:
                all_complete = False
                continue
            if dereferenced and (
                value is None
                or any(token.kind != "stack" for token in value)
            ):
                all_complete = False
                continue
            nested = _resolve_tokens(
                context,
                module,
                control_flow,
                value,
                caller.containing_function_pc,
                (*stack, (function_pc, parameter)),
                caller.location.pc,
            )
            pcs.extend(nested.targets)
            # nested contexts already identify the immediate caller; keeping
            # those pairs preserves distinct main/worker wrapper paths.
            context_pairs.extend(nested.contexts)
            call_contexts.extend(nested.call_contexts)
            locations.extend(nested.locations)
            location_contexts.extend(nested.location_contexts)
            origins.append(nested.origin or nested.reason or "unknown callback edge")
            all_complete = all_complete and nested.complete
    unique = tuple(dict.fromkeys(pcs))
    context_pairs = tuple(dict.fromkeys(context_pairs))
    unique_locations = tuple(dict.fromkeys(locations))
    return CallbackResolution(
        targets=unique,
        complete=all_complete and bool(unique or unique_locations),
        origin=(
            "interprocedural SysV callback argument propagation"
            + ("; " + "; ".join(dict.fromkeys(origins)) if origins else "")
        ),
        reason=(
            None
            if all_complete and (unique or unique_locations)
            else "one or more callback caller arguments are incomplete"
        ),
        contexts=context_pairs,
        call_contexts=tuple(dict.fromkeys(call_contexts)),
        locations=unique_locations,
        location_contexts=tuple(dict.fromkeys(location_contexts)),
    )


def resolve_callback_targets(
    context: object,
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    call: CallSite,
    register: str,
) -> CallbackResolution:
    """解析 pthread/OpenMP callback；失败时保留已知候选并返回不完整。"""

    value, _origin, local_complete = _local_argument_value(
        context, module, control_flow, call, register
    )
    if not local_complete:
        return CallbackResolution(reason="callback is not in a closed function-entry block")
    return _resolve_tokens(
        context,
        module,
        control_flow,
        value,
        call.containing_function_pc,
        (),
        call.location.pc,
    )


def resolve_argument_locations(
    context: object,
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    call: CallSite,
    register: str,
) -> CallbackResolution:
    """沿同一条闭合调用链恢复指针实参所指向的栈槽身份。"""

    value, _origin, local_complete = _local_argument_value(
        context, module, control_flow, call, register
    )
    if not local_complete:
        return CallbackResolution(reason="argument is not in a closed function-entry block")
    return _resolve_tokens(
        context,
        module,
        control_flow,
        value,
        call.containing_function_pc,
        (),
        call.location.pc,
    )


def target_set_from_resolution(
    resolution: CallbackResolution,
    make_location,
) -> IndirectTargetSet:
    """把解析结果转为现有 ThreadRole 使用的目标集合。"""

    targets = tuple(make_location(pc) for pc in resolution.targets)
    return IndirectTargetSet(
        known_targets=targets,
        complete=resolution.complete,
        evidence=(resolution.origin,) if resolution.origin else (),
        reason=None if resolution.complete else resolution.reason or "callback target set is incomplete",
    )


__all__ = [
    "CallbackResolution",
    "resolve_argument_locations",
    "resolve_callback_targets",
    "target_set_from_resolution",
]
