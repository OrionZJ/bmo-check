from __future__ import annotations

from dataclasses import dataclass

from capstone import CS_AC_READ, CS_AC_WRITE
from capstone.x86 import X86_OP_MEM, X86_OP_REG

from bmo_check_static.binary.angr_backend import AngrModuleContext
from bmo_check_static.model import CallKind, ControlFlowReport


_ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
_ALIASES = {
    "eax": "rax", "ax": "rax", "al": "rax",
    "edi": "rdi", "di": "rdi", "dil": "rdi",
    "esi": "rsi", "si": "rsi", "sil": "rsi",
    "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx",
    "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9d": "r9", "r9w": "r9", "r9b": "r9",
    "r10d": "r10", "r10w": "r10", "r10b": "r10",
    "r11d": "r11", "r11w": "r11", "r11b": "r11",
}


@dataclass(frozen=True)
class NoCaptureResult:
    # proven 只有在所有已恢复路径都没有发布参数地址时才为 true。
    proven: bool
    # evidence 说明批准依据或第一个阻止证明的用法。
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class _TaintState:
    # registers 保存仍携带被检查参数地址的规范寄存器名。
    registers: frozenset[str]
    # frame_slots 保存参数被 spill 到的 rbp 固定槽。
    frame_slots: frozenset[int]


def _register(instruction: object, operand: object) -> str:
    name = instruction.reg_name(operand.reg)
    return _ALIASES.get(name, name)


def _register_names(instruction: object) -> list[str]:
    return [
        _register(instruction, operand)
        for operand in instruction.operands
        if operand.type == X86_OP_REG
    ]


def _merge(left: _TaintState | None, right: _TaintState) -> _TaintState:
    if left is None:
        return right
    return _TaintState(
        registers=left.registers | right.registers,
        frame_slots=left.frame_slots | right.frame_slots,
    )


class _NoCaptureAnalyzer:
    def __init__(
        self,
        context: AngrModuleContext,
        control_flow: ControlFlowReport,
        scalar_external_symbols: frozenset[str],
    ):
        self.context = context
        self.functions = {item.location.pc: item for item in control_flow.functions}
        self.blocks = {item.location.pc: item for item in control_flow.basic_blocks}
        self.calls = {item.location.pc: item for item in control_flow.call_sites}
        # 这些函数只从浮点寄存器取标量参数；整数寄存器中的旧值不是实参。
        self.scalar_external_symbols = scalar_external_symbols
        self.cache: dict[tuple[int, int], NoCaptureResult] = {}
        self.active: set[tuple[int, int]] = set()

    def analyze(self, function_pc: int, argument_index: int) -> NoCaptureResult:
        key = (function_pc, argument_index)
        if key in self.cache:
            return self.cache[key]
        function = self.functions.get(function_pc)
        if function is None:
            return NoCaptureResult(False, ("callee or ABI argument is not modeled",))
        if key in self.active:
            return NoCaptureResult(False, ("recursive parameter flow has not converged",))
        self.active.add(key)
        try:
            result = self._analyze_function(function_pc, argument_index)
            self.cache[key] = result
            return result
        finally:
            self.active.remove(key)

    def _analyze_function(self, function_pc: int, argument_index: int) -> NoCaptureResult:
        function = self.functions[function_pc]
        initial_registers: frozenset[str] = frozenset()
        initial_slots: frozenset[int] = frozenset()
        if argument_index < len(_ARGUMENT_REGISTERS):
            initial_registers = frozenset({_ARGUMENT_REGISTERS[argument_index]})
        else:
            try:
                entry = self.context.project.factory.block(
                    self.context.to_rebased(function_pc)
                )
                entry_instructions = [item.insn for item in entry.capstone.insns]
            except Exception:
                entry_instructions = []
            names = [_register_names(item) for item in entry_instructions[:2]]
            if (
                len(entry_instructions) < 2
                or entry_instructions[0].mnemonic != "push"
                or names[0][:1] != ["rbp"]
                or entry_instructions[1].mnemonic != "mov"
                or names[1][:2] != ["rbp", "rsp"]
            ):
                return NoCaptureResult(False, ("stack argument frame layout is not proven",))
            initial_slots = frozenset({16 + 8 * (argument_index - 6)})
        incoming: dict[int, _TaintState] = {
            function_pc: _TaintState(
                registers=initial_registers,
                frame_slots=initial_slots,
            )
        }
        pending = [function_pc]
        inspected: set[tuple[int, _TaintState]] = set()
        while pending:
            block_pc = pending.pop()
            state = incoming[block_pc]
            marker = (block_pc, state)
            if marker in inspected:
                continue
            inspected.add(marker)
            block_fact = self.blocks.get(block_pc)
            if block_fact is None:
                return NoCaptureResult(False, (f"block 0x{block_pc:x} is missing",))
            try:
                block = self.context.project.factory.block(
                    self.context.to_rebased(block_pc)
                )
            except Exception:
                return NoCaptureResult(False, (f"block 0x{block_pc:x} cannot be decoded",))
            for wrapped in block.capstone.insns:
                instruction = wrapped.insn
                state, failure = self._transfer(instruction, state)
                if failure is not None:
                    return NoCaptureResult(False, (failure,))
            for successor in block_fact.successor_pcs:
                if successor not in function.block_pcs:
                    continue
                merged = _merge(incoming.get(successor), state)
                if incoming.get(successor) != merged:
                    incoming[successor] = merged
                    pending.append(successor)
        return NoCaptureResult(
            True,
            (f"argument {argument_index} is only dereferenced or kept in the callee frame",),
        )

    def _transfer(
        self, instruction: object, state: _TaintState
    ) -> tuple[_TaintState, str | None]:
        operands = list(instruction.operands)
        registers = set(state.registers)
        slots = set(state.frame_slots)
        pc = self.context.to_elf_pc(instruction.address)

        if instruction.mnemonic == "ret":
            if "rax" in registers:
                return state, f"0x{pc:x}: parameter address is returned"
            return state, None

        call = self.calls.get(pc)
        if call is not None:
            tainted_arguments = [
                index for index, name in enumerate(_ARGUMENT_REGISTERS) if name in registers
            ]
            for index in tainted_arguments:
                if call.target_symbol in self.scalar_external_symbols:
                    continue
                if call.kind != CallKind.DIRECT or len(call.targets.known_targets) != 1:
                    return state, f"0x{pc:x}: parameter reaches an unresolved call"
                target = call.targets.known_targets[0]
                if target.module_sha256 != self.context.module.sha256:
                    return state, f"0x{pc:x}: parameter reaches an external call"
                child = self.analyze(target.pc, index)
                if not child.proven:
                    return state, f"0x{pc:x}: callee may capture argument {index}: {child.evidence[0]}"
            registers.difference_update(_CALLER_SAVED)
            return _TaintState(frozenset(registers), frozenset(slots)), None

        if instruction.mnemonic in {"push", "pop"}:
            if any(
                operand.type == X86_OP_REG and _register(instruction, operand) in registers
                for operand in operands
            ):
                return state, f"0x{pc:x}: tainted stack arguments are not modeled"
            return state, None

        if instruction.mnemonic in {"mov", "movzx", "movsx", "movsxd"} and len(operands) >= 2:
            destination, source = operands[0], operands[1]
            source_tainted = (
                source.type == X86_OP_REG and _register(instruction, source) in registers
            )
            if source.type == X86_OP_MEM:
                base = instruction.reg_name(source.mem.base)
                source_tainted = base == "rbp" and int(source.mem.disp) in slots
            if destination.type == X86_OP_REG:
                name = _register(instruction, destination)
                registers.discard(name)
                if source_tainted:
                    registers.add(name)
            elif destination.type == X86_OP_MEM and source_tainted:
                base = instruction.reg_name(destination.mem.base)
                if base == "rbp":
                    slots.add(int(destination.mem.disp))
                else:
                    return state, f"0x{pc:x}: parameter address is stored outside the callee frame"
            return _TaintState(frozenset(registers), frozenset(slots)), None

        if instruction.mnemonic == "lea" and operands and operands[0].type == X86_OP_REG:
            destination = _register(instruction, operands[0])
            memory = next((item for item in operands if item.type == X86_OP_MEM), None)
            tainted = memory is not None and any(
                _ALIASES.get(instruction.reg_name(register), instruction.reg_name(register))
                in registers
                for register in (memory.mem.base, memory.mem.index)
                if register
            )
            registers.discard(destination)
            if tainted:
                registers.add(destination)
            return _TaintState(frozenset(registers), frozenset(slots)), None

        read_tainted = {
            _register(instruction, operand)
            for operand in operands
            if operand.type == X86_OP_REG
            and operand.access & CS_AC_READ
            and _register(instruction, operand) in registers
        }
        written = {
            _register(instruction, operand)
            for operand in operands
            if operand.type == X86_OP_REG and operand.access & CS_AC_WRITE
        }
        address_registers = {
            _ALIASES.get(instruction.reg_name(register), instruction.reg_name(register))
            for operand in operands
            if operand.type == X86_OP_MEM
            for register in (operand.mem.base, operand.mem.index)
            if register
        }
        unsupported = read_tainted - address_registers
        if unsupported and instruction.mnemonic not in {
            "add", "sub", "and", "or", "xor", "shl", "shr", "sar", "cmp", "test"
        }:
            return state, f"0x{pc:x}: unsupported tainted use by {instruction.mnemonic}"
        tainted_result = bool(read_tainted) and instruction.mnemonic not in {"cmp", "test"}
        registers.difference_update(written)
        if tainted_result:
            registers.update(written)
        return _TaintState(frozenset(registers), frozenset(slots)), None


def prove_register_parameter_nocapture(
    context: AngrModuleContext,
    control_flow: ControlFlowReport,
    function_pc: int,
    argument_index: int,
    scalar_external_symbols: frozenset[str] = frozenset(),
) -> NoCaptureResult:
    return _NoCaptureAnalyzer(
        context, control_flow, scalar_external_symbols
    ).analyze(function_pc, argument_index)
