from __future__ import annotations

from pathlib import Path

from capstone import (
    CS_AC_READ,
    CS_AC_WRITE,
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_64,
    Cs,
)
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_PREFIX_LOCK

from bmo_check_static.model import (
    ControlFlowKind,
    FenceKind,
    InstructionFact,
    InstructionModuleFacts,
    MemoryAccessKind,
    MemoryOperandFact,
    ModuleFingerprint,
    ImmediateOperandFact,
    RegisterOperandFact,
    UnknownFact,
    UnknownKind,
)

from .elf import executable_segments


_FENCES = {
    "lfence": FenceKind.LFENCE,
    "sfence": FenceKind.SFENCE,
    "mfence": FenceKind.MFENCE,
}

_IMPLICIT_MEMORY = {
    "call": MemoryAccessKind.WRITE,
    "enter": MemoryAccessKind.READ_WRITE,
    "leave": MemoryAccessKind.READ,
    "pop": MemoryAccessKind.READ,
    "popf": MemoryAccessKind.READ,
    "popfq": MemoryAccessKind.READ,
    "push": MemoryAccessKind.WRITE,
    "pushf": MemoryAccessKind.WRITE,
    "pushfq": MemoryAccessKind.WRITE,
    "ret": MemoryAccessKind.READ,
    "retf": MemoryAccessKind.READ,
}


def _access_kind(access: int) -> MemoryAccessKind:
    reads = bool(access & CS_AC_READ)
    writes = bool(access & CS_AC_WRITE)
    if reads and writes:
        return MemoryAccessKind.READ_WRITE
    if reads:
        return MemoryAccessKind.READ
    if writes:
        return MemoryAccessKind.WRITE
    return MemoryAccessKind.UNKNOWN


def _string_memory_access(mnemonic: str) -> MemoryAccessKind | None:
    if mnemonic in {"movsb", "movsw", "movsd", "movsq"}:
        return MemoryAccessKind.READ_WRITE
    if mnemonic in {"cmpsb", "cmpsw", "cmpsd", "cmpsq"}:
        return MemoryAccessKind.READ
    if mnemonic in {"lodsb", "lodsw", "lodsd", "lodsq", "xlatb"}:
        return MemoryAccessKind.READ
    if mnemonic in {"stosb", "stosw", "stosd", "stosq"}:
        return MemoryAccessKind.WRITE
    if mnemonic in {"scasb", "scasw", "scasd", "scasq"}:
        return MemoryAccessKind.READ
    return None


def _implicit_access_size(mnemonic: str) -> int:
    if mnemonic.endswith("b"):
        return 1
    if mnemonic.endswith("w"):
        return 2
    if mnemonic.endswith("d"):
        return 4
    return 8


def _memory_operands(insn: object) -> tuple[MemoryOperandFact, ...]:
    mnemonic = insn.mnemonic.lower()
    if mnemonic == "lea":
        return ()

    facts: list[MemoryOperandFact] = []
    for index, operand in enumerate(insn.operands):
        if operand.type != X86_OP_MEM:
            continue
        access = _access_kind(int(operand.access))
        if mnemonic == "xchg" or X86_PREFIX_LOCK in tuple(insn.prefix):
            access = MemoryAccessKind.READ_WRITE
        memory = operand.mem
        facts.append(
            MemoryOperandFact(
                operand_index=index,
                access=access,
                size=int(operand.size),
                segment=insn.reg_name(memory.segment) or None,
                base=insn.reg_name(memory.base) or None,
                index=insn.reg_name(memory.index) or None,
                scale=int(memory.scale),
                displacement=int(memory.disp),
            )
        )

    implicit = _IMPLICIT_MEMORY.get(mnemonic)
    if implicit is None:
        implicit = _string_memory_access(mnemonic)
    if implicit is not None and not facts:
        facts.append(
            MemoryOperandFact(
                operand_index=-1,
                access=implicit,
                size=_implicit_access_size(mnemonic),
                base="rsp" if mnemonic in _IMPLICIT_MEMORY else None,
                implicit=True,
            )
        )
    return tuple(facts)


def _address_operands(insn: object) -> tuple[MemoryOperandFact, ...]:
    if insn.mnemonic.lower() != "lea":
        return ()
    return tuple(
        MemoryOperandFact(
            operand_index=index,
            access=MemoryAccessKind.UNKNOWN,
            size=int(operand.size),
            segment=insn.reg_name(operand.mem.segment) or None,
            base=insn.reg_name(operand.mem.base) or None,
            index=insn.reg_name(operand.mem.index) or None,
            scale=int(operand.mem.scale),
            displacement=int(operand.mem.disp),
        )
        for index, operand in enumerate(insn.operands)
        if operand.type == X86_OP_MEM
    )


def _register_operands(insn: object) -> tuple[RegisterOperandFact, ...]:
    return tuple(
        RegisterOperandFact(
            operand_index=index,
            register_name=insn.reg_name(operand.reg),
            access=_access_kind(int(operand.access)),
        )
        for index, operand in enumerate(insn.operands)
        if operand.type == X86_OP_REG
    )


def _immediate_operands(insn: object) -> tuple[ImmediateOperandFact, ...]:
    return tuple(
        ImmediateOperandFact(operand_index=index, value=int(operand.imm))
        for index, operand in enumerate(insn.operands)
        if operand.type == X86_OP_IMM
    )


def _control_flow(insn: object) -> tuple[ControlFlowKind | None, int | None]:
    direct_target: int | None = None
    first_operand = insn.operands[0] if insn.operands else None
    direct = first_operand is not None and first_operand.type == X86_OP_IMM
    if direct:
        direct_target = int(first_operand.imm)

    if insn.group(CS_GRP_CALL):
        return (
            ControlFlowKind.DIRECT_CALL if direct else ControlFlowKind.INDIRECT_CALL,
            direct_target,
        )
    if insn.group(CS_GRP_JUMP):
        return (
            ControlFlowKind.DIRECT_JUMP if direct else ControlFlowKind.INDIRECT_JUMP,
            direct_target,
        )
    if insn.group(CS_GRP_RET):
        return ControlFlowKind.RETURN, None
    return None, None


def _fact_from_instruction(
    insn: object,
    module_path: str,
    module_sha256: str,
    section: str | None,
) -> InstructionFact:
    if insn.id == 0:
        unknown = UnknownFact(
            kind=UnknownKind.INCOMPLETE_INSTRUCTION,
            reason="Capstone skipped an undecodable byte sequence",
            impact="instruction and memory effects are unknown",
            module=module_path,
            pc=int(insn.address),
            details={"raw_bytes": bytes(insn.bytes).hex()},
        )
        return InstructionFact(
            module_sha256=module_sha256,
            module_path=module_path,
            section=section,
            pc=int(insn.address),
            raw_bytes=bytes(insn.bytes).hex(),
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            classification_complete=False,
            unknowns=(unknown,),
        )

    memory_operands = _memory_operands(insn)
    address_operands = _address_operands(insn)
    register_operands = _register_operands(insn)
    immediate_operands = _immediate_operands(insn)
    unknowns: list[UnknownFact] = []
    if any(item.access == MemoryAccessKind.UNKNOWN for item in memory_operands):
        unknowns.append(
            UnknownFact(
                kind=UnknownKind.INCOMPLETE_INSTRUCTION,
                reason="Capstone did not provide memory operand access direction",
                impact="later analysis must not guess whether this operand reads or writes",
                module=module_path,
                pc=int(insn.address),
                details={"mnemonic": insn.mnemonic, "op_str": insn.op_str},
            )
        )

    control_flow, direct_target = _control_flow(insn)
    mnemonic = insn.mnemonic.lower()
    return InstructionFact(
        module_sha256=module_sha256,
        module_path=module_path,
        section=section,
        pc=int(insn.address),
        raw_bytes=bytes(insn.bytes).hex(),
        mnemonic=mnemonic,
        op_str=insn.op_str,
        memory_operands=memory_operands,
        address_operands=address_operands,
        register_operands=register_operands,
        immediate_operands=immediate_operands,
        has_lock_prefix=X86_PREFIX_LOCK in tuple(insn.prefix),
        is_memory_xchg=mnemonic == "xchg" and bool(memory_operands),
        fence=_FENCES.get(mnemonic),
        control_flow=control_flow,
        direct_target=direct_target,
        is_syscall=mnemonic == "syscall",
        classification_complete=not unknowns,
        unknowns=tuple(unknowns),
    )


def _disassembler() -> Cs:
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    engine.detail = True
    engine.skipdata = True
    return engine


def disassemble_bytes(
    code: bytes,
    address: int = 0,
    *,
    module_path: str = "<bytes>",
    module_sha256: str = "0" * 64,
    section: str | None = None,
) -> tuple[InstructionFact, ...]:
    engine = _disassembler()
    return tuple(
        _fact_from_instruction(insn, module_path, module_sha256, section)
        for insn in engine.disasm(code, address)
    )


def collect_instruction_facts(
    module: ModuleFingerprint,
) -> InstructionModuleFacts:
    facts: list[InstructionFact] = []
    unknowns: list[UnknownFact] = []
    try:
        for segment in executable_segments(Path(module.path)):
            segment_facts = disassemble_bytes(
                segment.data,
                segment.virtual_address,
                module_path=module.path,
                module_sha256=module.sha256,
                section=segment.name,
            )
            facts.extend(segment_facts)
            for fact in segment_facts:
                unknowns.extend(fact.unknowns)
    except Exception as error:
        # 后端失败后不能留下一个看似完整的空指令集。
        # 后续证明必须看到这个 Unknown，才能阻止 false SAFE。
        unknowns.append(
            UnknownFact(
                kind=UnknownKind.DISASSEMBLY_FAILURE,
                reason=str(error),
                impact="instruction coverage for this module is unavailable",
                module=module.path,
            )
        )

    return InstructionModuleFacts(
        module_path=module.path,
        module_sha256=module.sha256,
        instruction_count=len(facts),
        memory_instruction_count=sum(bool(fact.memory_operands) for fact in facts),
        facts=tuple(facts),
        unknowns=tuple(unknowns),
    )
