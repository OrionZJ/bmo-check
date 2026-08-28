from __future__ import annotations

from enum import Enum

from .common import StrictModel
from .unknown import UnknownFact


class MemoryAccessKind(str, Enum):
    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"
    UNKNOWN = "unknown"


class FenceKind(str, Enum):
    LFENCE = "lfence"
    SFENCE = "sfence"
    MFENCE = "mfence"


class ControlFlowKind(str, Enum):
    DIRECT_CALL = "direct_call"
    INDIRECT_CALL = "indirect_call"
    DIRECT_JUMP = "direct_jump"
    INDIRECT_JUMP = "indirect_jump"
    RETURN = "return"


class MemoryOperandFact(StrictModel):
    operand_index: int
    access: MemoryAccessKind
    size: int
    segment: str | None = None
    base: str | None = None
    index: str | None = None
    scale: int = 1
    displacement: int = 0
    implicit: bool = False


class RegisterOperandFact(StrictModel):
    # operand_index 保留寄存器在 x86 指令中的位置，供定义链区分源和目的。
    operand_index: int
    # register_name 使用 Capstone 的具体名称；分析层负责归一化 eax/rax 等别名。
    register_name: str
    # access 区分该 operand 读取、覆盖还是读后写寄存器。
    access: MemoryAccessKind


class ImmediateOperandFact(StrictModel):
    # operand_index 让立即数与对应的算术或控制流 operand 对齐。
    operand_index: int
    # value 保存解码后的有符号整数，不从格式化字符串反推数值。
    value: int


class InstructionFact(StrictModel):
    module_sha256: str
    module_path: str
    section: str | None = None
    pc: int
    raw_bytes: str
    mnemonic: str
    op_str: str
    memory_operands: tuple[MemoryOperandFact, ...] = ()
    # address_operands 保存 LEA 的寻址式；它们参与 provenance，但不是内存事件。
    address_operands: tuple[MemoryOperandFact, ...] = ()
    # register_operands 支持从机器码建立寄存器定义链。
    register_operands: tuple[RegisterOperandFact, ...] = ()
    # immediate_operands 支持常量偏移、缩放和边界恢复。
    immediate_operands: tuple[ImmediateOperandFact, ...] = ()
    has_lock_prefix: bool = False
    is_memory_xchg: bool = False
    fence: FenceKind | None = None
    control_flow: ControlFlowKind | None = None
    direct_target: int | None = None
    is_syscall: bool = False
    classification_complete: bool = True
    unknowns: tuple[UnknownFact, ...] = ()


class InstructionModuleFacts(StrictModel):
    module_path: str
    module_sha256: str
    instruction_count: int
    memory_instruction_count: int
    facts: tuple[InstructionFact, ...]
    unknowns: tuple[UnknownFact, ...] = ()
