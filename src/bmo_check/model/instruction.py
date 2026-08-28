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


class InstructionFact(StrictModel):
    module_sha256: str
    module_path: str
    section: str | None = None
    pc: int
    raw_bytes: str
    mnemonic: str
    op_str: str
    memory_operands: tuple[MemoryOperandFact, ...] = ()
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
