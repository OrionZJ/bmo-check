from __future__ import annotations

from bmo_check_static.binary.capstone_backend import disassemble_bytes
from bmo_check_static.model import (
    ControlFlowKind,
    FenceKind,
    MemoryAccessKind,
)


def _one(code: bytes, address: int = 0x1000):
    facts = disassemble_bytes(code, address)
    assert len(facts) == 1
    return facts[0]


def test_mov_load_and_store() -> None:
    load = _one(bytes.fromhex("48 8b 03"))
    store = _one(bytes.fromhex("48 89 03"))
    assert load.memory_operands[0].access == MemoryAccessKind.READ
    assert store.memory_operands[0].access == MemoryAccessKind.WRITE


def test_lock_rmw_variants() -> None:
    for code in (
        "f0 0f b1 0b",
        "f0 0f c1 0b",
        "f0 ff 0b",
    ):
        fact = _one(bytes.fromhex(code))
        assert fact.has_lock_prefix
        assert fact.memory_operands[0].access == MemoryAccessKind.READ_WRITE


def test_memory_and_register_xchg_are_distinct() -> None:
    memory = _one(bytes.fromhex("48 87 03"))
    register = _one(bytes.fromhex("48 87 d8"))
    assert memory.is_memory_xchg
    assert not register.is_memory_xchg


def test_movsxd_is_not_misclassified_as_string_memory() -> None:
    extension = _one(bytes.fromhex("48 63 d2"))

    assert extension.mnemonic == "movsxd"
    assert not extension.memory_operands


def test_explicit_fences() -> None:
    assert _one(bytes.fromhex("0f ae e8")).fence == FenceKind.LFENCE
    assert _one(bytes.fromhex("0f ae f8")).fence == FenceKind.SFENCE
    assert _one(bytes.fromhex("0f ae f0")).fence == FenceKind.MFENCE


def test_control_flow_and_syscall() -> None:
    direct_call = _one(bytes.fromhex("e8 00 00 00 00"))
    indirect_call = _one(bytes.fromhex("ff d0"))
    direct_jump = _one(bytes.fromhex("e9 00 00 00 00"))
    indirect_jump = _one(bytes.fromhex("ff e0"))
    ret = _one(bytes.fromhex("c3"))
    syscall = _one(bytes.fromhex("0f 05"))

    assert direct_call.control_flow == ControlFlowKind.DIRECT_CALL
    assert direct_call.direct_target == 0x1005
    assert direct_call.memory_operands[0].implicit
    assert indirect_call.control_flow == ControlFlowKind.INDIRECT_CALL
    assert direct_jump.control_flow == ControlFlowKind.DIRECT_JUMP
    assert indirect_jump.control_flow == ControlFlowKind.INDIRECT_JUMP
    assert ret.control_flow == ControlFlowKind.RETURN
    assert ret.memory_operands[0].implicit
    assert syscall.is_syscall


def test_undecodable_bytes_remain_explicit_unknown() -> None:
    fact = _one(bytes.fromhex("0f"))
    assert not fact.classification_complete
    assert fact.unknowns
