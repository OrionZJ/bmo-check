from __future__ import annotations

from types import SimpleNamespace

from capstone.x86 import X86_OP_MEM

from bmo_check_static.binary.elf import executable_segments, inspect_elf
from bmo_check_static.model import ModuleRole
from bmo_check_static.threading.callback import (
    _Token,
    _resolve_tokens,
    _vector_from_operand,
)


def test_stack_token_keeps_a_stable_context_location(elf_fixture) -> None:
    module = inspect_elf(elf_fixture.executable, ModuleRole.EXECUTABLE)
    resolution = _resolve_tokens(
        None,
        module,
        None,
        frozenset((_Token("stack", -24, "rsp"),)),
        0x1234,
        (),
        0x5678,
    )

    assert resolution.complete
    assert resolution.locations == ("frame@0x1234:rsp:-24",)
    assert resolution.location_contexts == (
        ("frame@0x1234:rsp:-24", 0x1234, 0x5678),
    )


def test_vector_load_preserves_two_function_pointer_lanes(elf_fixture) -> None:
    module = inspect_elf(elf_fixture.executable, ModuleRole.EXECUTABLE)
    executable = executable_segments(elf_fixture.executable)[0]
    pc0 = executable.virtual_address
    pc1 = pc0 + 1
    data_address = 0x1000

    class _Memory:
        def load(self, address: int, width: int) -> bytes:
            assert width == 8
            value = pc0 if address == data_address else pc1
            return value.to_bytes(width, "little")

    context = SimpleNamespace(
        project=SimpleNamespace(loader=SimpleNamespace(memory=_Memory())),
        to_elf_pc=lambda value: value,
    )
    instruction = SimpleNamespace(
        address=data_address - 7,
        size=7,
        reg_name=lambda register: "rip" if register == 1 else "",
    )
    operand = SimpleNamespace(
        type=X86_OP_MEM,
        size=16,
        mem=SimpleNamespace(base=1, index=0, disp=0),
    )

    lanes = _vector_from_operand(
        context, module, instruction, operand, {}, {}, {}
    )

    assert tuple(token.value for token in lanes[0]) == (pc0,)
    assert tuple(token.value for token in lanes[1]) == (pc1,)
