from __future__ import annotations

from bmo_check.analysis.address_provenance import recover_block_local_addresses
from bmo_check.binary.capstone_backend import disassemble_bytes
from bmo_check.model import (
    AddressKind,
    BasicBlockFact,
    CFGCoverage,
    CodeLocation,
    ControlFlowReport,
    ElfMetadata,
    FunctionFact,
    ModuleFingerprint,
    ModuleRole,
)


HASH = "a" * 64


def _location(pc: int) -> CodeLocation:
    return CodeLocation(module_path="/bin/app", module_sha256=HASH, pc=pc)


def test_global_pointer_slot_and_scaled_stack_index_are_recovered() -> None:
    code = bytes.fromhex(
        "488b05f90f0000"  # mov rax, [rip + 0xff9] -> slot 0x2000
        "8b55e8"          # mov edx, [rbp - 0x18]
        "4863d2"          # movsxd rdx, edx
        "48c1e202"        # shl rdx, 2
        "4801d0"          # add rax, rdx
        "8b08"            # mov ecx, [rax]
    )
    facts = disassemble_bytes(code, address=0x1000)
    pcs = tuple(fact.pc for fact in facts)
    module = ModuleFingerprint(
        path="/bin/app",
        role=ModuleRole.EXECUTABLE,
        size=4096,
        sha256=HASH,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    control_flow = ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0x1000,
        functions=(
            FunctionFact(
                location=_location(0x1000),
                size=len(code),
                block_pcs=(0x1000,),
            ),
        ),
        basic_blocks=(
            BasicBlockFact(
                location=_location(0x1000),
                size=len(code),
                instruction_pcs=pcs,
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=1,
            basic_blocks=1,
            call_sites=0,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    addresses = recover_block_local_addresses(module, control_flow, facts)
    final_operand = facts[-1].memory_operands[0]
    address = addresses[(facts[-1].pc, final_operand.operand_index)]

    assert address.kind == AddressKind.AFFINE
    assert address.base == "app@0x2000"
    assert address.index_coefficient == 4
    assert address.provenance["index_term"] == "frame@0x1000-24"
