from __future__ import annotations

from bmo_check_static.analysis.address_provenance import (
    recover_address_provenance,
    recover_block_local_addresses,
)
from bmo_check_static.binary.capstone_backend import disassemble_bytes
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    BasicBlockFact,
    CallKind,
    CallSite,
    CFGCoverage,
    CodeLocation,
    ControlFlowReport,
    ElfMetadata,
    FunctionFact,
    IndirectTargetSet,
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
    assert address.base == "loaded-pointer@0x1000"
    assert address.index_coefficient == 4
    assert address.provenance["index_term"] == "frame@0x1000-24"


def test_fresh_allocation_return_flows_across_cfg_edge() -> None:
    call_fact = disassemble_bytes(bytes.fromhex("e800000000"), address=0x1000)[0]
    use_fact = disassemble_bytes(bytes.fromhex("c70001000000"), address=0x1005)[0]
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
                size=11,
                block_pcs=(0x1000, 0x1005),
            ),
        ),
        basic_blocks=(
            BasicBlockFact(
                location=_location(0x1000),
                size=5,
                instruction_pcs=(0x1000,),
                successor_pcs=(0x1005,),
            ),
            BasicBlockFact(
                location=_location(0x1005),
                size=6,
                instruction_pcs=(0x1005,),
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=1,
            basic_blocks=2,
            call_sites=1,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    addresses = recover_block_local_addresses(
        module,
        control_flow,
        (call_fact, use_fact),
        {0x1000: "malloc"},
    )

    address = addresses[(0x1005, use_fact.memory_operands[0].operand_index)]
    assert address.kind == AddressKind.HEAP
    assert address.base == "heap:malloc@0x1000"
    assert address.provenance["scope"] == "function-cfg"


def test_pointer_written_to_fresh_heap_slot_is_recovered_on_load() -> None:
    facts = disassemble_bytes(
        bytes.fromhex(
            "e800000000"  # call malloc
            "488900"      # mov [rax], rax
            "488b08"      # mov rcx, [rax]
            "8b11"        # mov edx, [rcx]
        ),
        address=0x1000,
    )
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
                size=sum(len(item.raw_bytes) for item in facts),
                block_pcs=(0x1000,),
            ),
        ),
        basic_blocks=(
            BasicBlockFact(
                location=_location(0x1000),
                size=sum(len(item.raw_bytes) for item in facts),
                instruction_pcs=tuple(item.pc for item in facts),
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=1,
            basic_blocks=1,
            call_sites=1,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    report = recover_address_provenance(
        module, control_flow, facts, {0x1000: "malloc"}
    )
    use = facts[-1]
    address = report.addresses[(use.pc, use.memory_operands[0].operand_index)]

    assert address.kind == AddressKind.HEAP
    assert address.base == "heap:malloc@0x1000"


def test_pointer_loaded_from_heap_field_is_not_the_container_address() -> None:
    facts = disassemble_bytes(
        bytes.fromhex(
            "e800000000"  # call malloc
            "488b08"      # mov rcx, [rax]
            "8b11"        # mov edx, [rcx]
        ),
        address=0x1000,
    )
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
                size=10,
                block_pcs=(0x1000,),
            ),
        ),
        basic_blocks=(
            BasicBlockFact(
                location=_location(0x1000),
                size=10,
                instruction_pcs=tuple(item.pc for item in facts),
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=1,
            basic_blocks=1,
            call_sites=1,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    report = recover_address_provenance(
        module, control_flow, facts, {0x1000: "malloc"}
    )
    use = facts[-1]
    address = report.addresses[
        (use.pc, use.memory_operands[0].operand_index)
    ]

    assert address.base == "loaded-pointer@0x1005"
    assert address.base != "heap:malloc@0x1000"
    assert address.provenance["base_indirect"] is True


def test_fresh_allocation_wrapper_is_summarized_at_its_caller() -> None:
    wrapper_call = disassemble_bytes(bytes.fromhex("e800000000"), address=0x1000)[0]
    wrapper_ret = disassemble_bytes(bytes.fromhex("c3"), address=0x1005)[0]
    caller_call = disassemble_bytes(bytes.fromhex("e800000000"), address=0x2000)[0]
    caller_use = disassemble_bytes(bytes.fromhex("c70001000000"), address=0x2005)[0]
    module = ModuleFingerprint(
        path="/bin/app",
        role=ModuleRole.EXECUTABLE,
        size=8192,
        sha256=HASH,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    locations = tuple(_location(pc) for pc in (0x1000, 0x1005, 0x2000, 0x2005))
    control_flow = ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0x2000,
        functions=(
            FunctionFact(location=locations[0], size=6, block_pcs=(0x1000, 0x1005)),
            FunctionFact(location=locations[2], size=11, block_pcs=(0x2000, 0x2005)),
        ),
        basic_blocks=(
            BasicBlockFact(location=locations[0], size=5, instruction_pcs=(0x1000,), successor_pcs=(0x1005,)),
            BasicBlockFact(location=locations[1], size=1, instruction_pcs=(0x1005,)),
            BasicBlockFact(location=locations[2], size=5, instruction_pcs=(0x2000,), successor_pcs=(0x2005,)),
            BasicBlockFact(location=locations[3], size=6, instruction_pcs=(0x2005,)),
        ),
        call_sites=(
            CallSite(
                location=locations[2],
                containing_function_pc=0x2000,
                block_pc=0x2000,
                kind=CallKind.DIRECT,
                targets=IndirectTargetSet(
                    known_targets=(_location(0x1000),),
                    complete=True,
                ),
                return_pc=0x2005,
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=2,
            basic_blocks=4,
            call_sites=2,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    addresses = recover_block_local_addresses(
        module,
        control_flow,
        (wrapper_call, wrapper_ret, caller_call, caller_use),
        {0x1000: "malloc"},
    )

    address = addresses[(0x2005, caller_use.memory_operands[0].operand_index)]
    assert address.kind == AddressKind.HEAP
    assert address.base == "heap:function@0x1000@0x2000"


def test_fresh_wrapper_may_link_its_own_allocations() -> None:
    wrapper_facts = disassemble_bytes(
        bytes.fromhex(
            "e800000000"  # outer = malloc()
            "4889c3"      # rbx = outer
            "e800000000"  # inner = malloc()
            "488903"      # outer[0] = inner
            "4889d8"      # return outer
            "c3"
        ),
        address=0x1000,
    )
    caller_facts = disassemble_bytes(
        bytes.fromhex("e8000000008b00"), address=0x2000
    )
    module = ModuleFingerprint(
        path="/bin/app",
        role=ModuleRole.EXECUTABLE,
        size=0x3000,
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
        entry_pc=0x2000,
        functions=(
            FunctionFact(location=_location(0x1000), size=20, block_pcs=(0x1000,)),
            FunctionFact(location=_location(0x2000), size=7, block_pcs=(0x2000,)),
        ),
        basic_blocks=(
            BasicBlockFact(location=_location(0x1000), size=20, instruction_pcs=tuple(item.pc for item in wrapper_facts)),
            BasicBlockFact(location=_location(0x2000), size=7, instruction_pcs=tuple(item.pc for item in caller_facts)),
        ),
        call_sites=(
            CallSite(
                location=_location(0x2000),
                containing_function_pc=0x2000,
                block_pc=0x2000,
                kind=CallKind.DIRECT,
                targets=IndirectTargetSet(known_targets=(_location(0x1000),), complete=True),
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=2,
            basic_blocks=2,
            call_sites=3,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    report = recover_address_provenance(
        module,
        control_flow,
        (*wrapper_facts, *caller_facts),
        {0x1000: "malloc", 0x1008: "malloc"},
    )
    use = caller_facts[-1]
    address = report.addresses[
        (use.pc, use.memory_operands[0].operand_index)
    ]

    assert address.base == "heap:function@0x1000@0x2000"


def test_pointer_argument_flows_into_direct_callee() -> None:
    caller_facts = disassemble_bytes(
        bytes.fromhex(
            "488d35f90f0000"  # lea rsi, [rip + 0xff9] -> object 0x2000
            "e800000000"      # call callee
        ),
        address=0x1000,
    )
    callee_fact = disassemble_bytes(bytes.fromhex("8b06"), address=0x3000)[0]
    module = ModuleFingerprint(
        path="/bin/app",
        role=ModuleRole.EXECUTABLE,
        size=0x4000,
        sha256=HASH,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    call_pc = caller_facts[-1].pc
    control_flow = ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0x1000,
        functions=(
            FunctionFact(
                location=_location(0x1000),
                size=12,
                block_pcs=(0x1000,),
            ),
            FunctionFact(
                location=_location(0x3000),
                size=2,
                block_pcs=(0x3000,),
            ),
        ),
        basic_blocks=(
            BasicBlockFact(
                location=_location(0x1000),
                size=12,
                instruction_pcs=tuple(item.pc for item in caller_facts),
            ),
            BasicBlockFact(
                location=_location(0x3000),
                size=2,
                instruction_pcs=(0x3000,),
            ),
        ),
        call_sites=(
            CallSite(
                location=_location(call_pc),
                containing_function_pc=0x1000,
                block_pc=0x1000,
                kind=CallKind.DIRECT,
                targets=IndirectTargetSet(
                    known_targets=(_location(0x3000),),
                    complete=True,
                ),
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=2,
            basic_blocks=2,
            call_sites=1,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    report = recover_address_provenance(
        module,
        control_flow,
        (*caller_facts, callee_fact),
    )
    address = report.addresses[(0x3000, callee_fact.memory_operands[0].operand_index)]

    assert address.kind == AddressKind.GLOBAL
    assert address.base == "app@0x2000"


def test_role_reachable_calls_do_not_mix_callee_arguments() -> None:
    first_caller = disassemble_bytes(
        bytes.fromhex("488d3df90f0000e800000000"), address=0x1000
    )
    second_caller = disassemble_bytes(
        bytes.fromhex("488d3df91f0000e800000000"), address=0x2000
    )
    callee_fact = disassemble_bytes(bytes.fromhex("8b07"), address=0x4000)[0]
    module = ModuleFingerprint(
        path="/bin/app",
        role=ModuleRole.EXECUTABLE,
        size=0x5000,
        sha256=HASH,
        elf=ElfMetadata(
            elf_class=64,
            little_endian=True,
            machine="EM_X86_64",
            elf_type="ET_EXEC",
        ),
    )
    call_sites = tuple(
        CallSite(
            location=_location(facts[-1].pc),
            containing_function_pc=entry,
            block_pc=entry,
            kind=CallKind.DIRECT,
            targets=IndirectTargetSet(
                known_targets=(_location(0x4000),), complete=True
            ),
        )
        for entry, facts in ((0x1000, first_caller), (0x2000, second_caller))
    )
    control_flow = ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0x1000,
        functions=tuple(
            FunctionFact(location=_location(pc), size=12 if pc != 0x4000 else 2, block_pcs=(pc,))
            for pc in (0x1000, 0x2000, 0x4000)
        ),
        basic_blocks=(
            BasicBlockFact(location=_location(0x1000), size=12, instruction_pcs=tuple(item.pc for item in first_caller)),
            BasicBlockFact(location=_location(0x2000), size=12, instruction_pcs=tuple(item.pc for item in second_caller)),
            BasicBlockFact(location=_location(0x4000), size=2, instruction_pcs=(0x4000,)),
        ),
        call_sites=call_sites,
        coverage=CFGCoverage(
            angr_version="test",
            functions=3,
            basic_blocks=3,
            call_sites=2,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    report = recover_address_provenance(
        module,
        control_flow,
        (*first_caller, *second_caller, callee_fact),
        reachable_function_pcs={0x1000, 0x4000},
    )
    address = report.addresses[
        (0x4000, callee_fact.memory_operands[0].operand_index)
    ]

    assert address.kind == AddressKind.GLOBAL
    assert address.base == "app@0x2000"


def test_scaled_global_pointer_survives_cfg_block_split() -> None:
    code = bytes.fromhex(
        "488b3d98282000"  # mov rdi, [rip + 0x202898] -> slot 0x2070f0
        "8b45c8"          # mov eax, [rbp - 0x38]
        "4863d0"          # movsxd rdx, eax
        "4889d0"          # mov rax, rdx
        "4801c0"          # add rax, rax
        "4801d0"          # add rax, rdx (new CFG block)
        "48c1e002"        # shl rax, 2
        "4801d0"          # add rax, rdx
        "48c1e003"        # shl rax, 3
        "4801f8"          # add rax, rdi
        "f20f104020"      # movsd xmm0, [rax + 0x20]
    )
    facts = disassemble_bytes(code, address=0x4851)
    split_pc = 0x4864
    first_pcs = tuple(fact.pc for fact in facts if fact.pc < split_pc)
    second_pcs = tuple(fact.pc for fact in facts if fact.pc >= split_pc)
    module = ModuleFingerprint(
        path="/bin/app",
        role=ModuleRole.EXECUTABLE,
        size=0x300000,
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
        entry_pc=0x4851,
        functions=(
            FunctionFact(
                location=_location(0x4851),
                size=len(code),
                block_pcs=(0x4851, split_pc),
            ),
        ),
        basic_blocks=(
            BasicBlockFact(
                location=_location(0x4851),
                size=split_pc - 0x4851,
                instruction_pcs=first_pcs,
                successor_pcs=(split_pc,),
            ),
            BasicBlockFact(
                location=_location(split_pc),
                size=len(code) - (split_pc - 0x4851),
                instruction_pcs=second_pcs,
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=1,
            basic_blocks=2,
            call_sites=0,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    report = recover_address_provenance(
        module,
        control_flow,
        facts,
        function_entry_arguments={
            0x4851: {
                "global-pointer@0x2070f0": AbstractAddress(
                    kind=AddressKind.HEAP,
                    base="heap:malloc@0x516f",
                )
            }
        },
    )
    use = facts[-1]
    address = report.addresses[(use.pc, use.memory_operands[0].operand_index)]

    assert address.base == "heap:malloc@0x516f"
    assert address.index_coefficient == 104
    assert address.provenance["index_term"] == "frame@0x4851-56"


def test_frame_arithmetic_kills_copied_symbolic_value() -> None:
    code = bytes.fromhex(
        "8b45e8"          # mov eax, [rbp - 0x18]
        "8945e0"          # mov [rbp - 0x20], eax
        "8345e001"        # add dword ptr [rbp - 0x20], 1
        "8b55e0"          # mov edx, [rbp - 0x20]
        "4863d2"          # movsxd rdx, edx
        "488b05e80f0000"  # mov rax, [rip + 0xfe8] -> slot 0x2000
        "488d0490"        # lea rax, [rax + rdx*4]
        "8b08"            # mov ecx, [rax]
    )
    facts = disassemble_bytes(code, address=0x1000)
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
        functions=(FunctionFact(location=_location(0x1000), size=len(code), block_pcs=(0x1000,)),),
        basic_blocks=(BasicBlockFact(location=_location(0x1000), size=len(code), instruction_pcs=tuple(item.pc for item in facts)),),
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
    address = addresses[(facts[-1].pc, facts[-1].memory_operands[0].operand_index)]

    assert address.provenance["index_term"] == "frame@0x1000-32"


def test_call_argument_address_source_is_recorded_before_call_clobber() -> None:
    code = bytes.fromhex(
        "488d3df90f0000"  # lea rdi, [rip + 0xff9] -> object 0x2000
        "e800000000"      # call 0x100c
    )
    facts = disassemble_bytes(code, address=0x1000)
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
                instruction_pcs=tuple(item.pc for item in facts),
            ),
        ),
        coverage=CFGCoverage(
            angr_version="test",
            functions=1,
            basic_blocks=1,
            call_sites=1,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
    )

    report = recover_address_provenance(module, control_flow, facts)

    first_argument = report.call_arguments[facts[-1].pc][0]
    assert first_argument is not None
    assert first_argument.kind == AddressKind.GLOBAL
    assert first_argument.base == "app@0x2000"
