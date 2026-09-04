from __future__ import annotations

from pathlib import Path

from capstone import CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86 import X86_OP_MEM, X86_OP_REG

from bmo_check_static.binary.angr_backend import AngrBackendError, load_cfg
from bmo_check_static.binary.elf import executable_segments
from bmo_check_static.binary.symbols import (
    function_pointer_sections,
    function_symbols,
    relocations,
)
from bmo_check_static.model import (
    BasicBlockFact,
    CallKind,
    CallSite,
    CFGCoverage,
    CodeLocation,
    ControlFlowReport,
    FunctionFact,
    IndirectSiteFact,
    IndirectTargetSet,
    ModuleFingerprint,
    ProgramManifest,
    RelocationFact,
    UnknownFact,
    UnknownKind,
)


def _location(
    module: ModuleFingerprint, pc: int, symbol: str | None = None
) -> CodeLocation:
    return CodeLocation(
        module_path=module.path,
        module_sha256=module.sha256,
        pc=pc,
        symbol=symbol,
    )


def _control_instruction(context: object, block_address: int) -> object | None:
    try:
        block = context.project.factory.block(block_address)
        instructions = list(block.capstone.insns)
        for wrapped in reversed(instructions):
            insn = wrapped.insn
            if insn.group(CS_GRP_CALL) or insn.group(CS_GRP_JUMP):
                return insn
    except Exception:
        pass
    return None


def _instruction_pc(context: object, block_address: int) -> tuple[int, str]:
    instruction = _control_instruction(context, block_address)
    if instruction is None:
        return context.to_elf_pc(block_address), "unknown"
    return context.to_elf_pc(instruction.address), instruction.mnemonic


def _internal_target_set(
    context: object, address: int, symbol: str | None = None
) -> IndirectTargetSet:
    return IndirectTargetSet(
        known_targets=(
            _location(context.module, context.to_elf_pc(address), symbol),
        ),
        complete=True,
        evidence=("direct target inside the analyzed ELF",),
    )


def _plt_target_set(
    symbol: str,
    definitions_by_name: dict[str, tuple[CodeLocation, ...]],
) -> IndirectTargetSet:
    targets = definitions_by_name.get(symbol, ())
    if targets:
        return IndirectTargetSet(
            known_targets=targets,
            complete=True,
            evidence=(
                "ELF PLT symbol",
                "definition found in concrete dependency closure",
            ),
        )
    return IndirectTargetSet(
        known_targets=(),
        complete=False,
        evidence=("ELF PLT symbol",),
        reason=f"no concrete definition for PLT symbol {symbol!r}",
    )


def _relocation_target_set(
    relocation: RelocationFact,
    definitions_by_name: dict[str, tuple[CodeLocation, ...]],
) -> IndirectTargetSet:
    targets = definitions_by_name.get(relocation.symbol_name, ())
    if targets:
        return IndirectTargetSet(
            known_targets=targets,
            complete=True,
            evidence=(
                "RIP-relative ELF relocation",
                "definition found in concrete dependency closure",
            ),
        )
    if relocation.undefined and relocation.binding == "STB_WEAK":
        return IndirectTargetSet(
            known_targets=(),
            complete=True,
            evidence=(
                "undefined weak relocation",
                "no definition exists in the concrete dependency closure",
                "the loader binds the slot to null",
            ),
        )
    return IndirectTargetSet(
        complete=False,
        evidence=("RIP-relative ELF relocation",),
        reason=f"no concrete definition for relocated symbol {relocation.symbol_name!r}",
    )


def _rip_memory_address(instruction: object) -> int | None:
    for operand in instruction.operands:
        if operand.type != X86_OP_MEM:
            continue
        if instruction.reg_name(operand.mem.base) != "rip":
            continue
        return int(instruction.address + instruction.size + operand.mem.disp)
    return None


def _indirect_relocation(
    context: object,
    block_address: int,
    relocations_by_offset: dict[int, RelocationFact],
) -> RelocationFact | None:
    instruction = _control_instruction(context, block_address)
    if instruction is None or not instruction.operands:
        return None

    address = _rip_memory_address(instruction)
    if address is not None:
        return relocations_by_offset.get(context.to_elf_pc(address))

    first = instruction.operands[0]
    if first.type != X86_OP_REG:
        return None
    target_register = instruction.reg_name(first.reg)
    try:
        block = context.project.factory.block(block_address)
        instructions = [item.insn for item in block.capstone.insns]
    except Exception:
        return None
    for candidate in reversed(instructions[:-1]):
        if len(candidate.operands) < 2:
            continue
        destination, source = candidate.operands[0], candidate.operands[1]
        if destination.type != X86_OP_REG:
            continue
        if candidate.reg_name(destination.reg) != target_register:
            continue
        if source.type != X86_OP_MEM:
            return None
        address = _rip_memory_address(candidate)
        if address is None:
            return None
        return relocations_by_offset.get(context.to_elf_pc(address))
    return None


def _plt_resolver_targets(
    plt_symbols: tuple[str, ...],
    definitions_by_name: dict[str, tuple[CodeLocation, ...]],
) -> IndirectTargetSet:
    targets: dict[tuple[str, int], CodeLocation] = {}
    missing: list[str] = []
    for symbol in plt_symbols:
        definitions = definitions_by_name.get(symbol, ())
        if not definitions:
            missing.append(symbol)
        for location in definitions:
            targets[(location.module_sha256, location.pc)] = location
    if missing:
        return IndirectTargetSet(
            known_targets=tuple(targets.values()),
            complete=False,
            evidence=("ELF PLT resolver entry",),
            reason=f"PLT definitions are missing for: {', '.join(sorted(missing))}",
        )
    return IndirectTargetSet(
        known_targets=tuple(
            sorted(targets.values(), key=lambda item: (item.module_path, item.pc))
        ),
        complete=True,
        evidence=(
            "ELF PLT resolver entry",
            "all PLT symbols bind inside the concrete dependency closure",
        ),
    )


def _fixed_pointer_targets(
    context: object,
    section_names: tuple[str, ...],
) -> IndirectTargetSet:
    sections = function_pointer_sections(context.module, section_names)
    values = tuple(
        value for name in section_names for value in sections.get(name, ())
    )
    if not values:
        return IndirectTargetSet(
            complete=False,
            reason="fixed function-pointer section is empty or unavailable",
        )
    executable = executable_segments(Path(context.module.path))
    ranges = tuple(
        (item.virtual_address, item.virtual_address + len(item.data))
        for item in executable
    )
    targets = tuple(
        _location(context.module, value)
        for value in values
        if any(start <= value < end for start, end in ranges)
    )
    if len(targets) != len(values):
        return IndirectTargetSet(
            known_targets=targets,
            complete=False,
            evidence=("fixed ELF function-pointer section",),
            reason="one or more table entries do not resolve into executable sections",
        )
    return IndirectTargetSet(
        known_targets=targets,
        complete=True,
        evidence=(
            "fixed ELF function-pointer section",
            "every table entry resolves into an executable section",
        ),
    )


def _jump_table_targets(
    context: object, indirect: object
) -> tuple[tuple[CodeLocation, ...], bool]:
    resolved = tuple(sorted(int(item) for item in indirect.resolved_targets))
    if not resolved:
        return (), False
    targets = tuple(
        _location(context.module, context.to_elf_pc(address))
        for address in resolved
        if context.contains_rebased(address)
    )
    if len(targets) != len(resolved) or not bool(getattr(indirect, "jumptable", False)):
        return targets, False

    executable = executable_segments(Path(context.module.path))
    ranges = tuple(
        (item.virtual_address, item.virtual_address + len(item.data))
        for item in executable
    )
    all_executable = all(
        any(start <= target.pc < end for start, end in ranges)
        for target in targets
    )
    entries = getattr(indirect, "jumptable_entries", None)
    return targets, bool(all_executable and entries)


def _indirect_target_set(
    context: object, indirect: object | None
) -> IndirectTargetSet:
    if indirect is None:
        return IndirectTargetSet(
            complete=False,
            reason="angr did not recover a target set",
        )
    targets, validated_table = _jump_table_targets(context, indirect)
    if validated_table:
        return IndirectTargetSet(
            known_targets=targets,
            complete=True,
            evidence=(
                "angr jump-table entries",
                "every entry resolves into an executable ELF section",
            ),
        )
    return IndirectTargetSet(
        known_targets=targets,
        complete=False,
        evidence=("angr candidate targets",) if targets else (),
        reason="candidate targets are not a proven closed set",
    )


def _empty_failure_report(
    module: ModuleFingerprint, reason: str
) -> ControlFlowReport:
    unknown = UnknownFact(
        kind=UnknownKind.CFG_BACKEND_FAILURE,
        reason=reason,
        impact="reachable code and indirect targets are unavailable",
        module=module.path,
    )
    return ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=0,
        coverage=CFGCoverage(
            angr_version="unknown",
            functions=0,
            basic_blocks=0,
            call_sites=0,
            indirect_sites=0,
            complete_indirect_sites=0,
            incomplete_indirect_sites=0,
        ),
        unknowns=(unknown,),
    )


def recover_control_flow(
    module: ModuleFingerprint,
    manifest: ProgramManifest,
) -> ControlFlowReport:
    try:
        context = load_cfg(module)
    except AngrBackendError as error:
        return _empty_failure_report(module, str(error))

    main_object = context.project.loader.main_object
    definitions_by_name: dict[str, tuple[CodeLocation, ...]] = {}
    for library in manifest.libraries:
        local: dict[str, list[CodeLocation]] = {}
        for symbol in function_symbols(library):
            local.setdefault(symbol.name, []).append(
                CodeLocation(
                    module_path=symbol.module_path,
                    module_sha256=symbol.module_sha256,
                    pc=symbol.pc,
                    symbol=symbol.name,
                )
            )
        for name, locations in local.items():
            if name not in definitions_by_name:
                definitions_by_name[name] = tuple(
                    sorted(
                        {item.pc: item for item in locations}.values(),
                        key=lambda item: item.pc,
                    )
                )
    reverse_plt = {
        int(address): symbol for symbol, address in main_object.plt.items()
    }
    module_relocations = {
        item.offset: item for item in relocations(module)
    }
    plt_symbols = tuple(sorted(main_object.plt))
    plt_section = next(
        (
            item
            for item in executable_segments(Path(module.path))
            if item.name == ".plt"
        ),
        None,
    )
    plt_resolver_pc = plt_section.virtual_address if plt_section else None
    indirect_by_address = {
        int(address): item for address, item in context.cfg.indirect_jumps.items()
    }
    unknowns: list[UnknownFact] = []
    functions: list[FunctionFact] = []
    blocks_by_pc: dict[int, BasicBlockFact] = {}
    call_sites: list[CallSite] = []
    indirect_sites: list[IndirectSiteFact] = []

    function_by_block: dict[int, int] = {}
    function_name_by_block: dict[int, str] = {}
    for function in sorted(
        context.cfg.kb.functions.values(), key=lambda item: int(item.addr)
    ):
        if not context.contains_rebased(function.addr):
            continue
        block_pcs: list[int] = []
        try:
            function_blocks = tuple(function.blocks)
        except Exception:
            function_blocks = ()
        for block in function_blocks:
            block_pc = context.to_elf_pc(block.addr)
            block_pcs.append(block_pc)
            function_by_block[int(block.addr)] = context.to_elf_pc(function.addr)
            function_name_by_block[int(block.addr)] = function.name or ""
            node = context.cfg.model.get_any_node(block.addr, anyaddr=False)
            successor_pcs: list[int] = []
            if node is not None:
                for successor in context.cfg.graph.successors(node):
                    if context.contains_rebased(successor.addr):
                        successor_pcs.append(context.to_elf_pc(successor.addr))
            instruction_pcs = tuple(
                context.to_elf_pc(item.insn.address)
                for item in block.capstone.insns
            )
            blocks_by_pc[block_pc] = BasicBlockFact(
                location=_location(module, block_pc),
                size=int(block.size),
                instruction_pcs=instruction_pcs,
                successor_pcs=tuple(sorted(set(successor_pcs))),
            )

        function_pc = context.to_elf_pc(function.addr)
        functions.append(
            FunctionFact(
                location=_location(module, function_pc, function.name or None),
                size=int(function.size),
                block_pcs=tuple(sorted(set(block_pcs))),
                returning=getattr(function, "returning", None),
                is_plt=bool(getattr(function, "is_plt", False)),
            )
        )

        for block_address in function.get_call_sites():
            block_address = int(block_address)
            target = function.get_call_target(block_address)
            return_address = function.get_call_return(block_address)
            call_pc, _ = _instruction_pc(context, block_address)
            target_symbol: str | None = None
            if target is not None and int(target) in reverse_plt:
                target_symbol = reverse_plt[int(target)]
                kind = CallKind.PLT
                targets = _plt_target_set(target_symbol, definitions_by_name)
            elif target is not None and context.contains_rebased(int(target)):
                kind = CallKind.DIRECT
                targets = _internal_target_set(context, int(target))
            else:
                kind = CallKind.INDIRECT
                relocation = _indirect_relocation(
                    context, block_address, module_relocations
                )
                if relocation is not None:
                    target_symbol = relocation.symbol_name
                    targets = _relocation_target_set(
                        relocation, definitions_by_name
                    )
                elif function.name == "__libc_csu_init":
                    targets = _fixed_pointer_targets(
                        context, (".preinit_array", ".init_array")
                    )
                else:
                    targets = _indirect_target_set(
                        context, indirect_by_address.get(block_address)
                    )
            call_sites.append(
                CallSite(
                    location=_location(module, call_pc),
                    containing_function_pc=function_pc,
                    block_pc=context.to_elf_pc(block_address),
                    kind=kind,
                    target_symbol=target_symbol,
                    targets=targets,
                    return_pc=(
                        context.to_elf_pc(int(return_address))
                        if return_address is not None
                        else None
                    ),
                )
            )
            if not targets.complete:
                unknowns.append(
                    UnknownFact(
                        kind=UnknownKind.INCOMPLETE_INDIRECT_TARGET,
                        reason=targets.reason or "call target set is incomplete",
                        impact="callee shared-memory effects may be missing",
                        module=module.path,
                        pc=call_pc,
                        details={"target_symbol": target_symbol},
                    )
                )

    for block_address, indirect in sorted(indirect_by_address.items()):
        site_pc, mnemonic = _instruction_pc(context, block_address)
        relocation = _indirect_relocation(
            context, block_address, module_relocations
        )
        if relocation is not None:
            targets = _relocation_target_set(relocation, definitions_by_name)
        elif (
            plt_resolver_pc is not None
            and context.to_elf_pc(block_address) == plt_resolver_pc
        ):
            targets = _plt_resolver_targets(plt_symbols, definitions_by_name)
        elif function_name_by_block.get(block_address) == "__libc_csu_init":
            targets = _fixed_pointer_targets(
                context, (".preinit_array", ".init_array")
            )
        else:
            targets = _indirect_target_set(context, indirect)
        containing_function = function_by_block.get(block_address)
        indirect_sites.append(
            IndirectSiteFact(
                location=_location(module, site_pc),
                containing_function_pc=containing_function,
                control_flow=mnemonic,
                targets=targets,
            )
        )
        if not targets.complete:
            unknowns.append(
                UnknownFact(
                    kind=UnknownKind.INCOMPLETE_INDIRECT_TARGET,
                    reason=targets.reason or "indirect target set is incomplete",
                    impact="reachable shared-memory effects may be missing",
                    module=module.path,
                    pc=site_pc,
                    details={
                        "known_targets": [
                            {
                                "module": target.module_path,
                                "pc": target.pc,
                            }
                            for target in targets.known_targets
                        ]
                    },
                )
            )

    incomplete = sum(not item.targets.complete for item in indirect_sites)
    coverage = CFGCoverage(
        angr_version=context.angr_version,
        functions=len(functions),
        basic_blocks=len(blocks_by_pc),
        call_sites=len(call_sites),
        indirect_sites=len(indirect_sites),
        complete_indirect_sites=len(indirect_sites) - incomplete,
        incomplete_indirect_sites=incomplete,
    )
    unique_unknowns = {
        (item.kind, item.module, item.pc, item.reason): item for item in unknowns
    }
    return ControlFlowReport(
        module_path=module.path,
        module_sha256=module.sha256,
        entry_pc=context.to_elf_pc(context.project.entry),
        functions=tuple(functions),
        basic_blocks=tuple(
            blocks_by_pc[key] for key in sorted(blocks_by_pc)
        ),
        call_sites=tuple(
            sorted(call_sites, key=lambda item: item.location.pc)
        ),
        indirect_sites=tuple(
            sorted(indirect_sites, key=lambda item: item.location.pc)
        ),
        coverage=coverage,
        unknowns=tuple(unique_unknowns.values()),
    )
