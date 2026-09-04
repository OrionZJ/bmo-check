from __future__ import annotations

from pathlib import Path

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from bmo_check_static.binary.angr_backend import AngrBackendError, load_cfg
from bmo_check_static.binary.elf import executable_segments
from bmo_check_static.binary.symbols import function_symbols
from bmo_check_static.model import (
    CodeLocation,
    ControlFlowReport,
    IndirectTargetSet,
    ModuleFingerprint,
    ProgramManifest,
    ThreadCreateFact,
    ThreadDiscoveryReport,
    ThreadJoinFact,
    ThreadRole,
    UnknownFact,
    UnknownKind,
)


def _location(module: ModuleFingerprint, pc: int, symbol: str | None = None) -> CodeLocation:
    return CodeLocation(
        module_path=module.path,
        module_sha256=module.sha256,
        pc=pc,
        symbol=symbol,
    )


def _definition_before_call(
    context: object, block_pc: int, call_pc: int, register: str
) -> tuple[int | None, str | None, bool]:
    """反向跟踪一个调用参数；只把块内常量定义当成封闭证明。"""
    wanted = register
    try:
        block = context.project.factory.block(context.to_rebased(block_pc))
        instructions = [
            item.insn
            for item in block.capstone.insns
            if context.to_elf_pc(item.insn.address) < call_pc
        ]
    except Exception:
        return None, None, False

    for instruction in reversed(instructions):
        if not instruction.operands:
            continue
        destination = instruction.operands[0]
        if destination.type != X86_OP_REG:
            continue
        if instruction.reg_name(destination.reg) != wanted:
            continue
        origin = f"{instruction.mnemonic} {instruction.op_str}".strip()
        if len(instruction.operands) < 2:
            return None, origin, False
        source = instruction.operands[1]
        if source.type == X86_OP_IMM:
            return context.to_elf_pc(int(source.imm)), origin, True
        if source.type == X86_OP_REG:
            wanted = instruction.reg_name(source.reg)
            continue
        if (
            source.type == X86_OP_MEM
            and instruction.mnemonic == "lea"
            and instruction.reg_name(source.mem.base) == "rip"
        ):
            address = int(instruction.address + instruction.size + source.mem.disp)
            return context.to_elf_pc(address), origin, True
        # 内存中保存的 callback 可能在运行时被改写，单个当前值不能封闭目标集合。
        return None, origin, False
    return None, None, False


def _executable_pc(module: ModuleFingerprint, pc: int) -> bool:
    return any(
        segment.virtual_address <= pc < segment.virtual_address + len(segment.data)
        for segment in executable_segments(Path(module.path))
    )


def _symbol_by_pc(module: ModuleFingerprint) -> dict[int, str]:
    return {symbol.pc: symbol.name for symbol in function_symbols(module)}


def _role_reachability(
    report: ControlFlowReport, role_roots: dict[str, tuple[int, ...]]
) -> dict[str, set[int]]:
    function_pcs = {item.location.pc for item in report.functions}
    edges: dict[int, set[int]] = {}
    for call in report.call_sites:
        for target in call.targets.known_targets:
            if target.module_sha256 == report.module_sha256 and target.pc in function_pcs:
                edges.setdefault(call.containing_function_pc, set()).add(target.pc)
    reachable: dict[str, set[int]] = {}
    for role, roots in role_roots.items():
        pending = list(roots)
        seen: set[int] = set()
        while pending:
            function_pc = pending.pop()
            if function_pc in seen:
                continue
            seen.add(function_pc)
            pending.extend(edges.get(function_pc, ()))
        reachable[role] = seen
    return reachable


def _containing_role(
    reachability: dict[str, set[int]], function_pc: int
) -> tuple[str, bool]:
    candidates = sorted(
        role for role, functions in reachability.items() if function_pc in functions
    )
    if len(candidates) == 1:
        return candidates[0], True
    return "unknown", False


def discover_pthread_threads(
    module: ModuleFingerprint,
    manifest: ProgramManifest,
    control_flow: ControlFlowReport,
) -> ThreadDiscoveryReport:
    try:
        context = load_cfg(module)
    except AngrBackendError as error:
        unknown = UnknownFact(
            kind=UnknownKind.CFG_BACKEND_FAILURE,
            reason=str(error),
            impact="pthread callback arguments cannot be recovered",
            module=module.path,
        )
        return ThreadDiscoveryReport(unknowns=(unknown,))

    symbols = _symbol_by_pc(module)
    main_function = next(
        (
            item.location
            for item in control_flow.functions
            if item.location.symbol == "main"
        ),
        _location(module, control_flow.entry_pc),
    )
    root_targets = IndirectTargetSet(
        known_targets=(main_function,),
        complete=True,
        evidence=((
            "main function recovered from the executable CFG"
            if main_function.symbol == "main"
            else "ELF entry point"
        ),),
    )
    roles: list[ThreadRole] = [
        ThreadRole(id="main", start_targets=root_targets, complete=True)
    ]
    creates: list[ThreadCreateFact] = []
    unknowns: list[UnknownFact] = []
    recovered_creates: list[tuple[object, str, IndirectTargetSet, str | None]] = []

    create_calls = [
        call for call in control_flow.call_sites if call.target_symbol == "pthread_create"
    ]
    for call in create_calls:
        callback_pc, _, constant = _definition_before_call(
            context, call.block_pc, call.location.pc, "rdx"
        )
        _, argument_origin, _ = _definition_before_call(
            context, call.block_pc, call.location.pc, "rcx"
        )
        callback_valid = (
            constant
            and callback_pc is not None
            and _executable_pc(module, callback_pc)
        )
        if callback_valid:
            target = _location(module, callback_pc, symbols.get(callback_pc))
            targets = IndirectTargetSet(
                known_targets=(target,),
                complete=True,
                evidence=("SysV third argument has a block-local constant definition",),
            )
        else:
            targets = IndirectTargetSet(
                complete=False,
                reason="pthread_create start routine is not a proven executable constant",
            )
            unknowns.append(
                UnknownFact(
                    kind=UnknownKind.UNKNOWN_THREAD_ENTRY,
                    reason=targets.reason or "pthread callback is unknown",
                    impact="reachable worker code may be missing",
                    module=module.path,
                    pc=call.location.pc,
                )
            )
        role_id = f"pthread@{call.location.pc:x}"
        recovered_creates.append((call, role_id, targets, argument_origin))

    role_roots: dict[str, tuple[int, ...]] = {"main": (main_function.pc,)}
    for _, role_id, targets, _ in recovered_creates:
        role_roots[role_id] = tuple(item.pc for item in targets.known_targets)
    reachability = _role_reachability(control_flow, role_roots)

    for call, role_id, targets, argument_origin in recovered_creates:
        parent, parent_complete = _containing_role(
            reachability, call.containing_function_pc
        )
        if not parent_complete:
            unknowns.append(
                UnknownFact(
                    kind=UnknownKind.REACHING_DEFINITION_FAILURE,
                    reason="pthread_create site is reachable from zero or multiple thread roles",
                    impact="the child thread's parent role is unknown",
                    module=module.path,
                    pc=call.location.pc,
                )
            )
        roles.append(
            ThreadRole(
                id=role_id,
                parent_role=parent,
                create_site=call.location,
                start_targets=targets,
                argument_origin=argument_origin,
                complete=targets.complete and parent_complete,
            )
        )
        creates.append(
            ThreadCreateFact(
                call_site=call.location,
                parent_role=parent,
                child_role=role_id,
                start_targets=targets,
                argument_origin=argument_origin,
            )
        )

    child_roles = tuple(item.id for item in roles if item.id != "main")
    joins: list[ThreadJoinFact] = []
    for call in control_flow.call_sites:
        if call.target_symbol != "pthread_join":
            continue
        parent, parent_complete = _containing_role(
            reachability, call.containing_function_pc
        )
        complete = parent_complete and len(child_roles) == 1
        reason = (
            None
            if complete
            else "join caller or handle cannot be mapped to one recovered thread role"
        )
        joins.append(
            ThreadJoinFact(
                call_site=call.location,
                parent_role=parent,
                candidate_child_roles=child_roles,
                complete=complete,
                reason=reason,
            )
        )
        if not complete:
            unknowns.append(
                UnknownFact(
                    kind=UnknownKind.UNKNOWN_JOIN_RELATION,
                    reason=reason or "join relation is unknown",
                    impact="thread lifetime ordering cannot be closed",
                    module=module.path,
                    pc=call.location.pc,
                )
            )

    return ThreadDiscoveryReport(
        roles=tuple(roles),
        creates=tuple(creates),
        joins=tuple(joins),
        unknowns=tuple(unknowns),
    )
