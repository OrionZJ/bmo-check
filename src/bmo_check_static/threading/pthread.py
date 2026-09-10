from __future__ import annotations

from pathlib import Path

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from bmo_check_core import EvidenceLedger
from bmo_check_static.binary.angr_backend import AngrBackendError, load_cfg
from bmo_check_static.binary.evidence import emit_static_unknown
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
    ThreadParallelFact,
    ThreadRole,
    UnknownFact,
    UnknownKind,
)


# GCC OpenMP lowering把并行函数地址作为 GOMP_parallel 的第一个参数传入。
# 这些调用没有 pthread_create 那样的 handle，但返回前仍是一个隐式
# 的 worker 阶段；恢复它们才能避免把 worker 代码误归到 main 线程。
_OPENMP_PARALLEL_APIS = frozenset(
    {
        "GOMP_parallel",
        "GOMP_parallel_start",
        "GOMP_parallel_loop_static_start",
        "GOMP_parallel_loop_dynamic_start",
        "GOMP_parallel_loop_guided_start",
        "GOMP_parallel_loop_runtime_start",
    }
)


def _location(module: ModuleFingerprint, pc: int, symbol: str | None = None) -> CodeLocation:
    return CodeLocation(
        module_path=module.path,
        module_sha256=module.sha256,
        pc=pc,
        symbol=symbol,
    )


def _unknown(
    kind: UnknownKind,
    reason: str,
    impact: str,
    *,
    module: str | None = None,
    pc: int | None = None,
    function: str | None = None,
    details: dict[str, object] | None = None,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.threading",
) -> UnknownFact:
    """保留旧线程报告，同时把同一个缺口写入可审计的 evidence ledger。"""

    return emit_static_unknown(
        kind,
        reason,
        impact,
        module=module,
        pc=pc,
        function=function,
        details=details,
        canonical_ledger=canonical_ledger,
        canonical_scope=canonical_scope,
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


def _main_reachability(
    report: ControlFlowReport, main_pc: int
) -> tuple[set[int], bool]:
    """沿已封闭的本 ELF 调用边恢复 main 可达函数。

    ``pthread_create`` 常出现在库适配层或死代码里。只有主线程能沿
    已知边到达它时，才把该调用纳入线程角色；若 main 可达函数里还有
    未封闭间接控制流，任何隐藏目标都可能创建线程，此时返回 False，
    调用方继续使用原来的全量保守结果。
    """

    function_pcs = {item.location.pc for item in report.functions}
    graph: dict[int, set[int]] = {}
    for call in report.call_sites:
        if not call.targets.complete:
            continue
        local_targets = {
            target.pc
            for target in call.targets.known_targets
            if target.module_sha256 == report.module_sha256
            and target.pc in function_pcs
        }
        if local_targets:
            graph.setdefault(call.containing_function_pc, set()).update(
                local_targets
            )
    reachable: set[int] = set()
    pending = [main_pc]
    while pending:
        function_pc = pending.pop()
        if function_pc in reachable:
            continue
        reachable.add(function_pc)
        pending.extend(graph.get(function_pc, ()))
    closed = not any(
        not site.targets.complete
        and site.containing_function_pc in reachable
        for site in report.indirect_sites
    ) and not any(
        not call.targets.complete
        and call.containing_function_pc in reachable
        for call in report.call_sites
    )
    return reachable, closed


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
    *,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.threading",
) -> ThreadDiscoveryReport:
    try:
        context = load_cfg(module)
    except AngrBackendError as error:
        unknown = _unknown(
            UnknownKind.CFG_BACKEND_FAILURE,
            str(error),
            "pthread callback arguments cannot be recovered",
            module=module.path,
            canonical_ledger=canonical_ledger,
            canonical_scope=canonical_scope,
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

    main_reachable, main_call_graph_closed = _main_reachability(
        control_flow, main_function.pc
    )
    all_create_calls = [
        call
        for call in control_flow.call_sites
        if call.target_symbol == "pthread_create"
    ]
    create_calls = (
        [
            call
            for call in all_create_calls
            if call.containing_function_pc in main_reachable
        ]
        if main_call_graph_closed
        else all_create_calls
    )
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
                _unknown(
                    UnknownKind.UNKNOWN_THREAD_ENTRY,
                    targets.reason or "pthread callback is unknown",
                    "reachable worker code may be missing",
                    module=module.path,
                    pc=call.location.pc,
                    details={"api": "pthread_create"},
                    canonical_ledger=canonical_ledger,
                    canonical_scope=canonical_scope,
                )
            )
        role_id = f"pthread@{call.location.pc:x}"
        recovered_creates.append((call, role_id, targets, argument_origin))

    # OpenMP worker 没有可供 join 的 pthread handle。这里只恢复实际传给
    # runtime 的 callback；角色按并行区入口分开，后面的隐式 barrier 才能
    # 只连接本阶段的 worker 事件。
    openmp_entries: list[tuple[object, str, IndirectTargetSet, str | None]] = []
    all_openmp_calls = [
        call
        for call in control_flow.call_sites
        if call.target_symbol in _OPENMP_PARALLEL_APIS
    ]
    openmp_calls = (
        [
            call
            for call in all_openmp_calls
            if call.containing_function_pc in main_reachable
        ]
        if main_call_graph_closed
        else all_openmp_calls
    )
    for call in openmp_calls:
        callback_pc, origin, constant = _definition_before_call(
            context, call.block_pc, call.location.pc, "rdi"
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
                evidence=(
                    "SysV first argument has a block-local constant OpenMP callback",
                ),
            )
            # 角色按并行区入口而不是 callback 地址命名；同一 callback
            # 在两个阶段复用时，两个阶段不能共享同一组事件边界。
            role_id = f"openmp@{call.location.pc:x}"
        else:
            targets = IndirectTargetSet(
                complete=False,
                reason=(
                    "OpenMP parallel callback is not a proven executable constant"
                ),
            )
            role_id = f"openmp@{call.location.pc:x}"
            unknowns.append(
                _unknown(
                    UnknownKind.UNKNOWN_THREAD_ENTRY,
                    targets.reason or "OpenMP callback is unknown",
                    "reachable OpenMP worker code may be missing",
                    module=module.path,
                    pc=call.location.pc,
                    details={"api": call.target_symbol or "openmp"},
                    canonical_ledger=canonical_ledger,
                    canonical_scope=canonical_scope,
                )
            )
        entry = (call, role_id, targets, origin)
        openmp_entries.append(entry)

    role_roots: dict[str, tuple[int, ...]] = {"main": (main_function.pc,)}
    for _, role_id, targets, _ in recovered_creates:
        role_roots[role_id] = tuple(item.pc for item in targets.known_targets)
    for _, role_id, targets, _ in openmp_entries:
        # role_id 按 call site 区分并行阶段；这里仍用 setdefault 保留该
        # 阶段 callback 的单一入口。
        role_roots.setdefault(
            role_id, tuple(item.pc for item in targets.known_targets)
        )
    reachability = _role_reachability(control_flow, role_roots)

    for call, role_id, targets, argument_origin in recovered_creates:
        parent, parent_complete = _containing_role(
            reachability, call.containing_function_pc
        )
        if not parent_complete:
            unknowns.append(
                _unknown(
                    UnknownKind.REACHING_DEFINITION_FAILURE,
                    "pthread_create site is reachable from zero or multiple thread roles",
                    "the child thread's parent role is unknown",
                    module=module.path,
                    pc=call.location.pc,
                    details={"api": "pthread_create"},
                    canonical_ledger=canonical_ledger,
                    canonical_scope=canonical_scope,
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

    # OpenMP 入口没有 pthread handle，因此不写入 creates；否则下面的
    # pthread_join 会错误地要求它们存在一个可 join 的角色。
    openmp_roles: dict[str, list[tuple[str, bool]]] = {}
    parallel_regions: list[ThreadParallelFact] = []
    for call, role_id, targets, argument_origin in openmp_entries:
        parent, parent_complete = _containing_role(
            reachability, call.containing_function_pc
        )
        openmp_roles.setdefault(role_id, []).append((parent, parent_complete))
        if call.target_symbol == "GOMP_parallel":
            # 只有合并式 GOMP_parallel 在同一个调用返回前完成隐式 join。
            # *_parallel_start 需要另找对应的 GOMP_parallel_end，暂不凭
            # callback 地址猜测它们的阶段边界。
            parallel_regions.append(
                ThreadParallelFact(
                    call_site=call.location,
                    parent_role=parent,
                    worker_role=role_id,
                    start_targets=targets,
                    complete=targets.complete and parent_complete,
                )
            )
        if not parent_complete:
            unknowns.append(
                _unknown(
                    UnknownKind.REACHING_DEFINITION_FAILURE,
                    "OpenMP parallel site is reachable from zero or multiple roles",
                    "the OpenMP worker parent role is unknown",
                    module=module.path,
                    pc=call.location.pc,
                    details={"api": call.target_symbol or "openmp"},
                    canonical_ledger=canonical_ledger,
                    canonical_scope=canonical_scope,
                )
            )
        # create_site 只用于把角色定位回第一个并行区入口；重复入口通过
        # role_id 合并，不改变每个 callback 的函数可达集合。
        if not any(role.id == role_id for role in roles):
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

    if openmp_roles:
        updated_roles: list[ThreadRole] = []
        for role in roles:
            entries = openmp_roles.get(role.id)
            if not entries:
                updated_roles.append(role)
                continue
            parents = {parent for parent, _ in entries}
            complete = role.complete and len(parents) == 1 and all(
                parent_complete for _, parent_complete in entries
            )
            parent = next(iter(parents)) if len(parents) == 1 else "unknown"
            updated_roles.append(
                role.model_copy(
                    update={"parent_role": parent, "complete": complete}
                )
            )
        roles = updated_roles

    # 只有 pthread 角色参与 pthread_join 的 handle 映射。
    child_roles = tuple(
        item.id
        for item in roles
        if item.id != "main" and item.id.startswith("pthread@")
    )
    joins: list[ThreadJoinFact] = []
    all_join_calls = [
        call
        for call in control_flow.call_sites
        if call.target_symbol == "pthread_join"
    ]
    join_calls = (
        [
            call
            for call in all_join_calls
            if call.containing_function_pc in main_reachable
        ]
        if main_call_graph_closed
        else all_join_calls
    )
    for call in join_calls:
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
                _unknown(
                    UnknownKind.UNKNOWN_JOIN_RELATION,
                    reason or "join relation is unknown",
                    "thread lifetime ordering cannot be closed",
                    module=module.path,
                    pc=call.location.pc,
                    details={"api": "pthread_join"},
                    canonical_ledger=canonical_ledger,
                    canonical_scope=canonical_scope,
                )
            )

    return ThreadDiscoveryReport(
        roles=tuple(roles),
        creates=tuple(creates),
        joins=tuple(joins),
        parallel_regions=tuple(parallel_regions),
        unknowns=tuple(unknowns),
        single_thread_proven=(
            main_call_graph_closed and not create_calls and not openmp_calls
        ),
        single_thread_evidence=(
            (
                f"closed direct-call graph from main covers {len(main_reachable)} functions",
                "no reachable pthread_create or OpenMP parallel entry was recovered",
            )
            if main_call_graph_closed and not create_calls and not openmp_calls
            else ()
        ),
    )
