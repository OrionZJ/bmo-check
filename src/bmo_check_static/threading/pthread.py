from __future__ import annotations

from pathlib import Path

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from bmo_check_core import EvidenceLedger, ProofFact, ProducerId, ThreadRoleId
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

from .callback import resolve_argument_locations, resolve_callback_targets


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


def _thread_proof(
    ledger: EvidenceLedger | None,
    module: ModuleFingerprint,
    scope: str,
    subject: str,
    rule: str,
) -> None:
    """把闭合的线程事实写入 canonical ledger，供证书回放追溯。"""

    if ledger is None:
        return
    ledger.add(
        ProofFact.create(
            schema_version="static-threading-1",
            producer=ProducerId("bmo_check_static.threading", "e3.1"),
            subject=ThreadRoleId.from_legacy(subject),
            rule=rule,
            scope=scope,
        )
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
    recovered_creates: list[
        tuple[object, str, IndirectTargetSet, str | None, tuple[str, ...]]
    ] = []
    # 每条 API 调用分别保存 callback/handle 的传参上下文；不能把同一个
    # wrapper 的多个 caller 压成一个 function 集合，否则父子角色会混淆。
    callback_contexts: dict[int, tuple[tuple[int, int, int | None], ...]] = {}
    handle_contexts: dict[int, tuple[tuple[str, int, int | None], ...]] = {}

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
        handle_resolution = resolve_argument_locations(
            context, module, control_flow, call, "rdi"
        )
        handle_contexts[call.location.pc] = handle_resolution.location_contexts
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
        callback_resolution = None
        if not callback_valid:
            # pthread_create 常被 launch 这类 wrapper 包住。先沿 wrapper
            # 的 SysV 形参回到每个本 ELF caller，再接受已闭合的 callback 集合；
            # 未闭合 caller 仍保留 Unknown，不能凭一次静态值猜目标。
            callback_resolution = resolve_callback_targets(
                context, module, control_flow, call, "rdx"
            )
            if callback_resolution.targets:
                callback_valid = callback_resolution.complete
        if callback_valid:
            resolved_pcs = (
                callback_resolution.targets
                if callback_resolution is not None
                else (callback_pc,)
            )
            target_locations = tuple(
                _location(module, pc, symbols.get(pc)) for pc in resolved_pcs
            )
            targets = IndirectTargetSet(
                known_targets=target_locations,
                complete=True,
                evidence=(
                    callback_resolution.origin
                    if callback_resolution is not None
                    and callback_resolution.origin is not None
                    else "SysV third argument has a block-local constant definition",
                ),
            )
            if callback_resolution is not None:
                callback_contexts[call.location.pc] = callback_resolution.call_contexts
                argument_origin = callback_resolution.origin
            elif callback_pc is not None:
                callback_contexts[call.location.pc] = (
                    (callback_pc, call.containing_function_pc, call.location.pc),
                )
        else:
            targets = IndirectTargetSet(
                known_targets=(
                    tuple(
                        _location(module, pc, symbols.get(pc))
                        for pc in callback_resolution.targets
                    )
                    if callback_resolution is not None
                    else ()
                ),
                complete=False,
                reason=(
                    callback_resolution.reason
                    if callback_resolution is not None
                    and callback_resolution.reason is not None
                    else "pthread_create start routine is not a proven executable constant"
                ),
            )
            if callback_resolution is not None:
                callback_contexts[call.location.pc] = callback_resolution.call_contexts
                argument_origin = callback_resolution.origin
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
        recovered_creates.append(
            (
                call,
                role_id,
                targets,
                argument_origin,
                tuple(
                    dict.fromkeys(
                        location
                        for location, _, _ in handle_contexts[call.location.pc]
                    )
                ),
            )
        )

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
        argument_origin = origin
        callback_valid = (
            constant
            and callback_pc is not None
            and _executable_pc(module, callback_pc)
        )
        callback_resolution = None
        if not callback_valid:
            callback_resolution = resolve_callback_targets(
                context, module, control_flow, call, "rdi"
            )
            if callback_resolution.targets:
                callback_valid = callback_resolution.complete
        if callback_valid:
            resolved_pcs = (
                callback_resolution.targets
                if callback_resolution is not None
                else (callback_pc,)
            )
            target_locations = tuple(
                _location(module, pc, symbols.get(pc)) for pc in resolved_pcs
            )
            targets = IndirectTargetSet(
                known_targets=target_locations,
                complete=True,
                evidence=(
                    callback_resolution.origin
                    if callback_resolution is not None
                    and callback_resolution.origin is not None
                    else "SysV first argument has a block-local constant OpenMP callback",
                ),
            )
            if callback_resolution is not None:
                argument_origin = callback_resolution.origin
            # 角色按并行区入口而不是 callback 地址命名；同一 callback
            # 在两个阶段复用时，两个阶段不能共享同一组事件边界。
            role_id = f"openmp@{call.location.pc:x}"
        else:
            targets = IndirectTargetSet(
                known_targets=(
                    tuple(
                        _location(module, pc, symbols.get(pc))
                        for pc in callback_resolution.targets
                    )
                    if callback_resolution is not None
                    else ()
                ),
                complete=False,
                reason=(callback_resolution.reason if callback_resolution is not None
                        and callback_resolution.reason is not None else
                        "OpenMP parallel callback is not a proven executable constant"),
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
        entry = (call, role_id, targets, argument_origin)
        openmp_entries.append(entry)

    # 一个 wrapper 可能在 main 和 worker 两条调用上下文中复用；把它的
    # 多个 callback 合并成一个 role 会让父线程永远变成 unknown，并把
    # 不同 worker 的事件混在一起。只有 callback 集合和 caller 上下文都
    # 闭合时才按目标拆 role；普通单目标 pthread_create 保持旧 ID。
    role_entries: list[
        tuple[object, str, IndirectTargetSet, str | None, int | None, tuple[str, ...]]
    ] = []
    for call, role_id, targets, argument_origin, all_handles in recovered_creates:
        contexts = callback_contexts.get(call.location.pc, ())
        if targets.complete and len(targets.known_targets) > 1 and contexts:
            for target in targets.known_targets:
                target_contexts = {
                    (caller, caller_call)
                    for callback, caller, caller_call in contexts
                    if callback == target.pc
                }
                target_handles = tuple(
                    dict.fromkeys(
                        location
                        for location, caller, caller_call in handle_contexts.get(
                            call.location.pc, ()
                        )
                        if (caller, caller_call) in target_contexts
                    )
                )
                single = IndirectTargetSet(
                    known_targets=(target,),
                    complete=True,
                    evidence=targets.evidence,
                )
                role_entries.append(
                    (
                        call,
                        f"{role_id}#{target.pc:x}",
                        single,
                        argument_origin,
                        target.pc,
                        target_handles,
                    )
                )
        else:
            role_entries.append(
                (call, role_id, targets, argument_origin, None, all_handles)
            )

    role_roots: dict[str, tuple[int, ...]] = {"main": (main_function.pc,)}
    for _, role_id, targets, _, _, _ in role_entries:
        role_roots[role_id] = tuple(item.pc for item in targets.known_targets)
    for _, role_id, targets, _ in openmp_entries:
        # role_id 按 call site 区分并行阶段；这里仍用 setdefault 保留该
        # 阶段 callback 的单一入口。
        role_roots.setdefault(
            role_id, tuple(item.pc for item in targets.known_targets)
        )
    reachability = _role_reachability(control_flow, role_roots)
    root_roles: dict[int, tuple[str, ...]] = {}
    for role_id, roots in role_roots.items():
        for root in roots:
            root_roles[root] = (*root_roles.get(root, ()), role_id)

    def parent_from_callback_context(function_pc: int) -> tuple[str, bool]:
        # callback 的直接 caller 如果正好是另一个线程角色的入口，
        # 这个事实比全函数调用图更精确；同一个函数被 main 和 worker
        # 复用时，单靠可达性会产生两个候选而丢掉真实父子关系。
        candidates = tuple(sorted(set(root_roles.get(function_pc, ()))))
        if len(candidates) == 1:
            return candidates[0], True
        return _containing_role(reachability, function_pc)

    role_handle_locations: dict[str, tuple[str, ...]] = {}
    for call, role_id, targets, argument_origin, target_pc, handle_locations in role_entries:
        contexts = callback_contexts.get(call.location.pc, ())
        parent_candidates: set[str] = set()
        parent_complete = True
        if target_pc is not None:
            caller_functions = {
                caller
                for callback, caller, _ in contexts
                if callback == target_pc
            }
            if not caller_functions:
                parent_complete = False
            for caller_function in caller_functions:
                candidate, complete = parent_from_callback_context(caller_function)
                if complete:
                    parent_candidates.add(candidate)
                else:
                    parent_complete = False
        else:
            candidate, complete = _containing_role(
                reachability, call.containing_function_pc
            )
            if complete:
                parent_candidates.add(candidate)
            else:
                parent_complete = False
        parent = next(iter(parent_candidates)) if len(parent_candidates) == 1 else "unknown"
        parent_complete = parent_complete and len(parent_candidates) == 1
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
                handle_locations=handle_locations,
                complete=targets.complete and parent_complete,
            )
        )
        if targets.complete and parent_complete:
            _thread_proof(
                canonical_ledger,
                module,
                canonical_scope,
                role_id,
                "pthread create callback and parent are closed",
            )
        role_handle_locations[role_id] = handle_locations
        creates.append(
            ThreadCreateFact(
                call_site=call.location,
                parent_role=parent,
                child_role=role_id,
                start_targets=targets,
                argument_origin=argument_origin,
                handle_locations=handle_locations,
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
    handles_to_roles: dict[str, set[str]] = {}
    for role_id, locations in role_handle_locations.items():
        for location in locations:
            handles_to_roles.setdefault(location, set()).add(role_id)
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
        handle_resolution = resolve_argument_locations(
            context, module, control_flow, call, "rdi"
        )
        contexts = tuple(dict.fromkeys(handle_resolution.location_contexts))
        if contexts:
            # 一个 join wrapper 可能被 main 和 worker 多次调用。每个已闭合
            # 的 caller/call-site 单独形成事实，避免把不同栈槽合成一个假句柄。
            for location, caller_function, caller_call in contexts:
                parent, parent_complete = parent_from_callback_context(caller_function)
                candidates = tuple(
                    sorted(handles_to_roles.get(location, ()))
                )
                complete = parent_complete and len(candidates) == 1
                reason = None
                if not parent_complete:
                    reason = "join caller is reachable from zero or multiple thread roles"
                elif not candidates:
                    reason = "join handle does not match a recovered pthread_create slot"
                elif len(candidates) > 1:
                    reason = "join handle may refer to multiple recovered thread roles"
                context_id = (
                    f"{module.sha256}:join:{call.location.pc:x}:"
                    f"caller:{caller_function:x}:call:{caller_call if caller_call is not None else 'none'}:"
                    f"slot:{location}"
                )
                joins.append(
                    ThreadJoinFact(
                        call_site=call.location,
                        parent_role=parent,
                        candidate_child_roles=(candidates if candidates else child_roles),
                        handle_locations=(location,),
                        context_id=context_id,
                        complete=complete,
                        reason=reason,
                    )
                )
                if complete:
                    _thread_proof(
                        canonical_ledger,
                        module,
                        canonical_scope,
                        context_id,
                        "pthread join handle and caller are closed",
                    )
                if not complete:
                    unknowns.append(
                        _unknown(
                            UnknownKind.UNKNOWN_JOIN_RELATION,
                            reason or "join relation is unknown",
                            "thread lifetime ordering cannot be closed",
                            module=module.path,
                            pc=call.location.pc,
                            details={
                                "api": "pthread_join",
                                "handle_location": location,
                                "caller_function_pc": caller_function,
                                "caller_call_pc": caller_call,
                            },
                            canonical_ledger=canonical_ledger,
                            canonical_scope=canonical_scope,
                        )
                    )
            if not handle_resolution.complete:
                # 已知 caller 的事实可以独立使用；另一些 caller 仍未闭合
                # 时追加 Unknown，不能因为部分成功就丢掉未证明路径。
                unknowns.append(
                    _unknown(
                        UnknownKind.UNKNOWN_JOIN_RELATION,
                        handle_resolution.reason
                        or "one or more join caller paths are incomplete",
                        "thread lifetime ordering cannot be closed for every caller",
                        module=module.path,
                        pc=call.location.pc,
                        details={"api": "pthread_join", "partial_contexts": len(contexts)},
                        canonical_ledger=canonical_ledger,
                        canonical_scope=canonical_scope,
                    )
                )
            continue

        parent, parent_complete = _containing_role(
            reachability, call.containing_function_pc
        )
        reason = (
            handle_resolution.reason
            or "join caller or handle cannot be mapped to one recovered thread role"
        )
        joins.append(
            ThreadJoinFact(
                call_site=call.location,
                parent_role=parent,
                candidate_child_roles=child_roles,
                handle_locations=handle_resolution.locations,
                context_id=(
                    f"{module.sha256}:join:{call.location.pc:x}:"
                    f"caller:{call.containing_function_pc:x}"
                ),
                complete=False,
                reason=reason,
            )
        )
        unknowns.append(
            _unknown(
                UnknownKind.UNKNOWN_JOIN_RELATION,
                reason,
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
