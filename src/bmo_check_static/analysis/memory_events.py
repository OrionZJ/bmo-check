from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path

from bmo_check_core import EvidenceLedger
from bmo_check_static.binary.evidence import emit_static_unknown
from bmo_check_static.binary.capstone_backend import collect_instruction_facts
from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    CallKind,
    CallSite,
    ControlFlowReport,
    EventKind,
    FenceKind,
    InstructionFact,
    MemoryAccessKind,
    MemoryEvent,
    MemoryEventReport,
    MemoryOperandFact,
    ModuleFingerprint,
    Ordering,
    ProgramOrderEdge,
    SynchronizationReport,
    ThreadDiscoveryReport,
    UnknownFact,
    UnknownKind,
)

from .address_provenance import recover_address_provenance


_ACQUIRE_APIS = {"pthread_mutex_lock", "pthread_spin_lock"}
_RELEASE_APIS = {
    "pthread_mutex_unlock",
    "pthread_spin_unlock",
    "pthread_cond_signal",
    "pthread_cond_broadcast",
}
_BARRIER_APIS = {"pthread_barrier_wait", "pthread_cond_wait"}
_OPENMP_BARRIER_APIS = {
    "GOMP_parallel",
    "GOMP_parallel_end",
    "GOMP_barrier",
}
_OPENMP_ACQUIRE_APIS = {"GOMP_critical_start"}
_OPENMP_RELEASE_APIS = {"GOMP_critical_end"}
_INTEGER_ARGUMENTS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


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
    canonical_scope: str = "static.memory",
) -> UnknownFact:
    """旧 MemoryEventReport 与 canonical ledger 共享同一个 Unknown 来源。"""

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


def _mirror_unknowns(
    unknowns: tuple[UnknownFact, ...],
    ledger: EvidenceLedger | None,
    scope: str,
) -> None:
    """访存 producer 复用指令事实时，保留其可达 Unknown 的来源。"""

    if ledger is None:
        return
    for unknown in unknowns:
        _unknown(
            unknown.kind,
            unknown.reason,
            unknown.impact,
            module=unknown.module,
            pc=unknown.pc,
            function=unknown.function,
            details=unknown.details,
            canonical_ledger=ledger,
            canonical_scope=scope,
        )


def _merge_heap_argument_values(
    values: list[AbstractAddress | None], target_pc: int, register: str
) -> AbstractAddress | None:
    """保留多处调用传入的已知对象，不把分歧直接抹成 Unknown。"""

    if not values or any(value is None for value in values):
        return None
    concrete = [value for value in values if value is not None]
    # worker 把自己的栈上的随机种子交给多层 helper 时，各 call site
    # 仍应指向同一个 frame。先保留这个精确 stack 身份；若把它强行
    # 改成 heap-union，后续栈逃逸分析会失去“同一 worker 栈槽”的证据。
    if all(
        value.kind == AddressKind.STACK
        and value.base is not None
        and value.provenance.get("base_indirect") is False
        for value in concrete
    ) and len({value.base for value in concrete}) == 1:
        return concrete[0]
    if any(
        value.kind not in {AddressKind.HEAP, AddressKind.AFFINE}
        or value.base is None
        or value.provenance.get("base_indirect") is True
        for value in concrete
    ):
        return None
    candidate_bases: set[str] = set()
    for value in concrete:
        candidates = value.provenance.get("candidate_bases", ())
        if isinstance(candidates, (list, tuple, set)) and candidates:
            candidate_bases.update(
                item for item in candidates if isinstance(item, str)
            )
        elif value.base.startswith("heap:"):
            candidate_bases.add(value.base)
        else:
            return None
    if not candidate_bases:
        return None
    common_shape = (
        len(
            {
                (
                    value.offset,
                    value.provenance.get("index_term"),
                    value.index_coefficient,
                    value.index_lower,
                    value.index_upper,
                )
                for value in concrete
            }
        )
        == 1
    )
    offset = concrete[0].offset if common_shape else 0
    index_term = concrete[0].provenance.get("index_term") if common_shape else None
    index_coefficient = concrete[0].index_coefficient if common_shape else None
    index_lower = concrete[0].index_lower if common_shape else None
    index_upper = concrete[0].index_upper if common_shape else None
    base = f"heap-union:argument@0x{target_pc:x}:{register}"
    expression = base
    if index_term is not None and index_coefficient is not None:
        expression += f"+({index_term})*{index_coefficient}"
    if offset:
        expression += f"{offset:+d}"
    # 不同调用点传入不同对象时，union 只列出真实 allocation site。
    # 后续别名层可以排除其它 allocation，但不会把 union 当成一个确定对象。
    return AbstractAddress(
        kind=AddressKind.AFFINE if index_term is not None else AddressKind.HEAP,
        base=base,
        offset=offset,
        expression=expression,
        index_coefficient=index_coefficient,
        index_lower=index_lower,
        index_upper=index_upper,
        provenance={
            "base_indirect": False,
            "index_term": index_term,
            "candidate_bases": sorted(candidate_bases),
            "scope": "role-call-union",
        },
    )


def _ordering_covers(actual: Ordering, required: Ordering) -> bool:
    directions = {
        Ordering.RELAXED: frozenset(),
        Ordering.ACQUIRE: frozenset({"acquire"}),
        Ordering.RELEASE: frozenset({"release"}),
        Ordering.ACQ_REL: frozenset({"acquire", "release"}),
        Ordering.FULL: frozenset({"acquire", "release"}),
    }
    return required in directions and directions[required] <= directions.get(
        actual, frozenset()
    )


def _function_graph(report: ControlFlowReport) -> dict[int, set[int]]:
    function_pcs = {item.location.pc for item in report.functions}
    graph: dict[int, set[int]] = {}
    for call in report.call_sites:
        for target in call.targets.known_targets:
            if target.module_sha256 == report.module_sha256 and target.pc in function_pcs:
                graph.setdefault(call.containing_function_pc, set()).add(target.pc)
    return graph


def _role_functions(
    report: ControlFlowReport, threads: ThreadDiscoveryReport
) -> dict[str, set[int]]:
    graph = _function_graph(report)
    result: dict[str, set[int]] = {}
    for role in threads.roles:
        roots = [
            target.pc
            for target in role.start_targets.known_targets
            if target.module_sha256 == report.module_sha256
        ]
        pending = list(roots)
        seen: set[int] = set()
        while pending:
            function_pc = pending.pop()
            if function_pc in seen:
                continue
            seen.add(function_pc)
            pending.extend(graph.get(function_pc, ()))
        result[role.id] = seen
    return result


def _stable_published_heap_fields(
    published_fields: dict[str, AbstractAddress],
    report,
    facts: tuple[InstructionFact, ...],
    worker_pc: int,
) -> frozenset[str]:
    """找出 worker 不会直接写回的已发布结构体字段摘要。"""

    summary_keys = {
        key for key in published_fields if key.startswith("heap-field-summary@")
    }
    if not summary_keys:
        return frozenset()
    written: set[str] = set()
    for fact in facts:
        for operand in fact.memory_operands:
            if operand.access not in {
                MemoryAccessKind.WRITE,
                MemoryAccessKind.READ_WRITE,
            }:
                continue
            address = report.addresses.get((fact.pc, operand.operand_index))
            if address is None:
                continue
            key = f"heap-field-summary@{address.base}{address.offset:+d}"
            if key in summary_keys:
                written.add(key)
    # 只把 worker 入口直接读到、且没有在该入口写回的字段标成 stable。
    # helper 的未知写入不会被这条规则忽略；它们没有同一 outer-object
    # provenance 时，摘要仍会在调用边界被清掉。
    return frozenset(summary_keys - written)


def _block_maps(
    report: ControlFlowReport,
) -> tuple[dict[int, int], dict[int, int], dict[int, str | None]]:
    instruction_to_block: dict[int, int] = {}
    block_to_function: dict[int, int] = {}
    function_names: dict[int, str | None] = {}
    for function in report.functions:
        function_names[function.location.pc] = function.location.symbol
        for block_pc in function.block_pcs:
            block_to_function[block_pc] = function.location.pc
    for block in report.basic_blocks:
        for pc in block.instruction_pcs:
            instruction_to_block[pc] = block.location.pc
    return instruction_to_block, block_to_function, function_names


def _blocks_reaching_return(
    report: ControlFlowReport,
    facts: tuple[InstructionFact, ...],
) -> set[int]:
    """反向标记能到达 ret 的块；没有恢复完整返回路径时不作乐观判断。"""

    return_pcs = {
        fact.pc
        for fact in facts
        if fact.control_flow is not None and fact.control_flow.value == "return"
    }
    result: set[int] = set()
    blocks = {item.location.pc: item for item in report.basic_blocks}
    for function in report.functions:
        function_blocks = set(function.block_pcs)
        exits = {
            block_pc
            for block_pc in function_blocks
            if block_pc in blocks
            and any(pc in return_pcs for pc in blocks[block_pc].instruction_pcs)
        }
        # 没有 ret 也可能是 tail call 或 CFG 缺口；这种情况不删任何事件。
        if not exits:
            continue
        predecessors: dict[int, set[int]] = {}
        for block_pc in function_blocks:
            if block_pc not in blocks:
                continue
            for successor in blocks[block_pc].successor_pcs:
                if successor in function_blocks:
                    predecessors.setdefault(successor, set()).add(block_pc)
        pending = list(exits)
        while pending:
            block_pc = pending.pop()
            if block_pc in result:
                continue
            result.add(block_pc)
            pending.extend(predecessors.get(block_pc, ()))
    return result


def _functions_only_called_from_nonreturning_paths(
    report: ControlFlowReport,
    return_reachable_blocks: set[int],
    role_roots: set[int],
    role_reachable_functions: set[int],
) -> set[int]:
    """只有所有调用点都无法返回时，才把这个 callee 纳入失败路径。"""

    functions = {item.location.pc: item for item in report.functions}
    # 未闭合的应用间接调用可能绕过已知 call site 进入 callee。
    # PLT 桁只跳到依赖库 relocation，不会反向调用主 ELF 的本地函数。
    if any(
        not site.targets.complete
        and site.containing_function_pc in functions
        and site.containing_function_pc in role_reachable_functions
        and not functions[site.containing_function_pc].is_plt
        for site in report.indirect_sites
    ):
        return set()

    incoming: dict[int, list[CallSite]] = defaultdict(list)
    for call in report.call_sites:
        if len(call.targets.known_targets) != 1:
            continue
        target = call.targets.known_targets[0]
        if target.module_sha256 == report.module_sha256 and target.pc in functions:
            incoming[target.pc].append(call)

    result: set[int] = set()
    changed = True
    while changed:
        changed = False
        for function_pc, calls in incoming.items():
            if function_pc in result or function_pc in role_roots or not calls:
                continue
            if all(
                call.containing_function_pc in result
                or (
                    call.block_pc not in return_reachable_blocks
                    and call.containing_function_pc in functions
                    and functions[call.containing_function_pc].returning is not None
                )
                for call in calls
            ):
                result.add(function_pc)
                changed = True
    return result


def _address(
    module: ModuleFingerprint,
    fact: InstructionFact,
    operand: MemoryOperandFact,
    function_pc: int,
) -> AbstractAddress:
    base = (operand.base or "").lower()
    segment = (operand.segment or "").lower()
    provenance = {
        "base_register": operand.base,
        "index_register": operand.index,
        "scale": operand.scale,
        "displacement": operand.displacement,
        "segment": operand.segment,
        "implicit": operand.implicit,
    }
    if segment in {"fs", "gs"}:
        return AbstractAddress(
            kind=AddressKind.TLS,
            base=segment,
            offset=operand.displacement,
            provenance=provenance,
        )
    if base == "rip":
        instruction_size = len(fact.raw_bytes) // 2
        target = fact.pc + instruction_size + operand.displacement
        return AbstractAddress(
            kind=AddressKind.GLOBAL,
            base=f"{Path(module.path).name}@0x{target:x}",
            offset=0,
            provenance={**provenance, "absolute_pc": target},
        )
    if not operand.base and not operand.index and operand.displacement:
        return AbstractAddress(
            kind=AddressKind.GLOBAL,
            base=f"{Path(module.path).name}@0x{operand.displacement:x}",
            offset=0,
            provenance={**provenance, "absolute_pc": operand.displacement},
        )
    if base in {"rsp", "rbp"} and not operand.index:
        return AbstractAddress(
            kind=AddressKind.STACK,
            base=f"frame@0x{function_pc:x}",
            offset=operand.displacement,
            provenance=provenance,
        )
    if operand.base or operand.index:
        terms = [item for item in (operand.base, operand.index) if item]
        expression = "+".join(terms)
        if operand.index and operand.scale != 1:
            expression = f"{operand.base or '0'}+{operand.index}*{operand.scale}"
        if operand.displacement:
            expression += f"{operand.displacement:+d}"
        return AbstractAddress(
            kind=AddressKind.AFFINE,
            expression=expression,
            offset=operand.displacement,
            provenance=provenance,
        )
    return AbstractAddress(
        kind=AddressKind.UNKNOWN,
        expression=fact.op_str or None,
        provenance=provenance,
    )


def _canonical_stack_address(address: AbstractAddress) -> AbstractAddress:
    """把 LEA 产生的 stack object 还原为共享状态使用的 frame+offset。"""

    if address.kind != AddressKind.STACK or not address.base:
        return address
    match = re.fullmatch(
        r"stack:frame-value@0x([0-9a-fA-F]+)([+-][0-9]+)?", address.base
    )
    if match is None:
        return address
    offset = address.offset + int(match.group(2) or 0)
    base = f"frame@0x{int(match.group(1), 16):x}"
    return address.model_copy(
        update={
            "base": base,
            "offset": offset,
            "expression": f"{base}{offset:+d}" if offset else base,
            "provenance": {
                **address.provenance,
                "canonical_stack_base": base,
                "canonical_stack_offset": offset,
            },
        }
    )


def _event_ordering(fact: InstructionFact) -> tuple[Ordering, Ordering]:
    if fact.has_lock_prefix or fact.is_memory_xchg:
        return Ordering.FULL, Ordering.ACQ_REL
    if fact.fence == FenceKind.LFENCE:
        return Ordering.FENCE_RR, Ordering.FENCE_RR
    if fact.fence == FenceKind.SFENCE:
        return Ordering.FENCE_WW, Ordering.FENCE_WW
    if fact.fence == FenceKind.MFENCE:
        return Ordering.FULL, Ordering.FULL
    return Ordering.TSO, Ordering.RELAXED


def _memory_kinds(
    fact: InstructionFact, operand: MemoryOperandFact
) -> tuple[EventKind, ...]:
    if fact.has_lock_prefix or fact.is_memory_xchg:
        return (EventKind.ATOMIC_RMW,)
    if operand.access == MemoryAccessKind.READ:
        return (EventKind.LOAD,)
    if operand.access == MemoryAccessKind.WRITE:
        return (EventKind.STORE,)
    if operand.access == MemoryAccessKind.READ_WRITE:
        return (EventKind.LOAD, EventKind.STORE)
    return (EventKind.UNKNOWN_MEMORY_EFFECT,)


def _summary_ordering(
    symbol: str, reports: tuple[SynchronizationReport, ...]
) -> tuple[Ordering | None, str | None]:
    # GOMP_parallel 返回前包含隐式 worker 汇合；它不是 pthread 库摘要，
    # 但并行区的 barrier 边界仍必须进入应用切片，不能当作普通 opaque call。
    if symbol in _OPENMP_BARRIER_APIS:
        return Ordering.ACQ_REL, None
    if symbol in _OPENMP_ACQUIRE_APIS:
        return Ordering.ACQUIRE, None
    if symbol in _OPENMP_RELEASE_APIS:
        return Ordering.RELEASE, None
    summaries = [
        summary
        for report in reports
        for summary in report.summaries
        if summary.api == symbol
    ]
    if not summaries:
        return None, "no concrete library summary was found"
    incomplete = [summary for summary in summaries if not summary.complete]
    if incomplete:
        reasons = sorted(
            {summary.reason or "return paths are incomplete" for summary in incomplete}
        )
        return None, "; ".join(reasons)
    weak = [
        summary
        for summary in summaries
        if not _ordering_covers(
            summary.target_ordering, summary.required_ordering
        )
    ]
    if weak:
        # API 名称只说明 source 需要什么。实际库路径达不到该强度时，
        # 后续层必须看到 Unknown，不能把“分析完整但过弱”当成同步边界。
        return None, "; ".join(
            sorted(
                {
                    f"target {summary.target_ordering.value} does not cover required "
                    f"{summary.required_ordering.value}"
                    for summary in weak
                }
            )
        )
    orderings = {summary.target_ordering for summary in summaries}
    if len(orderings) != 1:
        return None, "versioned implementations have different target orderings"
    return next(iter(orderings)), None


def _summary_provenance(
    symbol: str, reports: tuple[SynchronizationReport, ...]
) -> dict[str, object]:
    summaries = [
        summary
        for report in reports
        for summary in report.summaries
        if summary.api == symbol
    ]
    if not summaries:
        return {}
    return {
        "summary_required_orderings": sorted(
            {summary.required_ordering.value for summary in summaries}
        ),
        "summary_target_orderings": sorted(
            {summary.target_ordering.value for summary in summaries}
        ),
        "summary_complete": all(summary.complete for summary in summaries),
        "summary_evidence_pcs": sorted(
            {item.pc for summary in summaries for item in summary.evidence}
        ),
        "summary_issue_pcs": sorted(
            {
                int(match, 16)
                for summary in summaries
                for match in re.findall(r"0x[0-9a-fA-F]+", summary.reason or "")
            }
        ),
    }


def _call_event_kind(symbol: str, ordering: Ordering | None) -> EventKind:
    if symbol == "pthread_create":
        return EventKind.THREAD_CREATE
    if symbol == "pthread_join":
        return EventKind.THREAD_JOIN
    if symbol in _OPENMP_BARRIER_APIS:
        return EventKind.BARRIER
    if symbol in _OPENMP_ACQUIRE_APIS:
        return EventKind.ACQUIRE
    if symbol in _OPENMP_RELEASE_APIS:
        return EventKind.RELEASE
    if ordering is None:
        return EventKind.OPAQUE_CALL
    if symbol in _ACQUIRE_APIS:
        return EventKind.ACQUIRE
    if symbol in _RELEASE_APIS:
        return EventKind.RELEASE
    if symbol in _BARRIER_APIS:
        return EventKind.BARRIER
    return EventKind.OPAQUE_CALL


def extract_memory_events(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    threads: ThreadDiscoveryReport,
    synchronization: tuple[SynchronizationReport, ...] = (),
    *,
    function_effects: dict[str, str] | None = None,
    function_integer_arguments: dict[str, tuple[int, ...]] | None = None,
    function_memory_arguments: dict[str, tuple[tuple[int, str], ...]] | None = None,
    function_internal_objects: dict[str, str] | None = None,
    worker_argument_base: str | None = None,
    worker_argument_alias_base: str | None = None,
    provenance_instruction_limit: int | None = None,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.memory",
) -> MemoryEventReport:
    try:
        if not control_flow.functions or not control_flow.basic_blocks:
            raise RuntimeError("CFG contains no recoverable functions or basic blocks")
        effect_contract = function_effects or {}
        integer_argument_contract = function_integer_arguments or {}
        memory_argument_contract = function_memory_arguments or {}
        internal_object_contract = function_internal_objects or {}
        instruction_report = collect_instruction_facts(module)
        return_reachable_blocks = _blocks_reaching_return(
            control_flow, instruction_report.facts
        )
        functions_with_return = {
            function.location.pc
            for function in control_flow.functions
            if any(block_pc in return_reachable_blocks for block_pc in function.block_pcs)
        }
        known_nonreturn_functions = {
            function.location.pc
            for function in control_flow.functions
            if function.returning is False
        }
        function_symbols_by_pc = {
            function.location.pc: function.location.symbol
            for function in control_flow.functions
            if function.location.symbol
        }

        def resolved_effect_symbol(call: CallSite) -> str | None:
            """把同一 ELF 内部 direct call 绑定到函数事实的符号。"""

            if call.target_symbol is not None:
                return call.target_symbol
            if len(call.targets.known_targets) != 1:
                return None
            target = call.targets.known_targets[0]
            if target.module_sha256 != module.sha256:
                return None
            return function_symbols_by_pc.get(target.pc)

        allocation_calls = {
            call.location.pc: resolved_effect_symbol(call)
            for call in control_flow.call_sites
            if resolved_effect_symbol(call) is not None
            and effect_contract.get(resolved_effect_symbol(call))
            == "fresh_allocation"
        }
        # allocator、线程局部 helper、运行库私有状态以及经过机器码审计的
        # field_preserving helper 不会替换应用对象的指针字段。只有契约
        # 明确给出这条边界时才能保留字段事实；未知 helper、argument_access、
        # memcpy/memset 和 free 仍会清掉字段。
        preserve_heap_field_call_pcs = {
            call.location.pc
            for call in control_flow.call_sites
            if resolved_effect_symbol(call) is not None
            and effect_contract.get(resolved_effect_symbol(call))
            in {
                "fresh_allocation",
                "thread_local",
                "runtime_internal",
                "field_preserving",
            }
        }
        # 已闭合的同步 API 只访问自己的 mutex/cond/barrier 状态，不会改写
        # caller 保存的对象指针字段。若在这里把字段摘要清掉，worker 经过
        # 一次锁或 barrier 后就会重新变成 loaded-pointer，丢掉 fresh 对象
        # 的 ownership 事实；同步边界本身仍由 synchronization report 单独
        # 校验，未知或不完整的同步调用不会进入这个集合。
        complete_sync_symbols = {
            summary.api
            for report in synchronization
            for summary in report.summaries
            if summary.complete
        }
        preserve_heap_field_call_pcs.update(
            call.location.pc
            for call in control_flow.call_sites
            if resolved_effect_symbol(call) in complete_sync_symbols
            and resolved_effect_symbol(call)
            not in {"pthread_create", "pthread_join"}
        )
        # PARSEC 的 barrier 实现在主 ELF 内，不能套用 pthread 动态库摘要；
        # 但它仍是已知的全线程阶段边界。地址传播只把 pending global
        # 提升到普通槽，不把这个名字当成任意函数的通用“安全”标记。
        publication_barrier_call_pcs = {
            call.location.pc
            for call in control_flow.call_sites
            if (
                (symbol := resolved_effect_symbol(call))
                in {"pthread_barrier_wait", "GOMP_barrier"}
                or (symbol is not None and "parsec_barrier_wait" in symbol)
            )
        }
        preserve_global_call_pcs = {
            call.location.pc
            for call in control_flow.call_sites
            if effect_contract.get(resolved_effect_symbol(call))
            in {
                "fresh_allocation",
                "thread_local",
                "runtime_internal",
                "argument_access",
            }
        }
        # 只有已经绑定到某个线程角色的函数才可能贡献本次 shared slice。
        # 以前让基础传播遍历 ELF 中全部函数；生成的 litmus harness 会把
        # libc 适配和统计代码也带进来，传播成本随无关函数数量平方增长。
        # 未绑定函数仍由 CFG/indirect Unknown 单独记录，不会因为这里裁剪
        # 而被当成没有副作用。
        role_functions = _role_functions(control_flow, threads)
        role_reachable_functions = set().union(*role_functions.values())
        provenance_include_functions = {
            function.location.pc
            for function in control_flow.functions
            if function.location.symbol == "main"
        }
        provenance_include_functions.update(
            call.containing_function_pc
            for call in control_flow.call_sites
            if call.target_symbol in {
                "pthread_create",
                "pthread_join",
                *_OPENMP_BARRIER_APIS,
            }
        )
        # 参数可能经过一层以上普通 wrapper 才到达 create。反向沿已闭合
        # 的本 ELF call graph 纳入这些 caller，保留对象来源；其余大型
        # 清理/统计函数仍受 instruction limit 约束，不会拖慢固定点。
        reverse_calls: dict[int, set[int]] = defaultdict(set)
        for call in control_flow.call_sites:
            if len(call.targets.known_targets) != 1:
                continue
            target = call.targets.known_targets[0]
            if target.module_sha256 == module.sha256:
                reverse_calls[target.pc].add(call.containing_function_pc)
        pending_include = list(provenance_include_functions)
        while pending_include:
            target = pending_include.pop()
            for caller in reverse_calls.get(target, ()):
                if caller not in provenance_include_functions:
                    provenance_include_functions.add(caller)
                    pending_include.append(caller)
        base_address_provenance = recover_address_provenance(
            module,
            control_flow,
            instruction_report.facts,
            allocation_calls,
            reachable_function_pcs=role_reachable_functions,
            provenance_instruction_limit=provenance_instruction_limit,
            provenance_include_function_pcs=provenance_include_functions,
            preserve_heap_field_call_pcs=preserve_heap_field_call_pcs,
            publication_barrier_call_pcs=publication_barrier_call_pcs,
            preserve_global_call_pcs=preserve_global_call_pcs,
        )
        # argument_access helper 可能只会修改一个已知栈对象。若它的
        # 所有声明实参都恢复为 Stack，就只保留 heap 字段摘要；stack
        # 字段仍会被清掉，避免把 helper 的写入漏进后续路径。
        preserve_heap_only_call_pcs = {
            call.location.pc
            for call in control_flow.call_sites
            if resolved_effect_symbol(call) is not None
            and effect_contract.get(resolved_effect_symbol(call))
            == "argument_access"
            and all(
                call.location.pc in base_address_provenance.call_arguments
                and index < len(base_address_provenance.call_arguments[call.location.pc])
                and (
                argument := base_address_provenance.call_arguments[
                        call.location.pc
                    ][index]
                )
                is not None
                and argument.kind == AddressKind.STACK
                for index, _ in memory_argument_contract.get(
                    resolved_effect_symbol(call), ()
                )
            )
        }
        role_address_provenance = {}
        for role in threads.roles:
            function_entry_arguments: dict[int, dict[str, AbstractAddress]] = {}
            seeded_function_pcs: set[int] = set()
            role_reachable_functions = _role_functions(control_flow, threads).get(
                role.id, set()
            )
            if role.create_site is not None and len(role.start_targets.known_targets) == 1:
                worker_pc = role.start_targets.known_targets[0].pc
                seeded_function_pcs.add(worker_pc)
                call_arguments = base_address_provenance.call_arguments.get(
                    role.create_site.pc, ()
                )
                if worker_argument_base is not None:
                    # lifecycle 已逐个记录 create 的第四实参并证明它们互异。
                    # 用同一个逻辑对象名贯穿 worker 调用树，避免把不同
                    # create site 的精确栈表达式错误地合并成 Unknown。
                    function_entry_arguments[worker_pc] = {
                        "rdi": AbstractAddress(
                            # lifecycle proof 已经证明每个 create 的第四实参
                            # 来自互异对象；把它标成 HEAP，才能在 worker
                            # helper 的参数合流时继续保留这条 ownership 事实。
                            kind=AddressKind.HEAP,
                            base=worker_argument_base,
                            provenance={
                                "base_indirect": False,
                                "scope": "symbolic-lifecycle",
                            },
                        )
                    }
                elif worker_argument_alias_base is not None:
                    # 共享参数只用于恢复 worker 的 this/字段来源。
                    # 这里不能复用 worker_argument_base，否则 shared_state
                    # 会把同一个对象误当成每个线程独有的分片。
                    function_entry_arguments[worker_pc] = {
                        "rdi": AbstractAddress(
                            kind=(
                                AddressKind.STACK
                                if worker_argument_alias_base.startswith("stack:")
                                else AddressKind.HEAP
                            ),
                            base=worker_argument_alias_base,
                            provenance={
                                "base_indirect": False,
                                "scope": "symbolic-lifecycle-shared",
                            },
                        )
                    }
                elif len(call_arguments) > 3 and call_arguments[3] is not None:
                    function_entry_arguments[worker_pc] = {
                        "rdi": call_arguments[3]
                    }
            # recover_address_provenance 内部按一次函数图传播参数。大型 C++
            # worker 往往还会经过多层 helper；每一轮先恢复已知调用实参，
            # 再把“所有同目标 call site 都传入同一对象”的事实带入下一轮。
            # 只有全体调用点的值相同才扩展入口，分歧或缺失仍保持 Unknown。
            reachable = role_reachable_functions
            immutable_heap_field_keys: frozenset[str] = frozenset()
            for _ in range(max(1, len(reachable) + 1)):
                report = recover_address_provenance(
                    module,
                    control_flow,
                    instruction_report.facts,
                    allocation_calls,
                    function_entry_arguments,
                    seeded_function_pcs,
                    reachable,
                    provenance_instruction_limit=provenance_instruction_limit,
                    provenance_include_function_pcs=provenance_include_functions,
                    seeded_heap_fields=base_address_provenance.published_heap_fields,
                    seeded_globals=base_address_provenance.published_globals,
                    preserve_heap_field_call_pcs=preserve_heap_field_call_pcs,
                    immutable_heap_field_keys=immutable_heap_field_keys,
                    preserve_heap_only_call_pcs=preserve_heap_only_call_pcs,
                    publication_barrier_call_pcs=publication_barrier_call_pcs,
                    preserve_global_call_pcs=preserve_global_call_pcs,
                )
                if role.create_site is not None and len(role.start_targets.known_targets) == 1:
                    immutable_heap_field_keys = _stable_published_heap_fields(
                        base_address_provenance.published_heap_fields,
                        report,
                        instruction_report.facts,
                        role.start_targets.known_targets[0].pc,
                    )
                candidate_calls: dict[int, list[tuple[str, AbstractAddress | None]]] = defaultdict(list)
                for call in control_flow.call_sites:
                    if (
                        call.containing_function_pc not in reachable
                        or len(call.targets.known_targets) != 1
                    ):
                        continue
                    target = call.targets.known_targets[0]
                    if (
                        target.module_sha256 != module.sha256
                        or target.pc not in reachable
                    ):
                        continue
                    arguments = report.call_arguments.get(call.location.pc)
                    if arguments is None:
                        continue
                    for register, value in zip(_INTEGER_ARGUMENTS, arguments):
                        candidate_calls[target.pc].append((register, value))
                expanded = {
                    function_pc: dict(registers)
                    for function_pc, registers in function_entry_arguments.items()
                }
                for target_pc, candidates in candidate_calls.items():
                    by_register: dict[str, list[AbstractAddress | None]] = defaultdict(list)
                    for register, value in candidates:
                        by_register[register].append(value)
                    for register, values in by_register.items():
                        if (
                            values
                            and all(value is not None for value in values)
                            and all(value == values[0] for value in values[1:])
                        ):
                            expanded.setdefault(target_pc, {})[register] = values[0]
                        elif (merged := _merge_heap_argument_values(
                            values, target_pc, register
                        )) is not None:
                            # helper 可能被同一个 worker 以不同的临时矩阵
                            # 多次调用。保留这些 allocation site，才能在
                            # callee 内排除与应用共享对象的错误别名；不相同
                            # 的标量、global 或未知指针仍不进入入口摘要。
                            expanded.setdefault(target_pc, {})[register] = merged
                if expanded == function_entry_arguments:
                    role_address_provenance[role.id] = report
                    break
                function_entry_arguments = expanded
            else:
                role_address_provenance[role.id] = report
        instruction_to_block, block_to_function, function_names = _block_maps(
            control_flow
        )
        role_roots = {
            target.pc
            for role in threads.roles
            for target in role.start_targets.known_targets
            if target.module_sha256 == module.sha256
        }
        nonreturning_context_functions = (
            _functions_only_called_from_nonreturning_paths(
                control_flow,
                return_reachable_blocks,
                role_roots,
                set().union(*role_functions.values()),
            )
        )
        roles_by_function: dict[int, set[str]] = {}
        for role, functions in role_functions.items():
            for function_pc in functions:
                roles_by_function.setdefault(function_pc, set()).add(role)

        events: list[MemoryEvent] = []
        # InstructionModuleFacts 还包含不可达函数的解码缺口；这里只传播线程可达事实。
        unknowns: list[UnknownFact] = []
        block_events: dict[tuple[str, int], list[MemoryEvent]] = {}

        def append_event(event: MemoryEvent) -> None:
            if (
                event.function_pc in nonreturning_context_functions
                and event.function_pc not in role_roots
            ):
                # callee 自身虽能 ret，但它的所有调用点都位于失败分支。
                # 必须先于函数内的 ret 可达性判断，否则会把这种路径重新标为正常。
                event = event.model_copy(
                    update={
                        "provenance": {
                            **event.provenance,
                            "can_reach_function_return": False,
                        }
                    }
                )
            elif (
                event.function_pc in known_nonreturn_functions
                and event.function_pc not in role_roots
            ):
                # 这些 callee 的 CFG 已明确不返回。但线程入口可以
                # 通过 exit 正常结束进程，所以不能套用这条规则。
                event = event.model_copy(
                    update={
                        "provenance": {
                            **event.provenance,
                            "can_reach_function_return": False,
                        }
                    }
                )
            elif (
                event.block_pc is not None
                and event.function_pc in functions_with_return
            ):
                event = event.model_copy(
                    update={
                        "provenance": {
                            **event.provenance,
                            "can_reach_function_return": (
                                event.block_pc in return_reachable_blocks
                            ),
                        }
                    }
                )
            events.append(event)
            if event.block_pc is not None and event.thread_role is not None:
                block_events.setdefault((event.thread_role, event.block_pc), []).append(event)

        for role in threads.roles:
            if role.start_targets.complete and role.start_targets.known_targets:
                continue
            event_id = f"{role.id}:unknown-thread-entry"
            append_event(
                MemoryEvent(
                    id=event_id,
                    module=module.path,
                    module_sha256=module.sha256,
                    pc=role.create_site.pc if role.create_site else control_flow.entry_pc,
                    kind=EventKind.UNKNOWN_MEMORY_EFFECT,
                    address=AbstractAddress(kind=AddressKind.UNKNOWN),
                    thread_role=role.id,
                    provenance={"reason": role.start_targets.reason},
                )
            )
            unknowns.append(
                _unknown(
                    UnknownKind.UNKNOWN_THREAD_ROLE,
                    role.start_targets.reason or "thread entry is incomplete",
                    "the unknown worker may access any shared object",
                    module=module.path,
                    pc=role.create_site.pc if role.create_site else None,
                    details={"event_id": event_id, "role": role.id},
                    canonical_ledger=canonical_ledger,
                    canonical_scope=canonical_scope,
                )
            )

        for fact in instruction_report.facts:
            block_pc = instruction_to_block.get(fact.pc)
            if block_pc is None:
                continue
            function_pc = block_to_function.get(block_pc)
            if function_pc is None:
                continue
            roles = roles_by_function.get(function_pc, set())
            if not roles:
                continue
            unknowns.extend(fact.unknowns)
            _mirror_unknowns(fact.unknowns, canonical_ledger, canonical_scope)
            source_ordering, target_ordering = _event_ordering(fact)
            for role in sorted(roles):
                provenance_addresses = role_address_provenance[role].addresses
                for operand in fact.memory_operands:
                    address = _canonical_stack_address(
                        provenance_addresses.get(
                            (fact.pc, operand.operand_index)
                        ) or _address(module, fact, operand, function_pc)
                    )
                    for effect_index, kind in enumerate(_memory_kinds(fact, operand)):
                        event_id = (
                            f"{role}:0x{fact.pc:x}:m{operand.operand_index}:{effect_index}"
                        )
                        event = MemoryEvent(
                            id=event_id,
                            module=module.path,
                            module_sha256=module.sha256,
                            pc=fact.pc,
                            block_pc=block_pc,
                            function=function_names.get(function_pc),
                            function_pc=function_pc,
                            kind=kind,
                            address=address,
                            size=operand.size,
                            source_ordering=source_ordering,
                            target_ordering=target_ordering,
                            thread_role=role,
                            operand_index=operand.operand_index,
                            provenance={
                                "raw_bytes": fact.raw_bytes,
                                "mnemonic": fact.mnemonic,
                                "op_str": fact.op_str,
                                "dbt_rule": (
                                    "lock_rmw"
                                    if fact.has_lock_prefix
                                    else "memory_xchg"
                                    if fact.is_memory_xchg
                                    else "plain_memory"
                                ),
                            },
                        )
                        append_event(event)
                        if address.kind == AddressKind.UNKNOWN:
                            unknowns.append(
                                _unknown(
                                    UnknownKind.UNKNOWN_SHARED_ADDRESS,
                                    "memory address is not reduced to a bounded object",
                                    "the event must remain a MayAlias communication candidate",
                                    module=module.path,
                                    pc=fact.pc,
                                    function=function_names.get(function_pc),
                                    details={"event_id": event_id, "expression": address.expression},
                                    canonical_ledger=canonical_ledger,
                                    canonical_scope=canonical_scope,
                                )
                            )
                if fact.fence is not None:
                    append_event(
                        MemoryEvent(
                            id=f"{role}:0x{fact.pc:x}:fence",
                            module=module.path,
                            module_sha256=module.sha256,
                            pc=fact.pc,
                            block_pc=block_pc,
                            function=function_names.get(function_pc),
                            function_pc=function_pc,
                            kind=EventKind.FENCE,
                            source_ordering=source_ordering,
                            target_ordering=target_ordering,
                            thread_role=role,
                            provenance={"mnemonic": fact.mnemonic, "raw_bytes": fact.raw_bytes},
                        )
                    )
                if fact.is_syscall:
                    event_id = f"{role}:0x{fact.pc:x}:syscall"
                    append_event(
                        MemoryEvent(
                            id=event_id,
                            module=module.path,
                            module_sha256=module.sha256,
                            pc=fact.pc,
                            block_pc=block_pc,
                            function=function_names.get(function_pc),
                            function_pc=function_pc,
                            kind=EventKind.SYSCALL,
                            address=AbstractAddress(kind=AddressKind.UNKNOWN),
                            thread_role=role,
                            provenance={"mnemonic": "syscall"},
                        )
                    )
                    unknowns.append(
                        _unknown(
                            UnknownKind.UNKNOWN_MEMORY_EFFECT,
                            "syscall memory effects are not summarized",
                            "the syscall remains in the shared-memory slice",
                            module=module.path,
                            pc=fact.pc,
                            details={"event_id": event_id},
                            canonical_ledger=canonical_ledger,
                            canonical_scope=canonical_scope,
                        )
                    )

        for call in control_flow.call_sites:
            roles = roles_by_function.get(call.containing_function_pc, set())
            external_or_incomplete = (
                not call.targets.complete
                or call.kind == CallKind.PLT
                or any(
                    target.module_sha256 != module.sha256
                    for target in call.targets.known_targets
                )
            )
            if not external_or_incomplete:
                continue
            symbol = call.target_symbol or "<indirect>"
            contracted_effect = effect_contract.get(symbol)
            ordering, summary_reason = _summary_ordering(symbol, synchronization)
            kind = _call_event_kind(symbol, ordering)
            for role in sorted(roles):
                role_call_arguments = role_address_provenance[
                    role
                ].call_arguments.get(
                    call.location.pc,
                    base_address_provenance.call_arguments.get(
                        call.location.pc, ()
                    ),
                )
                call_argument_details = [
                    item.model_dump(mode="json") if item is not None else None
                    for item in role_call_arguments
                ]
                event_id = f"{role}:0x{call.location.pc:x}:call"
                if contracted_effect == "argument_access":
                    # 只展开规格中列出的指针参数。无法恢复参数来源时仍生成
                    # Unknown，避免把一个不完整的 libc 摘要当成无 effect。
                    specs = memory_argument_contract.get(symbol, ())
                    for argument_index, access_mode in specs:
                        address = (
                            role_call_arguments[argument_index]
                            if argument_index < len(role_call_arguments)
                            else None
                        )
                        if address is None:
                            unknown_event_id = (
                                f"{event_id}:arg{argument_index}:unknown"
                            )
                            append_event(
                                MemoryEvent(
                                    id=unknown_event_id,
                                    module=module.path,
                                    module_sha256=module.sha256,
                                    pc=call.location.pc,
                                    block_pc=call.block_pc,
                                    function=function_names.get(
                                        call.containing_function_pc
                                    ),
                                    function_pc=call.containing_function_pc,
                                    kind=EventKind.UNKNOWN_MEMORY_EFFECT,
                                    address=AbstractAddress(kind=AddressKind.UNKNOWN),
                                    thread_role=role,
                                    provenance={
                                        "target_symbol": symbol,
                                        "contracted_effect": contracted_effect,
                                        "argument_index": argument_index,
                                        "access_mode": access_mode,
                                    },
                                )
                            )
                            unknowns.append(
                                _unknown(
                                    UnknownKind.UNKNOWN_MEMORY_EFFECT,
                                    (
                                        f"call {symbol!r} argument {argument_index} "
                                        "address is not recoverable"
                                    ),
                                    "the external memory access remains a MayAlias candidate",
                                    module=module.path,
                                    pc=call.location.pc,
                                    function=function_names.get(
                                        call.containing_function_pc
                                    ),
                                    details={"event_id": unknown_event_id},
                                    canonical_ledger=canonical_ledger,
                                    canonical_scope=canonical_scope,
                                )
                            )
                            continue
                        kind = (
                            EventKind.LOAD
                            if access_mode == "read"
                            else EventKind.STORE
                        )
                        append_event(
                            MemoryEvent(
                                id=f"{event_id}:arg{argument_index}:{access_mode}",
                                module=module.path,
                                module_sha256=module.sha256,
                                pc=call.location.pc,
                                block_pc=call.block_pc,
                                function=function_names.get(
                                    call.containing_function_pc
                                ),
                                function_pc=call.containing_function_pc,
                                kind=kind,
                                address=address,
                                # 规格通常只知道指针起点，不知道动态长度；
                                # None 让别名层保守保留同 base 的候选冲突。
                                size=None,
                                source_ordering=Ordering.TSO,
                                target_ordering=Ordering.RELAXED,
                                thread_role=role,
                                provenance={
                                    "target_symbol": symbol,
                                    "contracted_effect": contracted_effect,
                                    "argument_index": argument_index,
                                    "access_mode": access_mode,
                                    "call_arguments": call_argument_details,
                                },
                            )
                        )
                    internal_object = internal_object_contract.get(symbol)
                    if internal_object is not None:
                        # FILE 等运行库对象不属于应用切片，但 full scope 仍
                        # 保留这个 opaque effect，避免把库内部状态误当私有。
                        runtime_event_id = f"{event_id}:runtime"
                        append_event(
                            MemoryEvent(
                                id=runtime_event_id,
                                module=module.path,
                                module_sha256=module.sha256,
                                pc=call.location.pc,
                                block_pc=call.block_pc,
                                function=function_names.get(
                                    call.containing_function_pc
                                ),
                                function_pc=call.containing_function_pc,
                                kind=EventKind.OPAQUE_CALL,
                                address=AbstractAddress(
                                    kind=AddressKind.GLOBAL,
                                    base=internal_object,
                                    provenance={
                                        "contracted_effect": contracted_effect,
                                        "target_symbol": symbol,
                                        "runtime_internal": True,
                                    },
                                ),
                                source_ordering=Ordering.UNKNOWN,
                                target_ordering=Ordering.UNKNOWN,
                                thread_role=role,
                                provenance={
                                    "target_symbol": symbol,
                                    "contracted_effect": contracted_effect,
                                    "internal_object": internal_object,
                                    "runtime_internal": True,
                                },
                            )
                        )
                        unknowns.append(
                            _unknown(
                                UnknownKind.UNKNOWN_MEMORY_EFFECT,
                                (
                                    f"call {symbol!r} has an unmodeled runtime object "
                                    f"{internal_object}"
                                ),
                                "full-process scope must retain the runtime effect",
                                module=module.path,
                                pc=call.location.pc,
                                function=function_names.get(
                                    call.containing_function_pc
                                ),
                                details={"event_id": runtime_event_id},
                                canonical_ledger=canonical_ledger,
                                canonical_scope=canonical_scope,
                            )
                        )
                    continue
                if contracted_effect == "thread_local":
                    # libm 可能更新 errno/fenv；把它保留为 TLS 读写，而不是假装无 effect。
                    # 后续只有在 TLS 地址没有逃逸时才能剪除这两个事件。
                    for suffix, effect_kind in (
                        ("tls-read", EventKind.LOAD),
                        ("tls-write", EventKind.STORE),
                    ):
                        append_event(
                            MemoryEvent(
                                id=f"{event_id}:{suffix}",
                                module=module.path,
                                module_sha256=module.sha256,
                                pc=call.location.pc,
                                block_pc=call.block_pc,
                                function=function_names.get(
                                    call.containing_function_pc
                                ),
                                function_pc=call.containing_function_pc,
                                kind=effect_kind,
                                address=AbstractAddress(
                                    kind=AddressKind.TLS,
                                    base=f"function-effect:{symbol}",
                                    offset=0,
                                    provenance={
                                        "contracted_effect": contracted_effect,
                                        "target_symbol": symbol,
                                    },
                                ),
                                source_ordering=Ordering.TSO,
                                target_ordering=Ordering.RELAXED,
                                thread_role=role,
                                provenance={
                                    "target_symbol": symbol,
                                    "contracted_effect": contracted_effect,
                                    "integer_arguments": list(
                                        integer_argument_contract.get(symbol, ())
                                    ),
                                },
                            )
                        )
                    continue
                internal_object = internal_object_contract.get(symbol)
                address = None
                if kind == EventKind.OPAQUE_CALL:
                    address = AbstractAddress(
                        kind=(
                            AddressKind.GLOBAL
                            if internal_object is not None
                            else AddressKind.UNKNOWN
                        ),
                        base=internal_object,
                        provenance={
                            "contracted_effect": contracted_effect,
                            "target_symbol": symbol,
                            "runtime_internal": internal_object is not None,
                        },
                    )
                elif kind in {
                    EventKind.ACQUIRE,
                    EventKind.RELEASE,
                    EventKind.BARRIER,
                }:
                    # 同步对象本身不是 wildcard memory effect；能恢复第一个
                    # 指针参数时把它挂到事件上，后续 lockset 分析才能识别
                    # 两个普通访问是否由同一把锁保护。
                    address = (
                        role_call_arguments[0]
                        if role_call_arguments
                        and role_call_arguments[0] is not None
                        else None
                    )
                append_event(
                    MemoryEvent(
                        id=event_id,
                        module=module.path,
                        module_sha256=module.sha256,
                        pc=call.location.pc,
                        block_pc=call.block_pc,
                        function=function_names.get(call.containing_function_pc),
                        function_pc=call.containing_function_pc,
                        kind=kind,
                        address=address,
                        source_ordering=(
                            Ordering.FULL if kind in _lifecycle_or_sync_kinds() else Ordering.UNKNOWN
                        ),
                        target_ordering=ordering or Ordering.UNKNOWN,
                        thread_role=role,
                        provenance={
                            "target_symbol": call.target_symbol,
                            "contracted_effect": contracted_effect,
                            "integer_arguments": list(
                                integer_argument_contract.get(symbol, ())
                            ),
                            "call_arguments": call_argument_details,
                            "target_set_complete": call.targets.complete,
                            "target_evidence": list(call.targets.evidence),
                            "summary_reason": summary_reason,
                            **_summary_provenance(symbol, synchronization),
                        },
                    )
                )
                if kind == EventKind.OPAQUE_CALL:
                    unknowns.append(
                        _unknown(
                            UnknownKind.UNKNOWN_MEMORY_EFFECT,
                            (
                                f"call {symbol!r} has no usable memory-effect summary: "
                                f"{summary_reason or 'unknown reason'}"
                            ),
                            (
                                f"the call may read or write runtime object {internal_object}"
                                if internal_object is not None
                                else "the call may read or write any shared object"
                            ),
                            module=module.path,
                            pc=call.location.pc,
                            function=function_names.get(call.containing_function_pc),
                            details={
                                "event_id": event_id,
                                "target_symbol": call.target_symbol,
                                "contracted_effect": contracted_effect,
                                "internal_object": internal_object,
                                "call_arguments": call_argument_details,
                            },
                            canonical_ledger=canonical_ledger,
                            canonical_scope=canonical_scope,
                        )
                    )

        incomplete_call_pcs = {
            call.location.pc
            for call in control_flow.call_sites
            if not call.targets.complete
        }
        for site in control_flow.indirect_sites:
            if site.targets.complete or site.location.pc in incomplete_call_pcs:
                continue
            roles = roles_by_function.get(site.containing_function_pc or -1, set())
            if not roles:
                # 不可达函数中的间接站点不属于任何线程角色；为它造 unknown role
                # 会反过来污染所有共享对象。未知线程入口已有独立哨兵覆盖。
                continue
            for role in sorted(roles):
                event_id = f"{role}:0x{site.location.pc:x}:indirect"
                append_event(
                    MemoryEvent(
                        id=event_id,
                        module=module.path,
                        module_sha256=module.sha256,
                        pc=site.location.pc,
                        function_pc=site.containing_function_pc,
                        kind=EventKind.UNKNOWN_MEMORY_EFFECT,
                        address=AbstractAddress(kind=AddressKind.UNKNOWN),
                        thread_role=role,
                        provenance={
                            "control_flow": site.control_flow,
                            "target_set_complete": False,
                            "known_targets": [target.pc for target in site.targets.known_targets],
                        },
                    )
                )
                unknowns.append(
                    _unknown(
                        UnknownKind.UNKNOWN_MEMORY_EFFECT,
                        site.targets.reason or "indirect jump target set is incomplete",
                        "unrecovered target code may access any shared object",
                        module=module.path,
                        pc=site.location.pc,
                        details={"event_id": event_id},
                        canonical_ledger=canonical_ledger,
                        canonical_scope=canonical_scope,
                    )
                )

        program_order = _program_order_edges(
            control_flow, block_events
        )
        unique_unknowns = {
            (item.kind, item.module, item.pc, item.reason, str(item.details)): item
            for item in unknowns
        }
        return MemoryEventReport(
            module_path=module.path,
            module_sha256=module.sha256,
            events=tuple(sorted(events, key=lambda item: (item.thread_role or "", item.pc, item.id))),
            program_order=program_order,
            unknowns=tuple(unique_unknowns.values()),
        )
    except Exception as error:
        unknown = _unknown(
            UnknownKind.MEMORY_EVENT_RECOVERY_FAILURE,
            str(error),
            "shared-memory effects are unavailable; later analysis must not use an empty slice",
            module=module.path,
            canonical_ledger=canonical_ledger,
            canonical_scope=canonical_scope,
        )
        sentinel = MemoryEvent(
            id="unknown:memory-event-recovery",
            module=module.path,
            module_sha256=module.sha256,
            pc=control_flow.entry_pc,
            kind=EventKind.UNKNOWN_MEMORY_EFFECT,
            address=AbstractAddress(kind=AddressKind.UNKNOWN),
            provenance={"failure": str(error)},
        )
        return MemoryEventReport(
            module_path=module.path,
            module_sha256=module.sha256,
            events=(sentinel,),
            unknowns=(unknown,),
        )


def _lifecycle_or_sync_kinds() -> set[EventKind]:
    return {
        EventKind.THREAD_CREATE,
        EventKind.THREAD_JOIN,
        EventKind.ACQUIRE,
        EventKind.RELEASE,
        EventKind.BARRIER,
    }


def _event_order_key(event: MemoryEvent) -> tuple[int, int, str]:
    call_boundary = event.kind in _lifecycle_or_sync_kinds() | {EventKind.OPAQUE_CALL}
    # call 的隐式 stack write 发生在进入 callee 前，生命周期/同步 effect 随后才成立。
    return event.pc, 1 if call_boundary else 0, event.id


def _program_order_edges(
    report: ControlFlowReport,
    block_events: dict[tuple[str, int], list[MemoryEvent]],
) -> tuple[ProgramOrderEdge, ...]:
    block_by_pc = {item.location.pc: item for item in report.basic_blocks}
    edges: dict[tuple[str, str, str], ProgramOrderEdge] = {}
    for (role, block_pc), events in block_events.items():
        ordered = sorted(events, key=_event_order_key)
        for first, second in zip(ordered, ordered[1:]):
            edge = ProgramOrderEdge(
                source_event=first.id,
                target_event=second.id,
                thread_role=role,
                evidence="instruction order inside one CFG block",
            )
            edges[(edge.source_event, edge.target_event, role)] = edge
        if not ordered:
            continue
        source = ordered[-1]
        pending: deque[int] = deque(block_by_pc.get(block_pc).successor_pcs if block_pc in block_by_pc else ())
        visited: set[int] = set()
        while pending:
            successor = pending.popleft()
            if successor in visited:
                continue
            visited.add(successor)
            next_events = block_events.get((role, successor), ())
            if next_events:
                target = min(next_events, key=_event_order_key)
                edge = ProgramOrderEdge(
                    source_event=source.id,
                    target_event=target.id,
                    thread_role=role,
                    evidence="CFG successor through zero or more empty blocks",
                )
                edges[(edge.source_event, edge.target_event, role)] = edge
                continue
            block = block_by_pc.get(successor)
            if block is not None:
                pending.extend(block.successor_pcs)
    return tuple(sorted(edges.values(), key=lambda item: (item.thread_role, item.source_event, item.target_event)))
