from __future__ import annotations

from bisect import bisect_left
from collections import deque
from pathlib import Path

import yaml

from bmo_check_core import EvidenceLedger
from bmo_check_static.binary.capstone_backend import collect_instruction_facts
from bmo_check_static.binary.evidence import emit_static_unknown
from bmo_check_static.binary.symbols import function_symbols
from bmo_check_static.model import (
    ControlFlowKind,
    FenceKind,
    InstructionFact,
    MemoryAccessKind,
    ModuleFingerprint,
    Ordering,
    SynchronizationKind,
    SynchronizationReport,
    SynchronizationSummary,
    SyncInstructionEvidence,
    UnknownFact,
    UnknownKind,
)


_ORDERING_BY_NAME = {
    "relaxed": Ordering.RELAXED,
    "acquire": Ordering.ACQUIRE,
    "release": Ordering.RELEASE,
    "acq_rel": Ordering.ACQ_REL,
    "full": Ordering.FULL,
}

_KIND_BY_API = {
    "pthread_create": SynchronizationKind.THREAD_CREATE,
    "pthread_join": SynchronizationKind.THREAD_JOIN,
    "pthread_mutex_lock": SynchronizationKind.ACQUIRE,
    "pthread_mutex_unlock": SynchronizationKind.RELEASE,
    "pthread_spin_lock": SynchronizationKind.ACQUIRE,
    "pthread_spin_unlock": SynchronizationKind.RELEASE,
    "pthread_cond_wait": SynchronizationKind.CONDITION_WAIT,
    "pthread_cond_signal": SynchronizationKind.CONDITION_SIGNAL,
    "pthread_cond_broadcast": SynchronizationKind.CONDITION_BROADCAST,
    "pthread_barrier_wait": SynchronizationKind.BARRIER,
    "pthread_once": SynchronizationKind.ONCE,
}

_REQUIRED_DEFAULT = {
    "pthread_create": Ordering.RELEASE,
    "pthread_join": Ordering.ACQUIRE,
}


def _load_yaml(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


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
    canonical_scope: str = "static.synchronization",
) -> UnknownFact:
    """把同步摘要缺口同时保留在旧报告和 canonical ledger 中。"""

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


def _mirror_instruction_unknowns(
    unknowns: tuple[UnknownFact, ...],
    ledger: EvidenceLedger | None,
    scope: str,
) -> None:
    """同步摘要复用反汇编结果时，不让其中的 Unknown 在旁路丢失。"""

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


def _effect_bits(fact: InstructionFact) -> int:
    if fact.has_lock_prefix or fact.is_memory_xchg:
        return 0b11
    if fact.fence == FenceKind.LFENCE:
        return 0b01
    if fact.fence == FenceKind.SFENCE:
        return 0b10
    if fact.fence == FenceKind.MFENCE:
        return 0b11
    return 0


def _ordering(bits: int, full: bool = False) -> Ordering:
    if full and bits == 0b11:
        return Ordering.FULL
    return {
        0: Ordering.RELAXED,
        1: Ordering.ACQUIRE,
        2: Ordering.RELEASE,
        3: Ordering.ACQ_REL,
    }[bits]


def _ordering_bits(ordering: Ordering) -> tuple[int, bool]:
    return {
        Ordering.RELAXED: (0, False),
        Ordering.ACQUIRE: (0b01, False),
        Ordering.RELEASE: (0b10, False),
        Ordering.ACQ_REL: (0b11, False),
        Ordering.FULL: (0b11, True),
    }.get(ordering, (0, False))


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


def _evidence(fact: InstructionFact) -> SyncInstructionEvidence | None:
    if not (
        fact.has_lock_prefix
        or fact.is_memory_xchg
        or fact.fence is not None
        or fact.memory_operands
    ):
        return None
    memory_access = None
    if fact.memory_operands:
        accesses = {item.access for item in fact.memory_operands}
        if MemoryAccessKind.READ_WRITE in accesses or len(accesses) > 1:
            memory_access = MemoryAccessKind.READ_WRITE
        else:
            memory_access = next(iter(accesses))
    bits = _effect_bits(fact)
    return SyncInstructionEvidence(
        pc=fact.pc,
        mnemonic=fact.mnemonic,
        op_str=fact.op_str,
        has_lock_prefix=fact.has_lock_prefix,
        is_memory_xchg=fact.is_memory_xchg,
        fence=fact.fence,
        memory_access=memory_access,
        translated_ordering=_ordering(bits, fact.fence == FenceKind.MFENCE),
    )


def _return_path_orderings(
    facts: tuple[InstructionFact, ...],
    function_start: int,
    function_end: int,
    function_bodies: dict[int, tuple[int, tuple[InstructionFact, ...]]] | None = None,
    syscall_ordering: Ordering = Ordering.UNKNOWN,
    allow_unknown_syscall: bool = False,
) -> tuple[tuple[Ordering, ...], bool, str | None, tuple[int, ...]]:
    bodies = dict(function_bodies or {})
    bodies.setdefault(function_start, (function_end, facts))
    cache: dict[int, tuple[tuple[tuple[int, bool], ...], bool, set[str], set[int]]] = {}

    def walk(
        start: int, active: frozenset[int]
    ) -> tuple[tuple[tuple[int, bool], ...], bool, set[str], set[int]]:
        cached = cache.get(start)
        if cached is not None:
            return cached
        body = bodies.get(start)
        if body is None or not body[1]:
            return (), False, {f"function 0x{start:x} has no decoded body"}, set()
        if start in active:
            return (), False, {f"recursive call cycle reaches 0x{start:x}"}, set()

        end, body_facts = body
        by_pc = {fact.pc: index for index, fact in enumerate(body_facts)}
        queue: deque[tuple[int, int, bool]] = deque([(0, 0, False)])
        visited: set[tuple[int, int, bool]] = set()
        visited_pcs: set[int] = set()
        returns: list[tuple[int, bool]] = []
        complete = True
        reasons: set[str] = set()
        next_active = active | {start}

        while queue:
            index, bits, full = queue.popleft()
            state = (index, bits, full)
            if state in visited:
                continue
            visited.add(state)
            if index < 0 or index >= len(body_facts):
                complete = False
                reasons.add("control flow leaves a decoded function range")
                continue
            fact = body_facts[index]
            visited_pcs.add(fact.pc)
            next_bits = bits | _effect_bits(fact)
            next_full = full or fact.fence == FenceKind.MFENCE
            if fact.is_syscall:
                syscall_bits, syscall_full = _ordering_bits(syscall_ordering)
                next_bits |= syscall_bits
                next_full |= syscall_full
                if syscall_ordering == Ordering.UNKNOWN and not allow_unknown_syscall:
                    complete = False
                    reasons.add(
                        f"0x{fact.pc:x}: syscall target ordering is absent from the DBT contract"
                    )
            if not fact.classification_complete:
                complete = False
                reasons.add("one or more instructions are not fully classified")

            if fact.control_flow == ControlFlowKind.RETURN:
                returns.append((next_bits, next_full))
                continue
            if fact.control_flow == ControlFlowKind.INDIRECT_JUMP:
                complete = False
                reasons.add(f"0x{fact.pc:x}: indirect tail target is not summarized")
                continue
            if fact.control_flow == ControlFlowKind.INDIRECT_CALL:
                complete = False
                reasons.add(f"0x{fact.pc:x}: indirect callee is not summarized")

            fallthrough = index + 1
            if fact.control_flow == ControlFlowKind.DIRECT_CALL:
                target = fact.direct_target
                if target not in bodies:
                    complete = False
                    rendered = "unknown" if target is None else f"0x{target:x}"
                    reasons.add(
                        f"0x{fact.pc:x}: direct callee {rendered} has no closed local body"
                    )
                else:
                    paths, callee_complete, callee_reasons, callee_pcs = walk(
                        target, next_active
                    )
                    complete &= callee_complete
                    reasons.update(callee_reasons)
                    visited_pcs.update(callee_pcs)
                    if paths and fallthrough < len(body_facts):
                        for callee_bits, callee_full in paths:
                            queue.append(
                                (
                                    fallthrough,
                                    next_bits | callee_bits,
                                    next_full or callee_full,
                                )
                            )
                        continue

            if fact.control_flow == ControlFlowKind.DIRECT_JUMP:
                target = fact.direct_target
                if target is not None and start <= target < end and target in by_pc:
                    queue.append((by_pc[target], next_bits, next_full))
                elif fact.mnemonic == "jmp" and target in bodies:
                    # glibc 常用小型导出符号尾跳到同一 ELF 的真实实现。
                    # 把目标的所有返回路径接到当前函数，避免把确定跳转误报成间接缺口。
                    paths, callee_complete, callee_reasons, callee_pcs = walk(
                        target, next_active
                    )
                    complete &= callee_complete
                    reasons.update(callee_reasons)
                    visited_pcs.update(callee_pcs)
                    returns.extend(
                        (next_bits | callee_bits, next_full or callee_full)
                        for callee_bits, callee_full in paths
                    )
                else:
                    complete = False
                    rendered = "unknown" if target is None else f"0x{target:x}"
                    reasons.add(
                        f"0x{fact.pc:x}: direct jump target {rendered} has no closed local body"
                    )
                if fact.mnemonic == "jmp":
                    continue
            if fallthrough < len(body_facts):
                queue.append((fallthrough, next_bits, next_full))
            else:
                complete = False
                reasons.add(f"function 0x{start:x} ends without a return")

        if not returns:
            complete = False
            reasons.add(f"function 0x{start:x} has no recovered return path")
        result = tuple(returns), complete, reasons, visited_pcs
        cache[start] = result
        return result

    returns, complete, reasons, visited_pcs = walk(function_start, frozenset())
    if not returns:
        return (), complete, "; ".join(sorted(reasons)), tuple(sorted(visited_pcs))
    intersection = returns[0][0]
    all_full = returns[0][1]
    for bits, full in returns[1:]:
        intersection &= bits
        all_full &= full
    path_orderings = tuple(sorted({_ordering(bits, full) for bits, full in returns}, key=str))
    # target_ordering 由所有返回路径的交集给出；任何一条弱路径都不能被更强路径掩盖。
    path_orderings = (_ordering(intersection, all_full),) + tuple(
        item for item in path_orderings if item != _ordering(intersection, all_full)
    )
    return (
        path_orderings,
        complete,
        "; ".join(sorted(reasons)) or None,
        tuple(sorted(visited_pcs)),
    )


def _trusted_library_ordering(
    library: ModuleFingerprint,
    api: str,
    facts: tuple[InstructionFact, ...],
    trusted_apis: object,
    bodies: dict[int, tuple[int, tuple[InstructionFact, ...]]] | None = None,
) -> tuple[Ordering, tuple[int, ...]] | None:
    """按完整库哈希绑定 glibc 私有 helper 的排序摘要。

    glibc 的公开 pthread 符号经常尾跳到没有 ELF 函数符号的私有 helper。
    CFG 无法闭合这些 helper 时，不能把 API 名称本身当作排序证据；规格先
    绑定具体库哈希，当前反汇编还必须找到 LOCK/XCHG/Fence 证据。
    """

    if not isinstance(trusted_apis, dict):
        return None
    entry = trusted_apis.get(api)
    if not isinstance(entry, dict):
        return None
    expected_hash = entry.get("module_sha256")
    compatible_hashes = trusted_apis.get("compatible_module_sha256", ())
    accepted_hashes = {
        item
        for item in (expected_hash, *compatible_hashes)
        if isinstance(item, str)
    }
    if library.sha256 not in accepted_hashes:
        return None
    target = _ORDERING_BY_NAME.get(str(entry.get("target_ordering", "unknown")))
    if target is None:
        return None
    evidence = tuple(
        fact.pc
        for fact in facts
        if fact.has_lock_prefix or fact.is_memory_xchg or fact.fence is not None
    )
    if not evidence and bodies:
        # pthread_join 这类公开入口只有一条短 tail-jump，真正的原子操作在
        # 同库私有 helper 中。沿着有限的 direct call/jump 找到该 helper；
        # 不把整份库的任意 LOCK 当成当前 API 的证据。
        pending = [
            fact.direct_target
            for fact in facts
            if fact.direct_target is not None
            and fact.control_flow
            and fact.control_flow.value in {"direct_call", "direct_jump"}
        ]
        visited: set[int] = set()
        while pending and len(visited) < 16:
            target_pc = pending.pop()
            if target_pc is None or target_pc in visited:
                continue
            visited.add(target_pc)
            body = bodies.get(target_pc)
            if body is None:
                continue
            helper_facts = body[1]
            helper_evidence = tuple(
                item.pc
                for item in helper_facts
                if item.has_lock_prefix
                or item.is_memory_xchg
                or item.fence is not None
            )
            if helper_evidence:
                evidence = helper_evidence
                break
            pending.extend(
                item.direct_target
                for item in helper_facts
                if item.direct_target is not None
                and item.control_flow
                and item.control_flow.value in {"direct_call", "direct_jump"}
            )
    if not evidence and library.sha256 in set(compatible_hashes):
        # glibc 版本可能在 libc.so.6 留一个 ABI wrapper，把公开符号尾跳到
        # 同一 x86lib 目录中的 libpthread 实现。wrapper 自身没有 LOCK，
        # 但必须出现实际 tail jump/call；普通无关函数不能借这条别名。
        evidence = tuple(
            fact.pc
            for fact in facts
            if fact.control_flow
            and fact.control_flow.value in {"direct_jump", "indirect_jump"}
        )
    if not evidence:
        return None
    return target, evidence


def analyze_pthread_synchronization(
    library: ModuleFingerprint,
    pthread_spec_path: Path,
    dbt_contract_path: Path,
    requested_apis: set[str] | None = None,
    *,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.synchronization",
) -> SynchronizationReport:
    pthread_spec = _load_yaml(pthread_spec_path)
    contract = _load_yaml(dbt_contract_path)
    contract_version = str(contract.get("contract_version", "unknown"))
    translation = contract.get("translation", {})
    translation = translation if isinstance(translation, dict) else {}
    syscall_entry = translation.get("syscall", {})
    syscall_entry = syscall_entry if isinstance(syscall_entry, dict) else {}
    syscall_ordering = _ORDERING_BY_NAME.get(
        str(syscall_entry.get("target_ordering", "unknown")), Ordering.UNKNOWN
    )
    api_entries = pthread_spec.get("apis", {})
    if not isinstance(api_entries, dict):
        raise ValueError("pthread API specification must contain an 'apis' mapping")
    trusted_implementations = pthread_spec.get("trusted_implementations", {})

    instruction_report = collect_instruction_facts(library)
    _mirror_instruction_unknowns(
        instruction_report.unknowns,
        canonical_ledger,
        canonical_scope,
    )
    ordered_facts = tuple(sorted(instruction_report.facts, key=lambda item: item.pc))
    fact_pcs = tuple(item.pc for item in ordered_facts)

    def facts_in_range(start: int, end: int) -> tuple[InstructionFact, ...]:
        first = bisect_left(fact_pcs, start)
        last = bisect_left(fact_pcs, end)
        return ordered_facts[first:last]

    all_symbols = function_symbols(library)
    symbols_by_name: dict[str, list[object]] = {}
    for symbol in all_symbols:
        symbols_by_name.setdefault(symbol.name, []).append(symbol)
    bodies: dict[int, tuple[int, tuple[InstructionFact, ...]]] = {}
    for symbol in all_symbols:
        if symbol.size <= 0:
            continue
        previous = bodies.get(symbol.pc)
        if previous is not None and previous[0] >= symbol.pc + symbol.size:
            continue
        end = symbol.pc + symbol.size
        bodies[symbol.pc] = (
            end,
            facts_in_range(symbol.pc, end),
        )
    summaries: list[SynchronizationSummary] = []
    report_unknowns: list[UnknownFact] = list(instruction_report.unknowns)

    for api, kind in _KIND_BY_API.items():
        if requested_apis is not None and api not in requested_apis:
            continue
        entry = api_entries.get(api, {})
        entry = entry if isinstance(entry, dict) else {}
        required = _ORDERING_BY_NAME.get(
            str(entry.get("required_ordering", "unknown")),
            _REQUIRED_DEFAULT.get(api, Ordering.UNKNOWN),
        )
        # 只有 API 自身已经用 LOCK/XCHG 或 fence 给出所需边界时，
        # 才允许忽略其 futex 慢路径的 syscall；普通函数不能复用这项例外。
        allow_unknown_syscall = bool(entry.get("allow_unknown_syscall", False))
        symbols = {symbol.pc: symbol for symbol in symbols_by_name.get(api, [])}
        if not symbols:
            report_unknowns.append(
                _unknown(
                    UnknownKind.MISSING_SYMBOL_IMPLEMENTATION,
                    f"{api} has no concrete function symbol in this library",
                    "the synchronization API cannot be bound to machine instructions",
                    module=library.path,
                    function=api,
                    details={"api": api},
                    canonical_ledger=canonical_ledger,
                    canonical_scope=canonical_scope,
                )
            )
            continue
        # 同名的版本化实现都进入报告；缺少 version binding 时任选一个会漏掉真实实现。
        for symbol in sorted(symbols.values(), key=lambda item: item.pc):
            end = symbol.pc + symbol.size
            facts = facts_in_range(symbol.pc, end)
            path_orderings, complete, reason, evidence_pcs = _return_path_orderings(
                facts,
                symbol.pc,
                end,
                bodies,
                syscall_ordering,
                allow_unknown_syscall,
            )
            trusted = _trusted_library_ordering(
                library,
                api,
                facts,
                trusted_implementations,
                bodies,
            )
            target = path_orderings[0] if path_orderings else Ordering.UNKNOWN
            # CFG 可能把某条私有 helper 路径闭合成 Relaxed；这仍然不能
            # 覆盖已绑定库摘要声明的 Acquire/Release。只有摘要哈希和机器码
            # 证据都匹配时，才用更强的已审计排序替换这个过弱的结果。
            if trusted is not None and (
                not complete or not _ordering_covers(target, required)
            ):
                trusted_ordering, trusted_pcs = trusted
                if _ordering_covers(trusted_ordering, required):
                    # 私有 helper 的 CFG 缺口仍保留在普通 library report 中，
                    # 但这个公开 API 的排序只依赖已绑定库里的原子证据。
                    path_orderings = (trusted_ordering,)
                    complete = True
                    reason = None
                    evidence_pcs = tuple(sorted(set(evidence_pcs) | set(trusted_pcs)))
            evidence_pc_set = set(evidence_pcs)
            evidence = tuple(
                item
                for fact in ordered_facts
                if fact.pc in evidence_pc_set
                if (item := _evidence(fact)) is not None
            )
            target = path_orderings[0] if path_orderings else Ordering.UNKNOWN
            local_unknowns: list[UnknownFact] = []
            if not complete:
                local_unknowns.append(
                    _unknown(
                        UnknownKind.UNKNOWN_SYNCHRONIZATION,
                        reason or "not every return path was summarized",
                        "future proof must not assume a stronger library ordering",
                        module=library.path,
                        pc=symbol.pc,
                        function=api,
                        details={"api": api, "contract_version": contract_version},
                        canonical_ledger=canonical_ledger,
                        canonical_scope=canonical_scope,
                    )
                )
            summaries.append(
                SynchronizationSummary(
                    api=api,
                    kind=kind,
                    required_ordering=required,
                    module_path=library.path,
                    module_sha256=library.sha256,
                    module_build_id=library.build_id,
                    function_pc=symbol.pc,
                    function_size=symbol.size,
                    evidence=evidence,
                    return_path_orderings=path_orderings,
                    target_ordering=target,
                    complete=complete,
                    reason=reason,
                    unknowns=tuple(local_unknowns),
                )
            )
            report_unknowns.extend(local_unknowns)

    return SynchronizationReport(
        contract_version=contract_version,
        library_path=library.path,
        library_sha256=library.sha256,
        summaries=tuple(summaries),
        unknowns=tuple(report_unknowns),
    )
