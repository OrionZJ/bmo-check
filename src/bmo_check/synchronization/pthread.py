from __future__ import annotations

from collections import deque
from pathlib import Path

import yaml

from bmo_check.binary.capstone_backend import collect_instruction_facts
from bmo_check.binary.symbols import function_symbols
from bmo_check.model import (
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


def _load_yaml(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


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
    facts: tuple[InstructionFact, ...], function_start: int, function_end: int
) -> tuple[tuple[Ordering, ...], bool, str | None]:
    if not facts:
        return (), False, "function range contains no decoded instructions"
    by_pc = {fact.pc: index for index, fact in enumerate(facts)}
    queue: deque[tuple[int, int, bool]] = deque([(0, 0, False)])
    visited: set[tuple[int, int, bool]] = set()
    returns: list[tuple[int, bool]] = []
    complete = True
    reasons: set[str] = set()

    while queue:
        index, bits, full = queue.popleft()
        state = (index, bits, full)
        if state in visited:
            continue
        visited.add(state)
        if index < 0 or index >= len(facts):
            complete = False
            reasons.add("control flow leaves the decoded function range")
            continue
        fact = facts[index]
        next_bits = bits | _effect_bits(fact)
        next_full = full or fact.fence == FenceKind.MFENCE
        if not fact.classification_complete:
            complete = False
            reasons.add("one or more instructions are not fully classified")

        if fact.control_flow == ControlFlowKind.RETURN:
            returns.append((next_bits, next_full))
            continue
        if fact.control_flow == ControlFlowKind.INDIRECT_JUMP:
            complete = False
            reasons.add("an indirect tail target is not summarized")
            continue
        if fact.control_flow == ControlFlowKind.INDIRECT_CALL:
            complete = False
            reasons.add("an indirect callee is not summarized")
        if fact.control_flow == ControlFlowKind.DIRECT_CALL:
            # 当前层只证明函数本体出现的 ordering；调用的 effect 留给后续摘要组合。
            complete = False
            reasons.add("a direct callee is not composed into this summary")

        fallthrough = index + 1
        if fact.control_flow == ControlFlowKind.DIRECT_JUMP:
            target = fact.direct_target
            if target is None or not (function_start <= target < function_end):
                complete = False
                reasons.add("a direct jump leaves the function range")
            elif target in by_pc:
                queue.append((by_pc[target], next_bits, next_full))
            else:
                complete = False
                reasons.add("a jump target is not an instruction boundary")
            if fact.mnemonic == "jmp":
                continue
        if fallthrough < len(facts):
            queue.append((fallthrough, next_bits, next_full))
        else:
            complete = False
            reasons.add("function range ends without a return")

    if not returns:
        complete = False
        reasons.add("no return path was recovered")
        return (), complete, "; ".join(sorted(reasons))
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
    return path_orderings, complete, "; ".join(sorted(reasons)) or None


def analyze_pthread_synchronization(
    library: ModuleFingerprint,
    pthread_spec_path: Path,
    dbt_contract_path: Path,
) -> SynchronizationReport:
    pthread_spec = _load_yaml(pthread_spec_path)
    contract = _load_yaml(dbt_contract_path)
    contract_version = str(contract.get("contract_version", "unknown"))
    api_entries = pthread_spec.get("apis", {})
    if not isinstance(api_entries, dict):
        raise ValueError("pthread API specification must contain an 'apis' mapping")

    instruction_report = collect_instruction_facts(library)
    symbols_by_name: dict[str, list[object]] = {}
    for symbol in function_symbols(library):
        symbols_by_name.setdefault(symbol.name, []).append(symbol)
    summaries: list[SynchronizationSummary] = []
    report_unknowns: list[UnknownFact] = list(instruction_report.unknowns)

    for api, kind in _KIND_BY_API.items():
        entry = api_entries.get(api, {})
        entry = entry if isinstance(entry, dict) else {}
        required = _ORDERING_BY_NAME.get(
            str(entry.get("required_ordering", "unknown")), Ordering.UNKNOWN
        )
        symbols = {symbol.pc: symbol for symbol in symbols_by_name.get(api, [])}
        if not symbols:
            report_unknowns.append(
                UnknownFact(
                    kind=UnknownKind.MISSING_SYMBOL_IMPLEMENTATION,
                    reason=f"{api} has no concrete function symbol in this library",
                    impact="the synchronization API cannot be bound to machine instructions",
                    module=library.path,
                    function=api,
                )
            )
            continue
        # 同名的版本化实现都进入报告；缺少 version binding 时任选一个会漏掉真实实现。
        for symbol in sorted(symbols.values(), key=lambda item: item.pc):
            end = symbol.pc + symbol.size
            facts = tuple(
                fact
                for fact in instruction_report.facts
                if symbol.pc <= fact.pc < end
            )
            evidence = tuple(
                item for fact in facts if (item := _evidence(fact)) is not None
            )
            path_orderings, complete, reason = _return_path_orderings(
                facts, symbol.pc, end
            )
            target = path_orderings[0] if path_orderings else Ordering.UNKNOWN
            local_unknowns: list[UnknownFact] = []
            if not complete:
                local_unknowns.append(
                    UnknownFact(
                        kind=UnknownKind.UNKNOWN_SYNCHRONIZATION,
                        reason=reason or "not every return path was summarized",
                        impact="future proof must not assume a stronger library ordering",
                        module=library.path,
                        pc=symbol.pc,
                        function=api,
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
