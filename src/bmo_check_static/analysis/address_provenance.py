from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from bmo_check_static.model import (
    AbstractAddress,
    AddressKind,
    ControlFlowReport,
    InstructionFact,
    MemoryAccessKind,
    MemoryOperandFact,
    ModuleFingerprint,
)


_REGISTER_ROOTS = {
    name: root
    for root, aliases in {
        "rax": ("rax", "eax", "ax", "al", "ah"),
        "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
        "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
        "rdx": ("rdx", "edx", "dx", "dl", "dh"),
        "rsi": ("rsi", "esi", "si", "sil"),
        "rdi": ("rdi", "edi", "di", "dil"),
        "rbp": ("rbp", "ebp", "bp", "bpl"),
        "rsp": ("rsp", "esp", "sp", "spl"),
        **{
            f"r{index}": (
                f"r{index}",
                f"r{index}d",
                f"r{index}w",
                f"r{index}b",
            )
            for index in range(8, 16)
        },
    }.items()
    for name in aliases
}
_CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
_INTEGER_ARGUMENTS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_STACK_ARGUMENT_SLOTS = 8
_STACK_TRACK_LIMIT = 4096
_CALL_STACK_PREFIX = "call-stack@"


@dataclass(frozen=True)
class AddressProvenanceReport:
    # addresses 保存普通访存 operand 的对象与仿射来源。
    addresses: dict[tuple[int, int], AbstractAddress]
    # call_arguments 保存 call 前六个 SysV 整数参数的地址来源；None 表示无法恢复。
    call_arguments: dict[int, tuple[AbstractAddress | None, ...]]
    # stack_call_arguments 保存 call 前由 [rsp+offset] 或 push 形成的栈参数。
    # 下标 0 对应最靠近返回地址的第一个栈参数；无法恢复的槽仍保留为 None。
    stack_call_arguments: dict[int, tuple[AbstractAddress | None, ...]]
    # published_globals 记录 pthread_create 前已稳定写入全局槽的指针。
    # worker 只能使用这些在所有 create 状态中都相同的值。
    published_globals: dict[str, AbstractAddress]
    # published_heap_fields 记录 create 前已经收敛的指针字段和带索引字段摘要。
    # 参数对象可能在 heap，也可能是 main 的栈对象；worker 入口必须拿到同一对象名，
    # 才能继续追踪字段里的真实对象。摘要只保留“所有写入值相同”的字段。
    published_heap_fields: dict[str, AbstractAddress]


def _frame_key(function_pc: int, displacement: int) -> str:
    return f"frame-value@0x{function_pc:x}{displacement:+d}"


def _call_stack_key(offset: int) -> str:
    """用当前 rsp 为零点保存可作为下一次 call 实参的栈槽。"""

    return f"{_CALL_STACK_PREFIX}{offset:+d}"


def _call_stack_offset(key: str) -> int | None:
    if not key.startswith(_CALL_STACK_PREFIX):
        return None
    try:
        return int(key[len(_CALL_STACK_PREFIX) :])
    except ValueError:
        return None


def _shift_call_stack(state: dict[str, _SymbolicValue], delta: int) -> None:
    """rsp 改变后平移栈槽；超出窗口的值不能再作为可靠实参。"""

    if not delta:
        return
    updates: dict[str, _SymbolicValue] = {}
    for key, value in tuple(state.items()):
        offset = _call_stack_offset(key)
        if offset is None:
            continue
        new_offset = offset + delta
        state.pop(key, None)
        if abs(new_offset) <= _STACK_TRACK_LIMIT:
            updates[_call_stack_key(new_offset)] = value
    state.update(updates)


def _clear_call_stack(state: dict[str, _SymbolicValue]) -> None:
    for key in tuple(state):
        if key.startswith(_CALL_STACK_PREFIX):
            state.pop(key, None)


def _global_key(pc: int) -> str:
    return f"global-pointer@0x{pc:x}"


@dataclass(frozen=True)
class _SymbolicValue:
    # base 标识直接 global 地址或保存动态指针的 global slot。
    base: str | None = None
    # indirect=True 表示 base 的内容才是实际对象地址，不能按 ELF 对象直接 NoAlias。
    indirect: bool = False
    # term 标识仍未求值的栈变量或寄存器来源。
    term: str | None = None
    # coefficient 保存 term 对最终字节地址的线性系数。
    coefficient: int = 0
    # offset 保存已经折叠的常量字节偏移。
    offset: int = 0
    # evidence_pcs 记录这条值链依赖的机器指令。
    evidence_pcs: tuple[int, ...] = ()
    # object_kind 区分 allocation site 与普通 global pointer slot。
    object_kind: AddressKind | None = None
    # candidate_bases 保存 heap-union 合流前仍能追溯的 allocation site。
    # 空集合表示没有这类精确候选，不能据此排除别名。
    candidate_bases: tuple[str, ...] = ()
    # owner_* 记录“这个 fresh 指针来自哪个带索引的外层对象字段”。
    # 只有外层字段地址和 fresh allocation 同时闭合时，后续线程分片证明
    # 才能把同一字段的不同元素视为不同对象；它不改变对象本身的基址。
    owner_base: str | None = None
    owner_term: str | None = None
    owner_coefficient: int | None = None
    # fresh_call_pc 只保留 allocation contract 给出的调用点，便于审计
    # owner 事实来自新分配，而不是从未知 heap load 猜出来的指针。
    fresh_call_pc: int | None = None


def _heap_slot_key(value: _SymbolicValue | None) -> str | None:
    """只为已知对象的固定指针字段生成键。"""

    if (
        value is None
        or value.base is None
        or value.term is not None
        or value.coefficient
        or value.indirect
        or value.object_kind not in {AddressKind.HEAP, AddressKind.STACK}
    ):
        return None
    return f"heap-field@{value.base}{value.offset:+d}"


def _heap_field_summary_key(value: _SymbolicValue | None) -> str | None:
    """按对象基址和字段偏移汇总带索引结构体中的指针字段。"""

    # 经过未建模的整数运算后，object_kind 可能丢失，但 base 仍是
    # 已确认的 heap allocation。保留这个键，才能在 worker 的归纳索引
    # 与 create 前的字段摘要不同名时重新接上同一个外层对象。
    if (
        value is None
        or value.base is None
        or value.indirect
        or (
            value.object_kind not in {AddressKind.HEAP, AddressKind.STACK}
            and not (
                value.object_kind is None
                and value.base.startswith("heap:")
            )
        )
        or not (
            value.base.startswith("heap:")
            or value.base.startswith("stack:")
        )
    ):
        return None
    # 忽略数组元素的索引，只保留字段偏移。只有所有可达写入都
    # 汇成同一个值时，后续 load 才能复用这个摘要；分歧会在 CFG meet
    # 时消失，未知 helper 也会主动清掉它。
    return f"heap-field-summary@{value.base}{value.offset:+d}"


def _indexed_field_summary_value(
    state: dict[str, _SymbolicValue], value: _SymbolicValue
) -> _SymbolicValue | None:
    """为带归纳下标的结构体字段选择唯一的 fresh 指针摘要。"""

    if (
        value.base is None
        or value.indirect
        or not value.base.startswith("heap:")
    ):
        return None
    prefix = f"heap-field-summary@{value.base}"
    candidates = []
    for key, item in state.items():
        if not key.startswith(prefix):
            continue
        suffix = key[len(prefix) :]
        if len(suffix) < 2 or suffix[0] not in "+-" or not suffix[1:].isdigit():
            continue
        candidates.append(item)
    if not candidates:
        return None
    first = candidates[0]
    if not all(_summary_values_compatible(first, item) for item in candidates[1:]):
        return None
    # 摘要只证明“这个数组元素保存的是同一 allocation”，不证明当前
    # 下标对应哪个字节；清掉保存值的常量偏移，避免把一个 row 的偏移
    # 错套到另一个 row。后续访问会回到同一 heap base 的保守分组。
    return replace(first, term=None, coefficient=0, offset=0)


def _root(register: str | None) -> str | None:
    if register is None:
        return None
    return _REGISTER_ROOTS.get(register.lower(), register.lower())


def _global_name(module: ModuleFingerprint, pc: int) -> str:
    return f"{Path(module.path).name}@0x{pc:x}"


def _with_evidence(value: _SymbolicValue, pc: int) -> _SymbolicValue:
    return replace(
        value,
        evidence_pcs=tuple(dict.fromkeys((*value.evidence_pcs, pc))),
    )


def _with_owner(
    value: _SymbolicValue | None,
    location: _SymbolicValue | None,
    pc: int,
) -> _SymbolicValue | None:
    """把 fresh 指针绑定到它写入的外层数组元素。"""

    if (
        value is None
        or value.object_kind != AddressKind.HEAP
        or value.fresh_call_pc is None
        or location is None
        or location.base is None
        or location.term is None
        or location.coefficient == 0
    ):
        return value
    return replace(
        value,
        owner_base=location.base,
        owner_term=location.term,
        owner_coefficient=location.coefficient,
        evidence_pcs=tuple(dict.fromkeys((*value.evidence_pcs, pc))),
    )


def _summary_values_compatible(
    first: _SymbolicValue, second: _SymbolicValue
) -> bool:
    """允许同一 indexed field 的不同元素共享一个值摘要。"""

    if first == second:
        return True
    # owner 是“当前数组元素”的附加证据，不属于字段摘要本身。
    # 初始化循环经过不同 CFG 路径时可能暂时缺少 owner；只要所有元素
    # 仍指向同一个 allocation site，就可以保留摘要，worker load 会用
    # 当前索引重新绑定 owner。行指针表的不同元素还可能带不同偏移，
    # 但它们仍属于同一个 data allocation；把偏移差异当成冲突会丢掉整个字段。
    return (
        first.base == second.base
        and first.indirect == second.indirect
        and first.object_kind == second.object_kind
        and first.candidate_bases == second.candidate_bases
        and first.fresh_call_pc == second.fresh_call_pc
        and first.base is not None
        and not first.indirect
    )


def _state_values_compatible(
    first: _SymbolicValue, second: _SymbolicValue
) -> bool:
    """判断 CFG 合流时两条值链是否只在证据指令上不同。"""

    # 同一个循环变量会沿回边经过不同次数，因此 evidence_pcs 不可能
    # 相同；其余字段相同就代表对象来源和算术表达式相同，可以合流。
    return replace(first, evidence_pcs=()) == replace(second, evidence_pcs=())


def _merge_state_values(
    first: _SymbolicValue, second: _SymbolicValue
) -> _SymbolicValue:
    return replace(
        first,
        evidence_pcs=tuple(
            dict.fromkeys((*first.evidence_pcs, *second.evidence_pcs))
        ),
    )


def _scaled(value: _SymbolicValue, scale: int, pc: int) -> _SymbolicValue | None:
    # 对象基址不能参与乘法；出现这种运算时继续猜测会制造错误别名证明。
    if value.base is not None:
        return _with_evidence(value, pc) if scale == 1 else None
    return _SymbolicValue(
        term=value.term,
        coefficient=value.coefficient * scale,
        offset=value.offset * scale,
        evidence_pcs=tuple(dict.fromkeys((*value.evidence_pcs, pc))),
        object_kind=value.object_kind,
        candidate_bases=value.candidate_bases,
    )


def _added(
    left: _SymbolicValue, right: _SymbolicValue, pc: int
) -> _SymbolicValue | None:
    if left.base is not None and right.base is not None:
        return None
    if left.term is not None and right.term is not None and left.term != right.term:
        # 一个 fresh heap 指针常常同时叠加“起始行”和“当前行”两个
        # frame 变量。当前表示只能容纳一项时，丢掉仿射量但保留
        # allocation base 仍然是安全的：它不会把不同对象判成 NoAlias，
        # 只会让该对象失去精确的分片范围，后续自然退回保守分组。
        if (
            left.base is not None
            and not left.indirect
            and left.object_kind in {AddressKind.HEAP, AddressKind.STACK}
        ):
            return _SymbolicValue(
                base=left.base,
                indirect=left.indirect,
                offset=left.offset + right.offset,
                evidence_pcs=tuple(
                    dict.fromkeys((*left.evidence_pcs, *right.evidence_pcs, pc))
                ),
                object_kind=left.object_kind,
                candidate_bases=left.candidate_bases,
                owner_base=left.owner_base,
                owner_term=left.owner_term,
                owner_coefficient=left.owner_coefficient,
                fresh_call_pc=left.fresh_call_pc,
            )
        if (
            right.base is not None
            and not right.indirect
            and right.object_kind in {AddressKind.HEAP, AddressKind.STACK}
        ):
            return _SymbolicValue(
                base=right.base,
                indirect=right.indirect,
                offset=left.offset + right.offset,
                evidence_pcs=tuple(
                    dict.fromkeys((*left.evidence_pcs, *right.evidence_pcs, pc))
                ),
                object_kind=right.object_kind,
                candidate_bases=right.candidate_bases,
                owner_base=right.owner_base,
                owner_term=right.owner_term,
                owner_coefficient=right.owner_coefficient,
                fresh_call_pc=right.fresh_call_pc,
            )
        return None
    coefficient = left.coefficient + right.coefficient
    term = left.term or right.term
    if coefficient == 0:
        # 两个相反的归纳量抵消后，结果已经是固定对象地址。
        # 保留 term=...、coefficient=0 会把它误分类为 affine，随后
        # 共享状态分析会无谓地要求线程边界证明。
        term = None
    return _SymbolicValue(
        base=left.base or right.base,
        indirect=left.indirect if left.base is not None else right.indirect,
        term=term,
        coefficient=coefficient,
        offset=left.offset + right.offset,
        evidence_pcs=tuple(
            dict.fromkeys((*left.evidence_pcs, *right.evidence_pcs, pc))
        ),
        object_kind=left.object_kind or right.object_kind,
        candidate_bases=left.candidate_bases or right.candidate_bases,
        owner_base=left.owner_base if left.base is not None else right.owner_base,
        owner_term=left.owner_term if left.base is not None else right.owner_term,
        owner_coefficient=(
            left.owner_coefficient
            if left.base is not None
            else right.owner_coefficient
        ),
        fresh_call_pc=(
            left.fresh_call_pc if left.base is not None else right.fresh_call_pc
        ),
    )


def _memory_value(
    module: ModuleFingerprint,
    fact: InstructionFact,
    operand: MemoryOperandFact,
    function_pc: int,
    state: dict[str, _SymbolicValue],
) -> _SymbolicValue | None:
    base = _root(operand.base)
    index = _root(operand.index)
    if base == "rip":
        target = fact.pc + len(fact.raw_bytes) // 2 + operand.displacement
        saved = state.get(_global_key(target))
        if saved is not None:
            return _with_evidence(saved, fact.pc)
        # 64 位 RIP-relative load 常用于读取 GOT/global pointer slot。
        # 这里只保留来源，不据此声明两个 slot 的内容 NoAlias。
        return _SymbolicValue(
            base=_global_name(module, target) if operand.size == 8 else None,
            indirect=operand.size == 8,
            term=None if operand.size == 8 else f"global-value@0x{target:x}",
            coefficient=0 if operand.size == 8 else 1,
            evidence_pcs=(fact.pc,),
        )
    if base in {"rsp", "rbp"} and index is None:
        if fact.mnemonic == "lea":
            # LEA 取的是槽位地址，不是槽位当前保存的值。
            # 同一个局部槽后来被复用时，必须继续保留新的 stack object，
            # 否则 outgoing argument 会错误继承旧的 loaded-pointer。
            return _SymbolicValue(
                base=f"stack:{_frame_key(function_pc, operand.displacement)}",
                indirect=False,
                evidence_pcs=(fact.pc,),
                object_kind=AddressKind.STACK,
            )
        # rsp 相对槽会随着 push/sub rsp 改变；用当前 rsp 为零点保存，
        # 才能把真正的第七个及之后 SysV 实参传入直接 callee。
        saved = (
            state.get(_call_stack_key(operand.displacement))
            if base == "rsp"
            else state.get(_frame_key(function_pc, operand.displacement))
        )
        if saved is None and base == "rsp":
            # 旧的 frame-value 事实仍可解释没有参与栈参数传播的测试/产物。
            saved = state.get(_frame_key(function_pc, operand.displacement))
        if saved is not None:
            return _with_evidence(saved, fact.pc)
        return _SymbolicValue(
            term=f"frame@0x{function_pc:x}{operand.displacement:+d}",
            coefficient=1,
            evidence_pcs=(fact.pc,),
        )
    value = state.get(base) if base is not None else _SymbolicValue()
    if value is None:
        return None
    if index is not None:
        index_value = state.get(index)
        if index_value is None:
            if (
                value.base is not None
                and not value.indirect
                and value.object_kind in {AddressKind.HEAP, AddressKind.STACK}
            ):
                # 乘法/比较未建模时可能只丢了下标寄存器；对象基址仍
                # 来自同一条直接 pointer chain。保留基址会扩大 alias
                # 集合，但不会把两个 allocation 错判成 NoAlias。
                return replace(
                    value,
                    term=None,
                    coefficient=0,
                    evidence_pcs=tuple(
                        dict.fromkeys((*value.evidence_pcs, fact.pc))
                    ),
                )
            return None
        scaled = _scaled(index_value, operand.scale, fact.pc)
        if scaled is None:
            return None
        value = _added(value, scaled, fact.pc)
        if value is None:
            return None
    return _added(
        value,
        _SymbolicValue(offset=operand.displacement),
        fact.pc,
    )


def _source_value(
    module: ModuleFingerprint,
    fact: InstructionFact,
    function_pc: int,
    state: dict[str, _SymbolicValue],
    operand_index: int,
) -> _SymbolicValue | None:
    register = next(
        (
            item
            for item in fact.register_operands
            if item.operand_index == operand_index
        ),
        None,
    )
    if register is not None:
        value = state.get(_root(register.register_name) or "")
        return _with_evidence(value, fact.pc) if value is not None else None
    memory = next(
        (
            item
            for item in (*fact.memory_operands, *fact.address_operands)
            if item.operand_index == operand_index
        ),
        None,
    )
    if memory is not None:
        value = _memory_value(module, fact, memory, function_pc, state)
        if value is not None and memory.size < 8 and value.base is not None:
            # 32 位 load 从已知对象取出的是标量，不是该对象的地址。
            # 若继续携带 base，tid 等整数运算会被误当成指针运算。
            return _SymbolicValue(
                term=f"loaded-value@0x{fact.pc:x}",
                coefficient=1,
                evidence_pcs=tuple(
                    dict.fromkeys((*value.evidence_pcs, fact.pc))
                ),
            )
        if (
            value is not None
            and value.base is not None
            and memory.size == 8
            and _root(memory.base) in {"rsp", "rbp"}
            and memory.index is None
        ):
            # 栈槽保存的是已经算好的指针时，load 只是把它取回寄存器。
            # 不能再把这个 frame slot 当成 heap 对象字段，否则下一次
            # [rax] 会变成 loaded-pointer，丢掉 worker 的分片来源。
            return _with_evidence(value, fact.pc)
        if value is not None and memory.size == 8 and value.base is not None:
            base = _root(memory.base)
            # RIP-relative load 先取的是全局槽中的指针值。不能把这个
            # 槽对应的数值地址再当成 heap struct 字段，否则读取
            # `swaptions` 全局指针时会误套用 outer object 的 offset 0
            # 摘要，把整个数组基址替换成第一行的 dvector。
            heap_slot = (
                _heap_slot_key(value)
                if base not in {"rsp", "rbp", "rip"}
                else None
            )
            # 栈槽和全局槽保存的是“已经算好的指针值”。即使这个值
            # 带有 heap base + 归纳量，也不能把它重新解释成当前对象的
            # indexed field；否则 dmatrix 返回 row-table 时会被内层
            # data allocation 的字段摘要覆盖，后续间接 load 就失去真实基址。
            summary_slot = (
                _heap_field_summary_key(value)
                if base not in {"rsp", "rbp", "rip"}
                else None
            )
            saved_heap_pointer = (
                state.get(heap_slot)
                if heap_slot is not None
                else state.get(summary_slot)
                if summary_slot is not None
                else None
            )
            if saved_heap_pointer is None and base not in {"rsp", "rbp", "rip"}:
                # 全局槽本身只提供一个已发布的指针值，不代表外层对象的
                # indexed field。对 RIP load 做这个反推会把全局数组基址
                # 错换成 offset 0 的第一行字段。
                saved_heap_pointer = _indexed_field_summary_value(state, value)
            if saved_heap_pointer is not None:
                # 这个字段在当前 CFG 路径上刚被明确写入指针；只复用
                # 这条写入事实，不把任意 heap load 当成可追踪指针。
                # 当前 load 的索引才是 worker 正在处理的外层元素；用它
                # 覆盖初始化线程留下的 owner term，避免把主线程 frame
                # 当成 worker 的分片变量。
                return _with_evidence(
                    _with_owner(saved_heap_pointer, value, fact.pc)
                    or saved_heap_pointer,
                    fact.pc,
                )
            saved_pointer = (
                base == "rip"
                and state.get(
                    _global_key(
                        fact.pc
                        + len(fact.raw_bytes) // 2
                        + memory.displacement
                    )
                )
                is not None
            ) or (
                base in {"rsp", "rbp"}
                and memory.index is None
                and (
                    state.get(_call_stack_key(memory.displacement))
                    if base == "rsp"
                    else state.get(_frame_key(function_pc, memory.displacement))
                )
                is not None
            )
            if not saved_pointer:
                # 容器字段的地址不是字段中保存的指针。保留 load PC 作为
                # 新的 MayAlias 来源，后续 ownership 证明可再绑定其写入点。
                return _SymbolicValue(
                    base=f"loaded-pointer@0x{fact.pc:x}",
                    indirect=True,
                    evidence_pcs=tuple(
                        dict.fromkeys((*value.evidence_pcs, fact.pc))
                    ),
                )
        return value
    immediate = next(
        (
            item
            for item in fact.immediate_operands
            if item.operand_index == operand_index
        ),
        None,
    )
    if immediate is not None:
        return _SymbolicValue(offset=immediate.value, evidence_pcs=(fact.pc,))
    return None


def _abstract_value(value: _SymbolicValue | None) -> AbstractAddress | None:
    if value is None or value.base is None:
        return None
    expression = value.base
    if value.term is not None:
        expression += f"+({value.term})*{value.coefficient}"
    if value.offset:
        expression += f"{value.offset:+d}"
    if value.object_kind in {AddressKind.HEAP, AddressKind.STACK} and value.term is None:
        kind = value.object_kind
    elif not value.indirect and value.term is None:
        kind = AddressKind.GLOBAL
    else:
        kind = AddressKind.AFFINE
    return AbstractAddress(
        kind=kind,
        base=value.base,
        offset=value.offset,
        expression=expression,
        index_coefficient=(value.coefficient if value.term is not None else None),
        provenance={
            "pointer_slot": value.base,
            "base_indirect": value.indirect,
            "index_term": value.term,
            "evidence_pcs": list(value.evidence_pcs),
            "scope": "function-cfg",
            "candidate_bases": list(value.candidate_bases),
            "owner_base": value.owner_base,
            "owner_index_term": value.owner_term,
            "owner_index_coefficient": value.owner_coefficient,
            "owner_scope": (
                "fresh-indexed-field"
                if value.owner_base is not None
                and value.owner_term is not None
                and value.fresh_call_pc is not None
                else None
            ),
            "fresh_call_pc": value.fresh_call_pc,
        },
    )


def _symbolic_value(address: AbstractAddress) -> _SymbolicValue | None:
    if address.base is None:
        return None
    return _SymbolicValue(
        base=address.base,
        indirect=address.kind == AddressKind.AFFINE,
        term=(
            str(address.provenance["index_term"])
            if address.provenance.get("index_term") is not None
            else None
        ),
        coefficient=address.index_coefficient or 0,
        offset=address.offset or 0,
        evidence_pcs=tuple(
            int(item) for item in address.provenance.get("evidence_pcs", ())
        ),
        object_kind=(
            address.kind
            if address.kind in {AddressKind.HEAP, AddressKind.STACK}
            else AddressKind.HEAP
            if address.base.startswith("heap:")
            else None
        ),
        candidate_bases=tuple(
            str(item)
            for item in address.provenance.get("candidate_bases", ())
            if isinstance(item, str)
        ),
        owner_base=(
            str(address.provenance["owner_base"])
            if address.provenance.get("owner_base") is not None
            else None
        ),
        owner_term=(
            str(address.provenance["owner_index_term"])
            if address.provenance.get("owner_index_term") is not None
            else None
        ),
        owner_coefficient=(
            int(address.provenance["owner_index_coefficient"])
            if address.provenance.get("owner_index_coefficient") is not None
            else None
        ),
        fresh_call_pc=(
            int(address.provenance["fresh_call_pc"])
            if address.provenance.get("fresh_call_pc") is not None
            else None
        ),
    )


def _transfer(
    module: ModuleFingerprint,
    fact: InstructionFact,
    function_pc: int,
    state: dict[str, _SymbolicValue],
    allocation_symbol: str | None = None,
    preserve_heap_fields: bool = False,
    immutable_heap_field_keys: set[str] | frozenset[str] = frozenset(),
    preserve_heap_only: bool = False,
) -> None:
    # push/pop 会改变 rsp 的零点。先移动已知槽，再写入新栈顶，
    # 否则第二个以上的 SysV 实参会被错配到前一个参数。
    if fact.mnemonic in {"push", "pushf", "pushfq"}:
        stored = (
            _source_value(module, fact, function_pc, state, 0)
            if fact.mnemonic == "push"
            else None
        )
        _shift_call_stack(state, 8)
        state.pop(_call_stack_key(0), None)
        if stored is not None:
            state[_call_stack_key(0)] = stored
        return
    if fact.mnemonic in {"pop", "popf", "popfq"}:
        popped = state.get(_call_stack_key(0))
        _shift_call_stack(state, -8)
        if fact.mnemonic == "pop":
            destination = next(
                (
                    _root(item.register_name)
                    for item in fact.register_operands
                    if item.operand_index == 0
                    and item.access
                    in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
                ),
                None,
            )
            if destination is not None:
                state.pop(destination, None)
                if popped is not None:
                    state[destination] = _with_evidence(popped, fact.pc)
        return

    rsp_written = any(
        _root(item.register_name) == "rsp"
        and item.access in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
        for item in fact.register_operands
    )
    rsp_immediate = next(
        (
            item.value
            for item in fact.immediate_operands
            if item.operand_index == 1
        ),
        None,
    )
    if rsp_written and fact.mnemonic == "sub" and rsp_immediate is not None:
        if rsp_immediate > 0:
            _shift_call_stack(state, rsp_immediate)
        else:
            _clear_call_stack(state)
    elif rsp_written and fact.mnemonic == "add" and rsp_immediate is not None:
        if rsp_immediate > 0:
            _shift_call_stack(state, -rsp_immediate)
        else:
            _clear_call_stack(state)
    elif rsp_written and fact.mnemonic not in {"sub", "add"}:
        # mov/and/leave 等未被这里建模的 rsp 改写会改变零点，
        # 继续沿用旧槽会把普通局部变量误认成 outgoing argument。
        _clear_call_stack(state)

    if fact.control_flow is not None and fact.control_flow.value.endswith("call"):
        for register in _CALLER_SAVED:
            state.pop(register, None)
        # 任意调用都可能改写 heap；不把调用前的字段内容带过边界，
        # 否则未知 helper 可能悄悄替换指针而仍被当成 fresh 对象。
        if not (preserve_heap_fields or allocation_symbol is not None):
            for key in tuple(state):
                if (
                    key.startswith(("heap-field@", "heap-field-summary@"))
                    and key not in immutable_heap_field_keys
                ):
                    if preserve_heap_only and key.startswith(
                        ("heap-field@heap:", "heap-field-summary@heap:")
                    ):
                        continue
                    state.pop(key, None)
        if allocation_symbol is not None:
            state["rax"] = _SymbolicValue(
                base=f"heap:{allocation_symbol}@0x{fact.pc:x}",
                indirect=False,
                evidence_pcs=(fact.pc,),
                object_kind=AddressKind.HEAP,
                fresh_call_pc=fact.pc,
            )
        return
    writes = {
        _root(item.register_name)
        for item in fact.register_operands
        if item.access in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
    }
    writes.discard(None)
    frame_writes = [
        item
        for item in fact.memory_operands
        if item.access in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
        and _root(item.base) in {"rsp", "rbp"}
        and item.index is None
    ]
    for item in frame_writes:
        slot_key = (
            _call_stack_key(item.displacement)
            if _root(item.base) == "rsp"
            else _frame_key(function_pc, item.displacement)
        )
        # 未建模的算术写会改变 spill/归纳变量。继续沿用旧值会把循环中的
        # 当前 i 误认成初始化 start，因此任何非简单 mov 都先杀死该槽。
        if fact.mnemonic in {"add", "sub"} and item.operand_index == 0:
            current = state.get(slot_key)
            right = _source_value(module, fact, function_pc, state, 1)
            if current is not None and right is not None:
                # dmatrix 一类 helper 会先保存 malloc 返回值，再用 add
                # 把它移到第一行。循环下标也会直接在 frame slot 上递增；
                # 两者都只是把一个已知常量加到同一条值链，保留它不会
                # 引入新的对象来源。若右值仍带对象基址，才必须放弃。
                if fact.mnemonic == "sub":
                    right = _scaled(right, -1, fact.pc)
                direct_frame_term = (
                    f"frame@0x{function_pc:x}{item.displacement:+d}"
                )
                if (
                    right is not None
                    and right.base is None
                    and (
                        current.base is not None
                        or current.term is None
                        or current.term == direct_frame_term
                    )
                ):
                    updated = _added(current, right, fact.pc)
                    if updated is not None:
                        state[slot_key] = updated
                        continue
        if fact.mnemonic not in {"mov", "movabs"} or item.operand_index != 0:
            state.pop(slot_key, None)
    destination = next(
        (
            _root(item.register_name)
            for item in fact.register_operands
            if item.operand_index == 0
            and item.access in {MemoryAccessKind.WRITE, MemoryAccessKind.READ_WRITE}
        ),
        None,
    )
    value: _SymbolicValue | None = None
    if destination is not None and fact.mnemonic in {
        "mov",
        "movabs",
        "movsx",
        "movsxd",
        "movzx",
    }:
        value = _source_value(module, fact, function_pc, state, 1)
    elif destination is not None and fact.mnemonic == "lea" and fact.address_operands:
        value = _memory_value(
            module, fact, fact.address_operands[0], function_pc, state
        )
        if value is not None and _root(fact.address_operands[0].base) == "rip":
            value = _SymbolicValue(
                base=value.base,
                indirect=False,
                offset=value.offset,
                evidence_pcs=value.evidence_pcs,
                owner_base=value.owner_base,
                owner_term=value.owner_term,
                owner_coefficient=value.owner_coefficient,
                fresh_call_pc=value.fresh_call_pc,
                candidate_bases=value.candidate_bases,
            )
    elif destination is not None and fact.mnemonic in {"add", "sub"}:
        left = state.get(destination)
        right = _source_value(module, fact, function_pc, state, 1)
        if fact.mnemonic == "sub" and right is not None:
            right = _scaled(right, -1, fact.pc)
        if left is not None and right is not None:
            value = _added(left, right, fact.pc)
        elif (
            left is None
            and right is not None
            and right.base is not None
            and not right.indirect
            and right.object_kind in {AddressKind.HEAP, AddressKind.STACK}
        ):
            # 未建模的整数下标与已知对象相加时，右值仍给出了唯一
            # allocation base；只丢掉范围，不丢掉对象身份。
            value = replace(right, term=None, coefficient=0)
        elif (
            left is not None
            and right is None
            and left.base is not None
            and not left.indirect
            and left.object_kind in {AddressKind.HEAP, AddressKind.STACK}
        ):
            value = replace(left, term=None, coefficient=0)
    elif destination is not None and fact.mnemonic in {"shl", "sal"}:
        left = state.get(destination)
        immediate = next(iter(fact.immediate_operands), None)
        if left is not None and immediate is not None:
            value = _scaled(left, 1 << immediate.value, fact.pc)
    elif destination is not None and fact.mnemonic == "neg":
        # 编译器常用 neg 把数组下界变成指针回退量。只对没有对象基址
        # 的标量传播负号；对象指针不会被错误地反向解释。
        left = state.get(destination)
        if left is not None:
            value = _scaled(left, -1, fact.pc)
    elif destination is not None and fact.mnemonic == "and":
        left = state.get(destination)
        immediate = next(iter(fact.immediate_operands), None)
        if (
            left is not None
            and left.object_kind == AddressKind.HEAP
            and immediate is not None
            and immediate.value < 0
        ):
            # 对齐只会在同一 malloc 对象内移动基址。精确 offset 丢失，
            # 但 allocation site 仍可用于排除与另一 malloc 返回对象别名。
            value = _SymbolicValue(
                base=left.base,
                indirect=left.indirect,
                term=left.term,
                coefficient=left.coefficient,
                evidence_pcs=tuple(
                    dict.fromkeys((*left.evidence_pcs, fact.pc))
                ),
                object_kind=left.object_kind,
                candidate_bases=left.candidate_bases,
                owner_base=left.owner_base,
                owner_term=left.owner_term,
                owner_coefficient=left.owner_coefficient,
                fresh_call_pc=left.fresh_call_pc,
            )
    elif destination is not None and fact.mnemonic == "imul":
        source = _source_value(module, fact, function_pc, state, 1)
        immediate = next(
            (item for item in fact.immediate_operands if item.operand_index == 2),
            None,
        )
        if source is not None and immediate is not None:
            value = _scaled(source, immediate.value, fact.pc)

    for register in writes:
        state.pop(register, None)
    if destination is not None and value is not None:
        state[destination] = _with_evidence(value, fact.pc)

    if fact.mnemonic in {"mov", "movabs"}:
        heap_destination = next(
            (
                item
                for item in fact.memory_operands
                if item.operand_index == 0
                and _root(item.base) not in {"rip", "rsp", "rbp"}
            ),
            None,
        )
        if heap_destination is not None and heap_destination.size == 8:
            location = _memory_value(
                module, fact, heap_destination, function_pc, state
            )
            key = _heap_slot_key(location)
            summary_key = _heap_field_summary_key(location)
            if key is not None:
                stored = _source_value(module, fact, function_pc, state, 1)
                stored = _with_owner(stored, location, fact.pc)
                if stored is None:
                    state.pop(key, None)
                else:
                    state[key] = stored
            if summary_key is not None:
                stored = _source_value(module, fact, function_pc, state, 1)
                stored = _with_owner(stored, location, fact.pc)
                if stored is None:
                    state.pop(summary_key, None)
                else:
                    state[summary_key] = stored
        memory_destination = next(
            (
                item
                for item in fact.memory_operands
                if item.operand_index == 0
                and _root(item.base) in {"rsp", "rbp"}
                and item.index is None
            ),
            None,
        )
        if memory_destination is not None:
            key = (
                _call_stack_key(memory_destination.displacement)
                if _root(memory_destination.base) == "rsp"
                else _frame_key(function_pc, memory_destination.displacement)
            )
            stored = _source_value(module, fact, function_pc, state, 1)
            if stored is None:
                state.pop(key, None)
            else:
                state[key] = stored
        global_destination = next(
            (
                item
                for item in fact.memory_operands
                if item.operand_index == 0 and _root(item.base) == "rip"
            ),
            None,
        )
        if global_destination is not None:
            target = fact.pc + len(fact.raw_bytes) // 2 + global_destination.displacement
            stored = _source_value(module, fact, function_pc, state, 1)
            key = _global_key(target)
            if stored is None:
                state.pop(key, None)
            else:
                if stored.object_kind == AddressKind.HEAP:
                    # global 槽保存的是已经算好的指针。它依赖 numOptions 的旧
                    # 算式不应在 worker 中再次当作循环下标；保留 allocation
                    # site 即可排除另一 malloc 对象，槽内偏移仍按 Unknown 合并。
                    stored = _SymbolicValue(
                        base=stored.base,
                        indirect=False,
                        evidence_pcs=stored.evidence_pcs,
                        object_kind=stored.object_kind,
                        candidate_bases=stored.candidate_bases,
                        owner_base=stored.owner_base,
                        owner_term=stored.owner_term,
                        owner_coefficient=stored.owner_coefficient,
                        fresh_call_pc=stored.fresh_call_pc,
                    )
                state[key] = stored


def recover_address_provenance(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    facts: tuple[InstructionFact, ...],
    allocation_calls: dict[int, str] | None = None,
    function_entry_arguments: dict[int, dict[str, AbstractAddress]] | None = None,
    seeded_function_pcs: set[int] | None = None,
    reachable_function_pcs: set[int] | None = None,
    seeded_globals: dict[str, AbstractAddress] | None = None,
    seeded_heap_fields: dict[str, AbstractAddress] | None = None,
    preserve_heap_field_call_pcs: set[int] | None = None,
    immutable_heap_field_keys: set[str] | frozenset[str] = frozenset(),
    function_entry_stack_arguments: dict[int, dict[int, AbstractAddress]] | None = None,
    preserve_heap_only_call_pcs: set[int] | None = None,
) -> AddressProvenanceReport:
    """在函数 CFG 上传播唯一地址值；路径合流不一致时退回 Unknown。"""

    allocation_calls = allocation_calls or {}
    function_entry_arguments = function_entry_arguments or {}
    function_entry_stack_arguments = function_entry_stack_arguments or {}
    seeded_function_pcs = seeded_function_pcs or set()
    seeded_globals = seeded_globals or {}
    seeded_heap_fields = seeded_heap_fields or {}
    preserve_heap_field_call_pcs = preserve_heap_field_call_pcs or set()
    preserve_heap_only_call_pcs = preserve_heap_only_call_pcs or set()
    facts_by_pc = {fact.pc: fact for fact in facts}
    blocks = {block.location.pc: block for block in control_flow.basic_blocks}
    functions = {function.location.pc: function for function in control_flow.functions}
    nonreturning_targets = {
        function.location.pc
        for function in control_flow.functions
        if function.returning is False
    }
    nonreturning_call_pcs = {
        call.location.pc
        for call in control_flow.call_sites
        if any(
            target.module_sha256 == module.sha256
            and target.pc in nonreturning_targets
            for target in call.targets.known_targets
        )
    }
    # main 和 worker 可以调用同一个 helper，但传入完全不同的对象。
    # 按 role 闭包过滤 call site，避免另一个线程角色的参数污染当前入口 meet。
    reachable_functions = (
        set(functions)
        if reachable_function_pcs is None
        else set(reachable_function_pcs) & functions.keys()
    )
    entry_values: dict[int, dict[str, _SymbolicValue]] = {
        function_pc: {
            register: value
            for register, address in registers.items()
            if (value := _symbolic_value(address)) is not None
        }
        for function_pc, registers in function_entry_arguments.items()
    }
    entry_stack_values: dict[int, dict[int, _SymbolicValue]] = {
        function_pc: {
            int(offset): value
            for offset, address in arguments.items()
            if (value := _symbolic_value(address)) is not None
        }
        for function_pc, arguments in function_entry_stack_arguments.items()
    }
    entry_heap_fields: dict[int, dict[str, _SymbolicValue]] = {}
    seeded_heap_field_values = {
        key: value
        for key, address in seeded_heap_fields.items()
        if (value := _symbolic_value(address)) is not None
    }
    seeded_global_values = {
        key: value
        for key, address in seeded_globals.items()
        if (value := _symbolic_value(address)) is not None
    }
    function_instruction_pcs = {
        function_pc: {
            pc
            for block_pc in function.block_pcs
            if block_pc in blocks
            for pc in blocks[block_pc].instruction_pcs
        }
        for function_pc, function in functions.items()
    }

    # 先记录同一 ELF 内部 call 的目标。后面会为“构造器给调用者对象
    # 写入 fresh 指针字段”的函数建立摘要；调用者只有在目标和实参都
    # 可证明时才会接收这条摘要。
    internal_call_targets = {
        call.location.pc: call.targets.known_targets[0].pc
        for call in control_flow.call_sites
        if call.containing_function_pc in reachable_functions
        if len(call.targets.known_targets) == 1
        and call.targets.known_targets[0].module_sha256 == module.sha256
        and call.targets.known_targets[0].pc in reachable_functions
    }
    function_field_summaries: dict[int, dict[str, _SymbolicValue]] = {}

    # fresh-return helper 可能在返回前初始化一组指针字段。把摘要按调用点
    # 重新命名后，caller 才能继续解析下一层的 [object + index]；摘要只在
    # 返回基址唯一且函数没有发布对象时使用，分支不确定时仍回退 Unknown。
    allocation_field_summaries: dict[
        int, dict[str, _SymbolicValue]
    ] = {}

    def apply_allocation_field_summary(
        state: dict[str, _SymbolicValue], call_pc: int
    ) -> None:
        summary = allocation_field_summaries.get(call_pc)
        if summary:
            state.update(summary)

    def restore_private_allocation_summaries(
        state: dict[str, _SymbolicValue], fact: InstructionFact
    ) -> None:
        """恢复没有传给 opaque call 的 fresh 对象字段摘要。

        未知调用会清掉所有 heap 字段事实，但只要 fresh 对象仍只保存在
        当前函数的栈槽里，callee 就拿不到它。保留这种摘要可以跨过
        `sqrt`、随机数 helper 等无关调用；对象出现在实参或全局槽时则
        不恢复，避免把可能已被 callee 改写的字段当成旧值。
        """

        if not (
            fact.control_flow is not None
            and fact.control_flow.value.endswith("call")
            and allocation_field_summaries
        ):
            return
        summaries_by_base: dict[str, dict[str, _SymbolicValue]] = {}
        for summary in allocation_field_summaries.values():
            for key, value in summary.items():
                for prefix in ("heap-field@", "heap-field-summary@"):
                    if key.startswith(prefix):
                        base = key[len(prefix) :].split("+", 1)[0]
                        summaries_by_base.setdefault(base, {})[key] = value
                        break
        if not summaries_by_base:
            return
        passed_bases: set[str] = set()
        for register in _INTEGER_ARGUMENTS:
            value = state.get(register)
            if value is None:
                continue
            if value.base is not None:
                passed_bases.add(value.base)
            passed_bases.update(value.candidate_bases)
        global_bases = {
            value.base
            for key, value in state.items()
            if key.startswith("global-pointer@") and value.base is not None
        }
        for base, summary in summaries_by_base.items():
            if base not in passed_bases and base not in global_bases:
                state.update(summary)

    def apply_function_field_summary(
        state: dict[str, _SymbolicValue],
        call_pc: int,
        argument_state: dict[str, _SymbolicValue] | None = None,
    ) -> None:
        """把已验证的内部构造器字段写入映射回 caller 对象。"""

        target_pc = internal_call_targets.get(call_pc)
        summary = function_field_summaries.get(target_pc)
        if target_pc is None or not summary:
            return
        entry_registers = entry_values.get(target_pc, {})
        actual_registers = argument_state or state
        for key, value in summary.items():
            for register in _INTEGER_ARGUMENTS:
                entry = entry_registers.get(register)
                actual = actual_registers.get(register)
                if (
                    entry is None
                    or actual is None
                    or entry.base is None
                    or actual.base is None
                    or entry.indirect
                    or actual.indirect
                    or entry.object_kind not in {AddressKind.HEAP, AddressKind.STACK}
                    or actual.object_kind not in {AddressKind.HEAP, AddressKind.STACK}
                ):
                    continue
                for prefix in ("heap-field@", "heap-field-summary@"):
                    source_prefix = f"{prefix}{entry.base}"
                    if not key.startswith(source_prefix):
                        continue
                    # 字段摘要只替换 receiver 的对象基址。当前 canneal
                    # 构造器的 receiver 偏移为零；如果 caller 还有额外
                    # 偏移，保留原后缀会扩大候选范围，但不会伪造 NoAlias。
                    mapped_key = (
                        f"{prefix}{actual.base}{key[len(source_prefix):]}"
                    )
                    mapped_value = value
                    if (
                        value.object_kind == AddressKind.HEAP
                        and value.base is not None
                        and value.fresh_call_pc is not None
                    ):
                        # 同一个构造器 call site 可以被不同 worker 执行多次。
                        # 用 caller call site 区分 fresh 对象，不能把不同
                        # 线程的 new 结果错误合并成同一个 allocation。
                        mapped_value = replace(
                            value,
                            base=f"heap:ctor@0x{call_pc:x}",
                            fresh_call_pc=call_pc,
                            candidate_bases=(value.base,),
                        )
                    state[mapped_key] = mapped_value
                    break
                else:
                    continue
                break

    create_call_pcs = {
        call.location.pc
        for call in control_flow.call_sites
        if call.target_symbol == "pthread_create"
    }

    def flow(
        function_pc: int,
        seeded_globals: dict[str, _SymbolicValue] | None = None,
        seeded_heap_fields: dict[str, _SymbolicValue] | None = None,
    ) -> tuple[
        dict[int, dict[str, _SymbolicValue]],
        bool,
        dict[str, _SymbolicValue],
        dict[str, _SymbolicValue],
        tuple[str, ...],
    ]:
        function = functions[function_pc]
        local_allocation_bases = {
            f"heap:{symbol}@0x{call_pc:x}"
            for call_pc, symbol in allocation_calls.items()
            if call_pc in function_instruction_pcs.get(function_pc, set())
        }
        initial_state = {
            **(seeded_globals or {}),
            **(seeded_heap_fields or {}),
            **entry_values.get(function_pc, {}),
            **entry_heap_fields.get(function_pc, {}),
        }
        for offset, value in entry_stack_values.get(function_pc, {}).items():
            # call 前的 [rsp+offset] 在 callee 入口多了返回地址，
            # 而建立 rbp 后同一参数位于 [rbp+16+offset]。
            initial_state[_call_stack_key(8 + offset)] = value
            initial_state[_frame_key(function_pc, 16 + offset)] = value
        incoming: dict[int, dict[str, _SymbolicValue]] = {
            function_pc: initial_state
        }
        edge_states: dict[tuple[int, int], dict[str, _SymbolicValue]] = {}
        observed_heap_field_summaries: dict[str, _SymbolicValue] = {}
        conflicting_heap_field_summaries: set[str] = set()
        pending = [function_pc]
        while pending:
            block_pc = pending.pop()
            block = blocks.get(block_pc)
            if block is None:
                continue
            state = dict(incoming[block_pc])
            for pc in block.instruction_pcs:
                fact = facts_by_pc.get(pc)
                if fact is None:
                    state.clear()
                    continue
                # 记录每个可达 store 产生的摘要。不同路径写入不同对象时，
                # 该键会被标成冲突，不能再拿去解释 worker 的间接 load。
                for key, value in state.items():
                    if key.startswith("heap-field-summary@"):
                        previous = observed_heap_field_summaries.get(key)
                        if previous is not None and not _summary_values_compatible(
                            previous, value
                        ):
                            conflicting_heap_field_summaries.add(key)
                        elif key not in conflicting_heap_field_summaries:
                            observed_heap_field_summaries[key] = value
                argument_state = {
                    register: state[register]
                    for register in _INTEGER_ARGUMENTS
                    if register in state
                } if pc in internal_call_targets else None
                _transfer(
                    module,
                    fact,
                    function_pc,
                    state,
                    allocation_calls.get(pc),
                    pc in preserve_heap_field_call_pcs,
                    immutable_heap_field_keys,
                    pc in preserve_heap_only_call_pcs,
                )
                apply_allocation_field_summary(state, pc)
                apply_function_field_summary(state, pc, argument_state)
                restore_private_allocation_summaries(state, fact)
                for key, value in state.items():
                    if key.startswith("heap-field-summary@"):
                        previous = observed_heap_field_summaries.get(key)
                        if previous is not None and not _summary_values_compatible(
                            previous, value
                        ):
                            conflicting_heap_field_summaries.add(key)
                        elif key not in conflicting_heap_field_summaries:
                            observed_heap_field_summaries[key] = value
            # 已由 CFG 标成不返回的 call 没有成功路径；继续把它的
            # 后继状态带入 join 会让 error 分支覆盖正常返回分支，
            # 误杀刚建立的 heap-slot 指针事实。
            if any(pc in nonreturning_call_pcs for pc in block.instruction_pcs):
                continue
            for successor in block.successor_pcs:
                if successor not in function.block_pcs:
                    continue
                edge_states[(block_pc, successor)] = dict(state)
                predecessor_states = [
                    edge_state
                    for (source, target), edge_state in edge_states.items()
                    if target == successor
                ]
                joined = dict(predecessor_states[0])
                for predecessor_state in predecessor_states[1:]:
                    merged: dict[str, _SymbolicValue] = {}
                    for key, value in joined.items():
                        other = predecessor_state.get(key)
                        if other is not None and _state_values_compatible(
                            value, other
                        ):
                            merged[key] = _merge_state_values(value, other)
                    joined = merged
                previous = incoming.get(successor)
                if previous != joined:
                    incoming[successor] = joined
                    pending.append(successor)

        returns: list[_SymbolicValue | None] = []
        published = False
        create_globals: list[dict[str, _SymbolicValue]] = []
        create_heap_fields: list[dict[str, _SymbolicValue]] = []
        for block_pc, entry_state in incoming.items():
            state = dict(entry_state)
            for pc in blocks[block_pc].instruction_pcs:
                fact = facts_by_pc.get(pc)
                if fact is None:
                    state.clear()
                    continue
                if fact.control_flow is not None and fact.control_flow.value.endswith("call"):
                    if fact.pc in create_call_pcs:
                        create_globals.append(
                            {
                                key: value
                                for key, value in state.items()
                                if key.startswith("global-pointer@")
                            }
                        )
                        create_heap_fields.append(
                            {
                                key: value
                                for key, value in state.items()
                                if key.startswith(
                                    ("heap-field@", "heap-field-summary@")
                                )
                            }
                        )
                    if allocation_calls.get(fact.pc) is None and any(
                        state.get(register) is not None
                        and state[register].object_kind == AddressKind.HEAP
                        for register in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
                    ):
                        published = True
                if fact.mnemonic in {"mov", "movabs"}:
                    destination = next(
                        (item for item in fact.memory_operands if item.operand_index == 0),
                        None,
                    )
                    source = _source_value(module, fact, function_pc, state, 1)
                    if (
                        destination is not None
                        and _root(destination.base) not in {"rsp", "rbp"}
                        and source is not None
                        and source.object_kind == AddressKind.HEAP
                    ):
                        destination_value = _memory_value(
                            module,
                            fact,
                            destination,
                            function_pc,
                            state,
                        )
                        contained_in_fresh_graph = (
                            destination_value is not None
                            and destination_value.base
                            in local_allocation_bases
                            and source.base in local_allocation_bases
                        )
                        if not contained_in_fresh_graph:
                            published = True
                if fact.mnemonic == "ret":
                    returns.append(state.get("rax"))
                argument_state = {
                    register: state[register]
                    for register in _INTEGER_ARGUMENTS
                    if register in state
                } if pc in internal_call_targets else None
                _transfer(
                    module,
                    fact,
                    function_pc,
                    state,
                    allocation_calls.get(pc),
                    pc in preserve_heap_field_call_pcs,
                    immutable_heap_field_keys,
                    pc in preserve_heap_only_call_pcs,
                )
                apply_allocation_field_summary(state, pc)
                apply_function_field_summary(state, pc, argument_state)
                restore_private_allocation_summaries(state, fact)
        fresh_return = bool(returns) and not published and all(
            value is not None
            and value.object_kind == AddressKind.HEAP
            and value.base in local_allocation_bases
            for value in returns
        )
        common_globals = (
            {
                key: value
                for key, value in create_globals[0].items()
                if all(item.get(key) == value for item in create_globals[1:])
            }
            if create_globals
            else {}
        )
        common_heap_fields = (
            {
                key: value
                for key, value in create_heap_fields[0].items()
                if all(
                    item.get(key) is not None
                    and _summary_values_compatible(value, item[key])
                    for item in create_heap_fields[1:]
                )
            }
            if create_heap_fields
            else {}
        )
        for key in conflicting_heap_field_summaries:
            observed_heap_field_summaries.pop(key, None)
        # create 边界上的快照优先；其余摘要来自同一函数中已收敛的
        # 初始化循环。它们仍受上面的冲突检查和未知调用清除约束。
        common_heap_fields.update(observed_heap_field_summaries)
        return_bases = tuple(
            sorted(
                {
                    value.base
                    for value in returns
                    if value is not None and value.base is not None
                }
            )
        )
        return incoming, fresh_return, common_globals, common_heap_fields, return_bases

    internal_calls = {
        call.location.pc: call.targets.known_targets[0].pc
        for call in control_flow.call_sites
        if call.containing_function_pc in reachable_functions
        if len(call.targets.known_targets) == 1
        and call.targets.known_targets[0].module_sha256 == module.sha256
        and call.targets.known_targets[0].pc in reachable_functions
    }
    changed = True
    while changed:
        changed = False
        fresh_functions = {
            function_pc
            for function_pc in reachable_functions
            if function_pc in blocks and flow(function_pc)[1]
        }
        for call_pc, target_pc in internal_calls.items():
            if target_pc in fresh_functions and call_pc not in allocation_calls:
                allocation_calls[call_pc] = f"function@0x{target_pc:x}"
                changed = True

    # 现在 allocation_calls 已包含所有能证明返回 fresh 对象的内部 helper。
    # 重新计算它们的返回字段摘要，并把源 malloc 基址改成 caller 看到的
    # synthetic 基址；没有唯一返回基址的函数不提供摘要，避免把分支值
    # 错套到下一次调用。
    for _ in range(max(1, len(internal_calls) + 1)):
        summaries_changed = False
        for call_pc, target_pc in internal_calls.items():
            if allocation_calls.get(call_pc) != f"function@0x{target_pc:x}":
                continue
            _, fresh_return, _, heap_fields, return_bases = flow(target_pc)
            if not fresh_return or len(return_bases) != 1:
                continue
            source_base = return_bases[0]
            target_base = f"heap:function@0x{target_pc:x}@0x{call_pc:x}"
            remapped: dict[str, _SymbolicValue] = {}
            for key, value in heap_fields.items():
                for prefix in ("heap-field@", "heap-field-summary@"):
                    source_prefix = f"{prefix}{source_base}"
                    if key.startswith(source_prefix):
                        remapped[
                            f"{prefix}{target_base}{key[len(source_prefix):]}"
                        ] = value
                        break
            if allocation_field_summaries.get(call_pc) != remapped:
                allocation_field_summaries[call_pc] = remapped
                summaries_changed = True
        if not summaries_changed:
            break

    published_globals: dict[str, _SymbolicValue] = {}
    published_heap_fields: dict[str, _SymbolicValue] = {}
    for function_pc in {
        call.containing_function_pc
        for call in control_flow.call_sites
        if call.location.pc in create_call_pcs
    }:
        if function_pc in blocks:
            _, _, globals_at_create, heap_fields_at_create, _ = flow(function_pc)
            published_globals.update(globals_at_create)
            published_heap_fields.update(heap_fields_at_create)
    seeded_heap_field_values = {
        **seeded_heap_field_values,
        **published_heap_fields,
    }

    internal_call_sites = {
        call.location.pc: call
        for call in control_flow.call_sites
        if call.location.pc in internal_calls
    }
    calls_by_target: dict[int, set[int]] = {}
    for call_pc, target_pc in internal_calls.items():
        calls_by_target.setdefault(target_pc, set()).add(call_pc)

    def merge_stack_argument_values(
        values: list[_SymbolicValue | None], target_pc: int, offset: int
    ) -> _SymbolicValue | None:
        """合并可证明来自同一对象的栈实参；未知或混合类型直接放弃。"""

        if not values or any(value is None for value in values):
            return None
        concrete = [value for value in values if value is not None]
        first = concrete[0]
        if all(value == first for value in concrete[1:]):
            return first

        # 同一个内部 helper 可能同时被主线程和 worker 调用。
        # 如果所有 call site 都把同一个 caller 栈对象传进来，只是
        # 经过不同的常量偏移，丢掉这条事实会让 helper 的 this 指针
        # 重新变成 affine/unknown。这里把不同偏移折叠到对象基址，
        # 只扩大可能访问的范围，不把两个不同栈帧误判成同一对象。
        if all(
            value.object_kind == AddressKind.STACK
            and not value.indirect
            and value.base is not None
            and value.term is None
            and value.coefficient == 0
            and value.base == first.base
            for value in concrete
        ):
            return _SymbolicValue(
                base=first.base,
                indirect=False,
                offset=(
                    first.offset
                    if all(value.offset == first.offset for value in concrete)
                    else 0
                ),
                evidence_pcs=tuple(
                    dict.fromkeys(
                        pc for value in concrete for pc in value.evidence_pcs
                    )
                ),
                object_kind=AddressKind.STACK,
            )

        if any(
            value.object_kind != AddressKind.HEAP
            or value.indirect
            or value.base is None
            for value in concrete
        ):
            return None
        candidates = {
            candidate
            for value in concrete
            for candidate in (
                value.candidate_bases
                or ((value.base,) if value.base else ())
            )
            if candidate is not None and not candidate.startswith("heap-union:")
        }
        if not candidates:
            return None
        return _SymbolicValue(
            base=f"heap-union:stack@0x{target_pc:x}+{offset}",
            indirect=False,
            evidence_pcs=tuple(
                dict.fromkeys(
                    pc for value in concrete for pc in value.evidence_pcs
                )
            ),
            object_kind=AddressKind.HEAP,
            candidate_bases=tuple(sorted(candidates)),
            fresh_call_pc=(
                first.fresh_call_pc
                if all(value.fresh_call_pc == first.fresh_call_pc for value in concrete)
                else None
            ),
        )

    # worker 入口的指针已由 pthread_create 绑定，但它还会继续传给
    # 多层 helper。只有目标函数的每个已恢复 call site 都给出同一条
    # 地址来源时才写入口，路径分歧会自动退回 Unknown。
    propagated = True
    while propagated:
        propagated = False
        observed: dict[int, dict[str, _SymbolicValue]] = {}
        observed_fields: dict[int, dict[str, _SymbolicValue]] = {}
        observed_stack: dict[
            int, dict[int, _SymbolicValue | None]
        ] = {}
        for function_pc in reachable_functions:
            if function_pc not in blocks:
                continue
            incoming, _, _, _, _ = flow(
                function_pc,
                (
                    {
                        **seeded_global_values,
                        **published_globals,
                    }
                    if function_pc in seeded_function_pcs
                    else None
                ),
                seeded_heap_field_values
                if function_pc in seeded_function_pcs
                else None,
            )
            for block_pc, entry_state in incoming.items():
                state = dict(entry_state)
                for pc in blocks[block_pc].instruction_pcs:
                    fact = facts_by_pc.get(pc)
                    if fact is None:
                        state.clear()
                        continue
                    if pc in internal_call_sites:
                        observed[pc] = {
                            register: state[register]
                            for register in _INTEGER_ARGUMENTS
                            if register in state
                        }
                        argument_bases = {
                            value.base
                            for value in observed[pc].values()
                            if value.base is not None
                        }
                        observed_fields[pc] = {
                            key: value
                            for key, value in state.items()
                            if key.startswith(
                                ("heap-field@", "heap-field-summary@")
                            )
                            and any(
                                key[len(prefix) :].startswith(base)
                                for prefix in (
                                    "heap-field@",
                                    "heap-field-summary@",
                                )
                                for base in argument_bases
                                if key.startswith(prefix)
                            )
                        }
                        observed_stack[pc] = {
                            offset: state.get(_call_stack_key(offset))
                            for offset in range(0, _STACK_ARGUMENT_SLOTS * 8, 8)
                        }
                    argument_state = {
                        register: state[register]
                        for register in _INTEGER_ARGUMENTS
                        if register in state
                    } if pc in internal_call_targets else None
                    _transfer(
                        module,
                        fact,
                        function_pc,
                        state,
                        allocation_calls.get(pc),
                        pc in preserve_heap_field_call_pcs,
                        immutable_heap_field_keys,
                        pc in preserve_heap_only_call_pcs,
                    )
                    apply_allocation_field_summary(state, pc)
                    apply_function_field_summary(state, pc, argument_state)
                    restore_private_allocation_summaries(state, fact)
        for target_pc, call_pcs in calls_by_target.items():
            if not call_pcs <= observed.keys():
                continue
            target_values = entry_values.setdefault(target_pc, {})
            for register in _INTEGER_ARGUMENTS:
                values = [observed[pc].get(register) for pc in call_pcs]
                if any(value is None for value in values):
                    continue
                first = values[0]
                if first is None:
                    continue
                if any(value != first for value in values[1:]):
                    # 同一个 helper 可能从多个路径收到同一 caller 栈帧里的
                    # this/数组地址。这里保留栈对象基址；若只差常量偏移，
                    # 折叠到基址会扩大别名范围，但不会把不同栈帧合成一个对象。
                    if all(
                        value is not None
                        and value.object_kind == AddressKind.STACK
                        and not value.indirect
                        and value.base is not None
                        and value.term is None
                        and value.coefficient == 0
                        and value.base == first.base
                        for value in values
                    ):
                        first = _SymbolicValue(
                            base=first.base,
                            indirect=False,
                            offset=(
                                first.offset
                                if all(
                                    value is not None
                                    and value.offset == first.offset
                                    for value in values
                                )
                                else 0
                            ),
                            evidence_pcs=tuple(
                                dict.fromkeys(
                                    pc
                                    for value in values
                                    if value is not None
                                    for pc in value.evidence_pcs
                                )
                            ),
                            object_kind=AddressKind.STACK,
                        )
                    elif not all(
                        value is not None
                        and value.object_kind == AddressKind.HEAP
                        for value in values
                    ):
                        continue
                    if first.object_kind == AddressKind.STACK:
                        pass
                    else:
                        # 多个 call site 可以传入不同 malloc 对象。这里只保留
                        # “一定是 heap”，不声称这些 allocation site 彼此 NoAlias。
                        first = _SymbolicValue(
                            base=f"heap-union:argument@0x{target_pc:x}:{register}",
                            indirect=False,
                            evidence_pcs=tuple(
                                dict.fromkeys(
                                    pc
                                    for value in values
                                    if value is not None
                                    for pc in value.evidence_pcs
                                )
                            ),
                            object_kind=AddressKind.HEAP,
                            candidate_bases=tuple(
                                sorted(
                                    {
                                        candidate
                                        for value in values
                                        if value is not None
                                        for candidate in (
                                            value.candidate_bases
                                            or ((value.base,) if value.base else ())
                                        )
                                        if candidate is not None
                                        and value.object_kind == AddressKind.HEAP
                                        and not candidate.startswith("heap-union:")
                                    }
                                )
                            ),
                            owner_base=(
                                values[0].owner_base
                                if all(
                                    value.owner_base == values[0].owner_base
                                    for value in values
                                )
                                else None
                            ),
                            owner_term=(
                                values[0].owner_term
                                if all(
                                    value.owner_term == values[0].owner_term
                                    for value in values
                                )
                                else None
                            ),
                            owner_coefficient=(
                                values[0].owner_coefficient
                                if all(
                                    value.owner_coefficient
                                    == values[0].owner_coefficient
                                    for value in values
                                )
                                else None
                            ),
                            fresh_call_pc=(
                                values[0].fresh_call_pc
                                if all(
                                    value.fresh_call_pc == values[0].fresh_call_pc
                                    for value in values
                                )
                                else None
                            ),
                        )
                if register not in target_values:
                    target_values[register] = first
                    propagated = True
            target_stack_values = entry_stack_values.setdefault(target_pc, {})
            for offset in range(0, _STACK_ARGUMENT_SLOTS * 8, 8):
                values = [observed_stack[pc].get(offset) for pc in call_pcs]
                merged = merge_stack_argument_values(values, target_pc, offset)
                if merged is not None and offset not in target_stack_values:
                    target_stack_values[offset] = merged
                    propagated = True
            field_maps = [observed_fields[pc] for pc in call_pcs]
            if field_maps and all(item == field_maps[0] for item in field_maps[1:]):
                if entry_heap_fields.get(target_pc) != field_maps[0]:
                    entry_heap_fields[target_pc] = dict(field_maps[0])
                    propagated = True
            elif target_pc in entry_heap_fields:
                # 不同 call site 传入了不同对象或某个路径缺少字段摘要；
                # 继续沿用旧摘要会把一个 caller 的行指针套到另一个对象。
                entry_heap_fields.pop(target_pc, None)
                propagated = True

    # 参数传播收敛后再计算内部函数的字段摘要。这样像 Rng 构造器这类
    # 不返回对象、却把 fresh allocation 写进 caller 栈对象的函数，
    # 也能在下一轮 caller CFG 中恢复出该字段；未知写入不会出现在摘要里。
    for target_pc in set(internal_call_targets.values()):
        if target_pc not in blocks:
            continue
        _, _, _, field_summary, _ = flow(target_pc)
        if field_summary:
            function_field_summaries[target_pc] = field_summary

    result: dict[tuple[int, int], AbstractAddress] = {}
    call_arguments: dict[int, tuple[AbstractAddress | None, ...]] = {}
    stack_call_arguments: dict[int, tuple[AbstractAddress | None, ...]] = {}
    for function in control_flow.functions:
        if function.location.pc not in reachable_functions:
            continue
        if function.location.pc not in blocks:
            continue
        incoming, _, _, _, _ = flow(
            function.location.pc,
            {
                **seeded_global_values,
                **(
                    published_globals
                    if function.location.pc in seeded_function_pcs
                    else {}
                ),
            }
            if function.location.pc in seeded_function_pcs
            else None,
            seeded_heap_field_values
            if function.location.pc in seeded_function_pcs
            else None,
        )

        for block_pc, entry_state in incoming.items():
            block = blocks[block_pc]
            state = dict(entry_state)
            for pc in block.instruction_pcs:
                fact = facts_by_pc.get(pc)
                if fact is None:
                    state.clear()
                    continue
                if fact.control_flow is not None and fact.control_flow.value.endswith("call"):
                    call_arguments[pc] = tuple(
                        _abstract_value(state.get(register))
                        for register in _INTEGER_ARGUMENTS
                    )
                    stack_call_arguments[pc] = tuple(
                        _abstract_value(state.get(_call_stack_key(offset)))
                        for offset in range(0, _STACK_ARGUMENT_SLOTS * 8, 8)
                    )
                for operand in fact.memory_operands:
                    if _root(operand.base) in {"rip", "rsp", "rbp"} and operand.index is None:
                        continue
                    value = _memory_value(
                        module, fact, operand, function.location.pc, state
                    )
                    if (
                        value is None
                        or value.base is None
                    ):
                        continue
                    address = _abstract_value(value)
                    if address is not None:
                        result[(fact.pc, operand.operand_index)] = address
                argument_state = {
                    register: state[register]
                    for register in _INTEGER_ARGUMENTS
                    if register in state
                } if pc in internal_call_targets else None
                _transfer(
                    module,
                    fact,
                    function.location.pc,
                    state,
                    allocation_calls.get(pc),
                    pc in preserve_heap_field_call_pcs,
                    immutable_heap_field_keys,
                    pc in preserve_heap_only_call_pcs,
                )
                apply_allocation_field_summary(state, pc)
                apply_function_field_summary(state, pc, argument_state)
                restore_private_allocation_summaries(state, fact)
    return AddressProvenanceReport(
        addresses=result,
        call_arguments=call_arguments,
        stack_call_arguments=stack_call_arguments,
        published_globals={
            key: address
            for key, value in published_globals.items()
            if (address := _abstract_value(value)) is not None
        },
        published_heap_fields={
            key: address
            for key, value in published_heap_fields.items()
            if (address := _abstract_value(value)) is not None
        },
    )


def recover_block_local_addresses(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    facts: tuple[InstructionFact, ...],
    allocation_calls: dict[int, str] | None = None,
) -> dict[tuple[int, int], AbstractAddress]:
    """保留旧入口；调用参数来源由完整 report 的调用方使用。"""

    return recover_address_provenance(
        module, control_flow, facts, allocation_calls
    ).addresses
