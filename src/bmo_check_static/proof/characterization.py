"""静态有限模型的固定执行表征接口。

E2.5 需要把同一组 ``po/rf/co`` 关系分别送入 source 和 target。这里复用
现有 Z3 编码，只新增一个窄的只读入口；不改变 ``check_finite_portability``
的枚举、边界或最终 verdict。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import z3

from bmo_check_core import (
    AccessRange,
    ExecutionRelations,
    MemoryAccessKind,
    MemoryEventId,
    MemoryOperation,
    MemoryRelation,
    ObligationInventory,
    RelationKind,
    build_execution_obligation_inventory as build_core_execution_obligation_inventory,
)
from bmo_check_static.model import CheckerLimits, EventKind, SharedMemorySlice

from .encoding import (
    _RelationAssignment,
    _build_encoding,
    _is_memory,
    _is_read,
    _is_write,
    _object_id,
    _validate_supported_slice,
)


@dataclass(frozen=True, slots=True)
class FixedModelResult:
    """一个固定 ``rf/co`` 赋值在某个内存模型下的结果。"""

    model: str
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class FixedExecutionResult:
    """同一固定执行在 x86-TSO 与 RVWMO 下的独立结果。"""

    source: FixedModelResult
    target: FixedModelResult


def _canonical_operations(
    shared_slice: SharedMemorySlice,
) -> dict[str, MemoryOperation]:
    """为 static slice 建立一次稳定的 relation 端点表。"""

    operations: dict[str, MemoryOperation] = {}
    sequences: dict[str, int] = {}
    for event in shared_slice.events:
        if not _is_memory(event):
            continue
        if (
            event.thread_role is None
            or event.address is None
            or event.address.base is None
            or event.address.offset is None
            or event.size is None
        ):
            raise ValueError(f"event {event.id!r} lacks canonical relation address")
        if event.kind is EventKind.LOAD:
            kind = MemoryAccessKind.LOAD
        elif event.kind is EventKind.STORE:
            kind = MemoryAccessKind.STORE
        elif event.kind is EventKind.ATOMIC_RMW:
            kind = MemoryAccessKind.RMW
        else:
            raise ValueError(f"event {event.id!r} is not a relation memory operation")
        sequence = sequences.get(event.thread_role, 0)
        sequences[event.thread_role] = sequence + 1
        object_id = (
            f"{event.module_sha256}:{event.address.kind.value}:"
            f"{event.address.base}"
        )
        operations[event.id] = MemoryOperation(
            event_id=event.id,
            thread_id=event.thread_role,
            sequence=sequence,
            access=AccessRange(
                object_id=object_id,
                offset=event.address.offset,
                size=event.size,
            ),
            kind=kind,
        )
    return operations


def canonicalize_fixed_relations(
    shared_slice: SharedMemorySlice,
    *,
    read_from: Mapping[str, str | None],
    coherence: tuple[tuple[str, str, str], ...] = (),
    from_read: tuple[tuple[str, str, str], ...] = (),
) -> ExecutionRelations:
    """把旧 fixed-execution 输入转成 typed RF/CO/FR 命题。

    这是 characterization adapter，不执行 x86/RVWMO legality。调用方仍须
    由 checker 验证 RF 覆盖、CO 全序和 execution completeness；无法把关系
    唯一绑定到本 slice 时抛出输入错误，不能猜一个 event 或 object。
    """

    operations = _canonical_operations(shared_slice)

    def operation(event_id: str) -> MemoryOperation:
        try:
            return operations[event_id]
        except KeyError as error:
            raise ValueError(f"relation references unknown event {event_id!r}") from error

    typed_read_from = tuple(
        MemoryRelation(
            RelationKind.READ_FROM,
            None if source_id is None else operation(source_id),
            operation(load_id),
        )
        for load_id, source_id in sorted(read_from.items())
    )

    events = {event.id: event for event in shared_slice.events}

    def check_object_label(label: str, before: str, after: str) -> None:
        if not isinstance(label, str) or not label:
            raise ValueError("relation object label must be non-empty")
        if before not in events or after not in events:
            raise ValueError("relation object label references an unknown event")
        if _object_id(events[before]) != label:
            raise ValueError("relation object label does not match source event")
        if _object_id(events[after]) != label:
            raise ValueError("relation object label does not match target event")

    typed_coherence = tuple(
        (
            check_object_label(label, before, after),
            MemoryRelation(
                RelationKind.COHERENCE,
                operation(before),
                operation(after),
            ),
        )[1]
        for label, before, after in coherence
    )
    typed_from_read = tuple(
        (
            check_object_label(label, read, after),
            MemoryRelation(
                RelationKind.FROM_READ,
                operation(read),
                operation(after),
            ),
        )[1]
        for label, read, after in from_read
    )
    return ExecutionRelations(
        read_from=typed_read_from,
        coherence=typed_coherence,
        from_read=typed_from_read,
    )


def _legacy_relations(
    shared_slice: SharedMemorySlice,
    relations: ExecutionRelations,
) -> tuple[Mapping[str, str | None], tuple[tuple[str, str, str], ...], tuple[tuple[str, str, str], ...]]:
    """把已绑定到本 slice 的 typed relation 交给现有 encoder。"""

    expected = _canonical_operations(shared_slice)
    events = {event.id: event for event in shared_slice.events}
    if not relations.all_exact_width:
        raise ValueError("typed relation is outside the exact-width support boundary")

    def event_for(operation: MemoryOperation) -> str:
        expected_operation = expected.get(operation.event_id)
        if expected_operation != operation:
            raise ValueError(
                f"typed relation endpoint {operation.event_id!r} does not match slice"
            )
        return operation.event_id

    read_from = {
        event_for(relation.target):
        (None if relation.source is None else event_for(relation.source))
        for relation in relations.read_from
    }
    coherence = tuple(
        (
            _object_id(events[event_for(relation.source)]),
            event_for(relation.source),
            event_for(relation.target),
        )
        for relation in relations.coherence
        if relation.source is not None
    )
    from_read = tuple(
        (
            _object_id(events[event_for(relation.target)]),
            event_for(relation.source),
            event_for(relation.target),
        )
        for relation in relations.from_read
        if relation.source is not None
    )
    return read_from, coherence, from_read


def build_execution_obligation_inventory(
    shared_slice: SharedMemorySlice,
    relations: ExecutionRelations,
    *,
    event_ids: Mapping[str, MemoryEventId],
    scope: str = "static.fixed-execution",
) -> ObligationInventory:
    """把 static slice 归一化后交给 core 的唯一 obligation 规则。"""

    try:
        operations = _canonical_operations(shared_slice)
    except ValueError as error:
        from bmo_check_core import CompletenessState, CompletenessStatus

        return ObligationInventory(
            scope=scope,
            obligations=(),
            completeness=CompletenessState(
                CompletenessStatus.INCOMPLETE,
                scope,
                reason=f"static operation normalization is incomplete: {error}",
            ),
        )
    return build_core_execution_obligation_inventory(
        operations,
        relations,
        event_ids=event_ids,
        scope=scope,
    )


def _unknown(model: str, reason: str) -> FixedModelResult:
    return FixedModelResult(model=model, status="unknown", reason=reason)


def _check_model(
    shared_slice: SharedMemorySlice,
    assignment: _RelationAssignment,
    model: str,
    timeout_ms: int,
) -> FixedModelResult:
    encoding = _build_encoding(shared_slice, model, timeout_ms, assignment)
    status = encoding.solver.check()
    if status == z3.sat:
        return FixedModelResult(
            model=model,
            status="allowed",
            reason="fixed rf/co assignment satisfies the finite model constraints",
        )
    if status == z3.unsat:
        return FixedModelResult(
            model=model,
            status="forbidden",
            reason="fixed rf/co assignment violates the finite model constraints",
        )
    return _unknown(
        model,
        f"fixed execution solver returned unknown: {encoding.solver.reason_unknown()}",
    )


def check_fixed_execution(
    shared_slice: SharedMemorySlice,
    *,
    read_from: Mapping[str, str | None] | None = None,
    coherence: tuple[tuple[str, str, str], ...] = (),
    from_read: tuple[tuple[str, str, str], ...] = (),
    relations: ExecutionRelations | None = None,
    obligation_inventory: ObligationInventory | None = None,
    timeout_ms: int = 10_000,
) -> FixedExecutionResult:
    """检查一组已给定的 ``rf/co``，不搜索其它关系赋值。

    这个入口只报告底层 execution legality。它不会把 ``allowed`` 转成
    ``SAFE``，也不会把一次 fixture 的关系写入静态证据账本。
    """

    if relations is not None:
        if read_from is not None or coherence or from_read:
            reason = "typed relations cannot be mixed with legacy relation arguments"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        if not isinstance(relations, ExecutionRelations):
            reason = "typed relations must be an ExecutionRelations value"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        if not isinstance(obligation_inventory, ObligationInventory):
            reason = "typed relations require an explicit obligation inventory"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        if not obligation_inventory.is_enumerated:
            reason = "execution obligation inventory is incomplete"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        try:
            read_from, coherence, from_read = _legacy_relations(shared_slice, relations)
        except ValueError as error:
            reason = f"typed relation binding is incomplete: {error}"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
    elif read_from is None:
        reason = "fixed execution requires legacy or typed relation input"
        return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    roles = {
        event.thread_role
        for event in shared_slice.events
        if event.thread_role is not None
    }
    limits = CheckerLimits(
        max_events=max(1, len(shared_slice.events)),
        max_threads=max(1, len(roles)),
        max_executions=1,
        timeout_ms=timeout_ms,
    )
    unsupported = _validate_supported_slice(shared_slice, limits)
    if unsupported:
        reason = (
            "fixed execution is outside the static finite checker support set: "
            + ", ".join(unsupported)
        )
        return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    events = {event.id: event for event in shared_slice.events}
    memory = [event for event in shared_slice.events if _is_memory(event)]
    reads = {event.id for event in memory if _is_read(event)}
    writes = {event.id for event in memory if _is_write(event)}
    if set(read_from) != reads:
        reason = "fixed rf assignment must cover every static load/RMW exactly once"
        return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    object_by_event = {event.id: _object_id(event) for event in memory}
    for load_id, store_id in read_from.items():
        if load_id not in reads:
            reason = f"rf references a non-load event {load_id!r}"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        if store_id is not None and (
            store_id not in writes or object_by_event[store_id] != object_by_event[load_id]
        ):
            reason = f"rf source does not write the load object: {load_id!r} <- {store_id!r}"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    stores_by_object: dict[str, set[str]] = {}
    for event_id in writes:
        stores_by_object.setdefault(object_by_event[event_id], set()).add(event_id)
    fixed_co: set[tuple[str, str, str]] = set()
    for object_label, before, after in coherence:
        if before not in writes or after not in writes:
            reason = "coherence references a non-store event"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        if object_by_event[before] != object_label or object_by_event[after] != object_label:
            reason = "coherence object does not match the static address identity"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))
        fixed_co.add((object_label, before, after))

    # 固定关系必须给出每个对象上所有写入对的方向；缺一对时 solver 会
    # 自行选择另一种执行，失去 fixture 对“同一执行”的约束。
    for object_label, object_stores in stores_by_object.items():
        expected = len(object_stores) * (len(object_stores) - 1) // 2
        actual = sum(1 for label, _before, _after in fixed_co if label == object_label)
        if actual != expected:
            reason = f"coherence assignment is incomplete for object {object_label!r}"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    if from_read:
        expected_from_read: set[tuple[str, str, str]] = set()
        order_by_object: dict[str, tuple[str, ...]] = {}
        for object_id, object_store_ids in stores_by_object.items():
            store_ids = tuple(sorted(object_store_ids))
            predecessors = {store_id: 0 for store_id in store_ids}
            successors = {store_id: set() for store_id in store_ids}
            for _label, before_id, after_id in fixed_co:
                if _label == object_id:
                    successors[before_id].add(after_id)
                    predecessors[after_id] += 1
            ready = sorted(
                store_id for store_id, degree in predecessors.items() if degree == 0
            )
            order: list[str] = []
            while ready:
                store_id = ready.pop(0)
                order.append(store_id)
                for successor in sorted(successors[store_id]):
                    predecessors[successor] -= 1
                    if predecessors[successor] == 0:
                        ready.append(successor)
                        ready.sort()
            order_by_object[object_id] = tuple(order)
        for load_id, source_id in read_from.items():
            object_id = object_by_event[load_id]
            order = order_by_object[object_id]
            later = (
                order[order.index(source_id) + 1 :]
                if source_id is not None
                else order
            )
            expected_from_read.update(
                (object_id, load_id, store_id) for store_id in later
            )
        if set(from_read) != expected_from_read:
            reason = "explicit from-read relation does not match the rf/co assignment"
            return FixedExecutionResult(_unknown("x86-tso", reason), _unknown("rvwmo", reason))

    assignment = _RelationAssignment(
        read_from=dict(read_from),
        coherence=tuple(sorted(fixed_co)),
        booleans=(),
    )
    return FixedExecutionResult(
        _check_model(shared_slice, assignment, "x86-tso", timeout_ms),
        _check_model(shared_slice, assignment, "rvwmo", timeout_ms),
    )


__all__ = [
    "FixedExecutionResult",
    "FixedModelResult",
    "build_execution_obligation_inventory",
    "check_fixed_execution",
]
