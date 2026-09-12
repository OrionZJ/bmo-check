"""静态有限模型的固定执行表征接口。

E2.5 需要把同一组 ``po/rf/co`` 关系分别送入 source 和 target。这里复用
现有 Z3 编码，只新增一个窄的只读入口；不改变 ``check_finite_portability``
的枚举、边界或最终 verdict。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import z3

from bmo_check_static.model import CheckerLimits, SharedMemorySlice

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
    read_from: Mapping[str, str | None],
    coherence: tuple[tuple[str, str, str], ...] = (),
    timeout_ms: int = 10_000,
) -> FixedExecutionResult:
    """检查一组已给定的 ``rf/co``，不搜索其它关系赋值。

    这个入口只报告底层 execution legality。它不会把 ``allowed`` 转成
    ``SAFE``，也不会把一次 fixture 的关系写入静态证据账本。
    """

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

    assignment = _RelationAssignment(
        read_from=dict(read_from),
        coherence=tuple(sorted(fixed_co)),
        booleans=(),
    )
    return FixedExecutionResult(
        _check_model(shared_slice, assignment, "x86-tso", timeout_ms),
        _check_model(shared_slice, assignment, "rvwmo", timeout_ms),
    )


__all__ = ["FixedExecutionResult", "FixedModelResult", "check_fixed_execution"]
