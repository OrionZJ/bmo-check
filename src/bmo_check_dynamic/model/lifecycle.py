"""生命周期 sidecar 的严格序列化边界。

当前 TraceEvent 仍保持旧 wire layout。这个模型为后续版本化 sidecar 规定
必须携带的身份和完整性字段；它不从旧记录推断缺失关系，也不定义同步排序。
"""

from __future__ import annotations

import re

from bmo_check_core import (
    CompletenessStatus,
    FunctionId,
    LifecycleContextId,
    LifecycleKind,
    LifecycleOperationId,
    SyncOperationKind,
    ThreadHandleId,
    ThreadInstanceId,
    TraceId,
)
from pydantic import model_validator

from .manifest import StrictModel


_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _stable_id(name: str, value: str, parser):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty stable identity")
    try:
        return parser.from_value(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} is not a valid stable identity") from error


def _unique(name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError(f"{name} must contain non-empty identities")
    normalized = tuple(sorted(set(values)))
    if len(normalized) != len(values):
        raise ValueError(f"{name} contains duplicate identities")
    return normalized


class TraceLifecycleRecord(StrictModel):
    """一个 CREATE/START/END 操作的 wire 记录。"""

    # operation_id 绑定具体 site/context/occurrence，不能用数组下标代替。
    operation_id: str
    # kind 只描述生命周期阶段，不携带内存序。
    kind: LifecycleKind
    # thread_instance_id 区分同一 trace 中的线程实例。
    thread_instance_id: str
    # parent_thread_instance_id 缺失时不能把 caller 当作 parent。
    parent_thread_instance_id: str | None = None
    # handle_token/generation 成对出现，地址复用必须使用新 generation。
    handle_token: str | None = None
    handle_generation: int | None = None
    # callback_context_id 和 callback_target_ids 防止 wrapper 多 caller 被合并。
    callback_context_id: str | None = None
    callback_target_ids: tuple[str, ...] = ()
    # sidecar 的每条记录都明确自己的完整性。
    completeness: CompletenessStatus = CompletenessStatus.INCOMPLETE
    reason: str | None = "lifecycle record is not closed"

    @model_validator(mode="after")
    def validate_identities(self) -> "TraceLifecycleRecord":
        _stable_id("operation_id", self.operation_id, LifecycleOperationId)
        _stable_id("thread_instance_id", self.thread_instance_id, ThreadInstanceId)
        if self.parent_thread_instance_id is not None:
            _stable_id(
                "parent_thread_instance_id",
                self.parent_thread_instance_id,
                ThreadInstanceId,
            )
        if self.callback_context_id is not None:
            _stable_id("callback_context_id", self.callback_context_id, LifecycleContextId)
        _unique("callback_target_ids", self.callback_target_ids)
        for target in self.callback_target_ids:
            _stable_id("callback_target_id", target, FunctionId)
        if (self.handle_token is None) != (self.handle_generation is None):
            raise ValueError("handle_token and handle_generation must be provided together")
        if self.handle_token is not None and (
            not self.handle_token or "\x00" in self.handle_token
        ):
            raise ValueError("handle_token must be a non-empty string without NUL")
        if self.handle_generation is not None and (
            isinstance(self.handle_generation, bool)
            or not isinstance(self.handle_generation, int)
            or self.handle_generation < 0
        ):
            raise ValueError("handle_generation must be a non-negative integer")
        if self.completeness is CompletenessStatus.COMPLETE:
            if self.reason is not None:
                raise ValueError("complete lifecycle record cannot carry a reason")
        elif not isinstance(self.reason, str) or not self.reason:
            raise ValueError("incomplete lifecycle record requires a reason")
        return self


class TraceLifecycleJoin(StrictModel):
    """一个按 pthread_t handle 解析的 join wire 记录。"""

    # operation_id 定位具体 join call/context。
    operation_id: str
    # caller_thread_instance_id 是执行 join 的线程，而不是调度顺序位置。
    caller_thread_instance_id: str
    # handle generation 是 join→child 唯一允许使用的键。
    handle_token: str | None = None
    handle_generation: int | None = None
    # 候选集合必须保留，不能把歧义压成一个 target。
    candidate_thread_instance_ids: tuple[str, ...] = ()
    # target 只有唯一候选且关系闭合时才可填写。
    target_thread_instance_id: str | None = None
    completeness: CompletenessStatus = CompletenessStatus.INCOMPLETE
    reason: str | None = "join relation is not closed"

    @model_validator(mode="after")
    def validate_relation(self) -> "TraceLifecycleJoin":
        _stable_id("operation_id", self.operation_id, LifecycleOperationId)
        _stable_id(
            "caller_thread_instance_id",
            self.caller_thread_instance_id,
            ThreadInstanceId,
        )
        candidates = _unique(
            "candidate_thread_instance_ids", self.candidate_thread_instance_ids
        )
        for candidate in candidates:
            _stable_id("candidate_thread_instance_id", candidate, ThreadInstanceId)
        if self.target_thread_instance_id is not None:
            _stable_id(
                "target_thread_instance_id",
                self.target_thread_instance_id,
                ThreadInstanceId,
            )
            if self.target_thread_instance_id not in candidates:
                raise ValueError("target thread must be one of candidate threads")
        if (self.handle_token is None) != (self.handle_generation is None):
            raise ValueError("handle_token and handle_generation must be provided together")
        if self.handle_token is not None and (
            not self.handle_token or "\x00" in self.handle_token
        ):
            raise ValueError("handle_token must be a non-empty string without NUL")
        if self.handle_generation is not None and (
            isinstance(self.handle_generation, bool)
            or not isinstance(self.handle_generation, int)
            or self.handle_generation < 0
        ):
            raise ValueError("handle_generation must be a non-negative integer")
        if self.completeness is CompletenessStatus.COMPLETE:
            if self.handle_token is None or self.target_thread_instance_id is None:
                raise ValueError("complete join requires handle and target")
            if len(candidates) != 1:
                raise ValueError("complete join requires one candidate")
            if self.reason is not None:
                raise ValueError("complete join cannot carry a reason")
        elif not isinstance(self.reason, str) or not self.reason:
            raise ValueError("incomplete join requires a reason")
        return self


class TraceSynchronizationRecord(StrictModel):
    """同步身份和 contract 绑定；不在 wire 层猜 ordering。"""

    operation_id: str
    kind: SyncOperationKind
    sync_object_id: str | None = None
    contract_digest: str | None = None
    contract_rule: str | None = None
    completeness: CompletenessStatus = CompletenessStatus.INCOMPLETE
    reason: str | None = "synchronization contract binding is missing"

    @model_validator(mode="after")
    def validate_contract_binding(self) -> "TraceSynchronizationRecord":
        _stable_id("operation_id", self.operation_id, LifecycleOperationId)
        if self.sync_object_id is not None and (
            not self.sync_object_id or "\x00" in self.sync_object_id
        ):
            raise ValueError("sync_object_id must be a non-empty string without NUL")
        if self.contract_digest is not None and not _DIGEST.fullmatch(self.contract_digest):
            raise ValueError("contract_digest must be a lowercase SHA-256 digest")
        if self.contract_rule is not None and (
            not self.contract_rule or "\x00" in self.contract_rule
        ):
            raise ValueError("contract_rule must be a non-empty string without NUL")
        if self.completeness is CompletenessStatus.COMPLETE:
            if (
                self.sync_object_id is None
                or self.contract_digest is None
                or self.contract_rule is None
            ):
                raise ValueError("complete synchronization requires contract binding")
            if self.reason is not None:
                raise ValueError("complete synchronization cannot carry a reason")
        elif not isinstance(self.reason, str) or not self.reason:
            raise ValueError("incomplete synchronization requires a reason")
        return self


class TraceLifecycleMetadata(StrictModel):
    """版本化 sidecar 的 universe、join 和同步完整性总账。"""

    # schema_version 与 TraceEvent 版本分开，避免旧 binary layout 被误读。
    schema_version: str = "2.0"
    trace_id: str
    thread_universe: tuple[str, ...]
    records: tuple[TraceLifecycleRecord, ...] = ()
    joins: tuple[TraceLifecycleJoin, ...] = ()
    synchronizations: tuple[TraceSynchronizationRecord, ...] = ()
    completeness: CompletenessStatus = CompletenessStatus.INCOMPLETE
    reason: str | None = "lifecycle metadata is not closed"

    @model_validator(mode="after")
    def validate_universe(self) -> "TraceLifecycleMetadata":
        if not isinstance(self.schema_version, str) or not self.schema_version:
            raise ValueError("schema_version must be a non-empty string")
        _stable_id("trace_id", self.trace_id, TraceId)
        universe = _unique("thread_universe", self.thread_universe)
        for thread_id in universe:
            _stable_id("thread_universe entry", thread_id, ThreadInstanceId)
        record_ids = tuple(record.thread_instance_id for record in self.records)
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("records contain duplicate thread identities")
        if not set(record_ids).issubset(set(universe)):
            raise ValueError("record thread is outside thread_universe")
        if self.completeness is CompletenessStatus.COMPLETE:
            if not universe or set(record_ids) != set(universe):
                raise ValueError("complete lifecycle metadata must cover thread_universe")
            if any(
                item.completeness is not CompletenessStatus.COMPLETE
                for item in (*self.records, *self.joins, *self.synchronizations)
            ):
                raise ValueError("complete lifecycle metadata contains incomplete item")
            if self.reason is not None:
                raise ValueError("complete lifecycle metadata cannot carry a reason")
        elif not isinstance(self.reason, str) or not self.reason:
            raise ValueError("incomplete lifecycle metadata requires a reason")
        return self


__all__ = [
    "TraceLifecycleJoin",
    "TraceLifecycleMetadata",
    "TraceLifecycleRecord",
    "TraceSynchronizationRecord",
]
