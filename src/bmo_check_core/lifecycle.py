"""线程生命周期和同步身份的共享输入契约。

这里只记录谁、在哪个稳定位置、用哪个句柄发生了什么操作；不定义 acquire、
release 或 futex 的内存序。ordering 必须继续由版本化 contract 和唯一的
memory-semantics primitive 提供，缺少绑定时只能保留不完整状态。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from .identity import (
    FunctionId,
    LifecycleContextId,
    LifecycleOperationId,
    StableId,
    ThreadHandleId,
)
from .universe import CompletenessState, CompletenessStatus


_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class LifecycleKind(StrEnum):
    """需要独立身份的线程生命周期操作。"""

    # CREATE 建立父线程、child 和句柄之间的静态/动态关系。
    CREATE = "create"
    # START 把实际运行的线程实例绑定到 CREATE 和 callback。
    START = "start"
    # END 是线程实例退出的边界，不能由最后一条访存推断。
    END = "end"
    # JOIN 通过 pthread_t 句柄而不是出现顺序解析 child。
    JOIN = "join"
    # DETACH 关闭 join 关系，但不改变线程是否已经结束。
    DETACH = "detach"


class SyncOperationKind(StrEnum):
    """只描述同步操作身份，不携带任何默认内存序。"""

    # FUTEX_WAIT/WAKE 的排序必须来自 contract，不能由 API 名称猜测。
    FUTEX_WAIT = "futex_wait"
    FUTEX_WAKE = "futex_wake"
    MUTEX = "mutex"
    CONDITION = "condition"
    BARRIER = "barrier"
    NATIVE_MARKER = "native_marker"


class ThreadOrigin(StrEnum):
    """说明线程记录是根线程、create 产生还是外部观察到的。"""

    ROOT = "root"
    CREATED = "created"
    EXTERNAL = "external"


class LifecycleResolutionStatus(StrEnum):
    """句柄解析结果；只有 RESOLVED 才能作为生命周期事实继续传播。"""

    RESOLVED = "resolved"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"


def _stable_ids(name: str, values: tuple[StableId, ...]) -> tuple[StableId, ...]:
    if any(not isinstance(value, StableId) for value in values):
        raise ValueError(f"{name} must contain StableId values")
    normalized = tuple(sorted(set(values), key=lambda value: value.value))
    if len(normalized) != len(values):
        raise ValueError(f"{name} contains duplicate identities")
    return normalized


def _operations(
    name: str,
    values: tuple[LifecycleOperationId, ...],
) -> tuple[LifecycleOperationId, ...]:
    if any(not isinstance(value, LifecycleOperationId) for value in values):
        raise ValueError(f"{name} must contain LifecycleOperationId values")
    normalized = tuple(sorted(set(values), key=lambda value: value.value))
    if len(normalized) != len(values):
        raise ValueError(f"{name} contains duplicate identities")
    return normalized


def _functions(
    name: str,
    values: tuple[FunctionId, ...],
) -> tuple[FunctionId, ...]:
    if any(not isinstance(value, FunctionId) for value in values):
        raise ValueError(f"{name} must contain FunctionId values")
    normalized = tuple(sorted(set(values), key=lambda value: value.value))
    if len(normalized) != len(values):
        raise ValueError(f"{name} contains duplicate identities")
    return normalized


@dataclass(frozen=True, slots=True)
class ThreadLifecycleRecord:
    """一个产生过相关事件的 thread subject 的生命周期账本项。"""

    # thread_id 可以是静态 ThreadRoleId 或动态 ThreadInstanceId，但不能是裸 tid。
    thread_id: StableId
    # origin 区分根线程和由 create 产生的线程，决定需要哪些关系。
    origin: ThreadOrigin
    # parent_thread_id 只在有明确 CREATE 关系时填写。
    parent_thread_id: StableId | None = None
    # handle_id 绑定一次 pthread_t 生命周期；地址/数值复用必须换 generation。
    handle_id: ThreadHandleId | None = None
    # create/start/end 分别绑定实际操作，不能由事件出现顺序补全。
    create_operation: LifecycleOperationId | None = None
    start_operation: LifecycleOperationId | None = None
    end_operation: LifecycleOperationId | None = None
    # callback_context 记录 wrapper、多 caller 和实际 callback 的组合身份。
    callback_context: LifecycleContextId | None = None
    # callback_targets 保留实际候选函数；不能只留下 context 摘要后丢目标集合。
    callback_targets: tuple[FunctionId, ...] = ()
    # 非 COMPLETE 时必须说明缺少哪条生命周期事实。
    completeness: CompletenessState = CompletenessState(
        CompletenessStatus.INCOMPLETE,
        "lifecycle.record",
        reason="lifecycle record was not closed",
    )

    def __post_init__(self) -> None:
        if not isinstance(self.thread_id, StableId):
            raise ValueError("thread_id must be a StableId")
        if not isinstance(self.origin, ThreadOrigin):
            raise ValueError("origin must be a ThreadOrigin")
        if self.parent_thread_id is not None and not isinstance(
            self.parent_thread_id, StableId
        ):
            raise ValueError("parent_thread_id must be a StableId")
        if self.handle_id is not None and not isinstance(self.handle_id, ThreadHandleId):
            raise ValueError("handle_id must be a ThreadHandleId")
        for name in ("create_operation", "start_operation", "end_operation"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, LifecycleOperationId):
                raise ValueError(f"{name} must be a LifecycleOperationId")
        if self.callback_context is not None and not isinstance(
            self.callback_context, LifecycleContextId
        ):
            raise ValueError("callback_context must be a LifecycleContextId")
        object.__setattr__(
            self,
            "callback_targets",
            _functions("callback_targets", self.callback_targets),
        )
        if not isinstance(self.completeness, CompletenessState):
            raise ValueError("completeness must be a CompletenessState")
        if self.completeness.status is CompletenessStatus.COMPLETE:
            if self.start_operation is None or self.end_operation is None:
                raise ValueError("complete lifecycle record requires START and END")
            if self.origin is ThreadOrigin.CREATED and (
                self.parent_thread_id is None
                or self.handle_id is None
                or self.create_operation is None
            ):
                raise ValueError(
                    "complete created thread requires parent, handle, and CREATE"
                )


@dataclass(frozen=True, slots=True)
class LifecycleJoinRelation:
    """一个 join 调用对句柄和候选 child 的明确解析结果。"""

    # operation_id 定位具体 join call/context，不使用调度顺序。
    operation_id: LifecycleOperationId
    # caller_thread_id 记录执行 join 的线程 subject。
    caller_thread_id: StableId
    # handle_id 是唯一允许建立 join→child 关系的键。
    handle_id: ThreadHandleId | None
    # 候选集合保留歧义，不能任选一个 child 继续证明。
    candidate_threads: tuple[StableId, ...] = ()
    # target_thread 只有唯一解析时才可填写。
    target_thread: StableId | None = None
    # 非 COMPLETE 时必须保留原因，防止空候选被解释成无 child。
    completeness: CompletenessState = CompletenessState(
        CompletenessStatus.INCOMPLETE,
        "lifecycle.join",
        reason="join relation was not closed",
    )

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, LifecycleOperationId):
            raise ValueError("operation_id must be a LifecycleOperationId")
        if not isinstance(self.caller_thread_id, StableId):
            raise ValueError("caller_thread_id must be a StableId")
        if self.handle_id is not None and not isinstance(self.handle_id, ThreadHandleId):
            raise ValueError("handle_id must be a ThreadHandleId")
        object.__setattr__(
            self,
            "candidate_threads",
            _stable_ids("candidate_threads", self.candidate_threads),
        )
        if self.target_thread is not None and not isinstance(self.target_thread, StableId):
            raise ValueError("target_thread must be a StableId")
        if self.target_thread is not None and self.target_thread not in self.candidate_threads:
            raise ValueError("target_thread must be one of candidate_threads")
        if not isinstance(self.completeness, CompletenessState):
            raise ValueError("completeness must be a CompletenessState")
        if self.completeness.status is CompletenessStatus.COMPLETE:
            if self.handle_id is None or self.target_thread is None:
                raise ValueError("complete join relation requires handle and target")
            if len(self.candidate_threads) != 1:
                raise ValueError("complete join relation requires one candidate")


@dataclass(frozen=True, slots=True)
class SynchronizationIdentity:
    """同步操作的身份和 contract 绑定；这里不定义 ordering。"""

    # operation_id 让同一 API 的不同 caller/context 保持分离。
    operation_id: LifecycleOperationId
    # kind 只描述事件类别，不能据此推导 acquire/release/full。
    kind: SyncOperationKind
    # sync_object 缺失时不能把不同 mutex/futex 地址合并。
    sync_object: StableId | None
    # contract_digest/rule 必须来自同一次 immutable contract 解析。
    contract_digest: str | None = None
    contract_rule: str | None = None
    # 规则未绑定时保留 UNKNOWN/UNSUPPORTED，而不是猜一个强排序。
    completeness: CompletenessState = CompletenessState(
        CompletenessStatus.INCOMPLETE,
        "lifecycle.synchronization",
        reason="synchronization contract binding is missing",
    )

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, LifecycleOperationId):
            raise ValueError("operation_id must be a LifecycleOperationId")
        if not isinstance(self.kind, SyncOperationKind):
            raise ValueError("kind must be a SyncOperationKind")
        if self.sync_object is not None and not isinstance(self.sync_object, StableId):
            raise ValueError("sync_object must be a StableId")
        if self.contract_digest is not None and not _DIGEST.fullmatch(self.contract_digest):
            raise ValueError("contract_digest must be a lowercase SHA-256 digest")
        if self.contract_rule is not None and (
            not isinstance(self.contract_rule, str)
            or not self.contract_rule
            or "\x00" in self.contract_rule
        ):
            raise ValueError("contract_rule must be a non-empty string")
        if not isinstance(self.completeness, CompletenessState):
            raise ValueError("completeness must be a CompletenessState")
        if self.completeness.status is CompletenessStatus.COMPLETE and (
            self.sync_object is None
            or self.contract_digest is None
            or self.contract_rule is None
        ):
            raise ValueError(
                "complete synchronization identity requires object and contract rule"
            )


@dataclass(frozen=True, slots=True)
class LifecycleResolution:
    """按句柄解析 child 的结果；调度顺序不参与该值。"""

    # status 只有 RESOLVED 才允许下游建立 join happens-before。
    status: LifecycleResolutionStatus
    # target_thread 只在唯一解析时出现。
    target_thread: StableId | None = None
    # candidates 让歧义和缺口可解释，而不是返回空集合伪装无候选。
    candidates: tuple[StableId, ...] = ()
    # reason 记录为什么不能继续闭合。
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, LifecycleResolutionStatus):
            raise ValueError("status must be a LifecycleResolutionStatus")
        object.__setattr__(self, "candidates", _stable_ids("candidates", self.candidates))
        if self.target_thread is not None and not isinstance(self.target_thread, StableId):
            raise ValueError("target_thread must be a StableId")
        if self.status is LifecycleResolutionStatus.RESOLVED:
            if self.target_thread is None or self.candidates != (self.target_thread,):
                raise ValueError("resolved lifecycle relation requires one target")
        elif not isinstance(self.reason, str) or not self.reason:
            raise ValueError("unresolved lifecycle relation requires a reason")


@dataclass(frozen=True, slots=True)
class LifecycleLedger:
    """覆盖所有产生相关事件线程的生命周期账本。"""

    # subject 把账本绑定到一个 binary/trace，而不是跨输入复用角色字符串。
    subject: StableId
    # thread_universe 来自事件生产阶段；缺少其中一条记录不能宣称完整。
    thread_universe: tuple[StableId, ...]
    records: tuple[ThreadLifecycleRecord, ...]
    joins: tuple[LifecycleJoinRelation, ...] = ()
    synchronizations: tuple[SynchronizationIdentity, ...] = ()
    completeness: CompletenessState = CompletenessState(
        CompletenessStatus.INCOMPLETE,
        "lifecycle.ledger",
        reason="lifecycle universe was not closed",
    )

    def __post_init__(self) -> None:
        if not isinstance(self.subject, StableId):
            raise ValueError("subject must be a StableId")
        object.__setattr__(
            self,
            "thread_universe",
            _stable_ids("thread_universe", self.thread_universe),
        )
        if any(not isinstance(item, ThreadLifecycleRecord) for item in self.records):
            raise ValueError("records must contain ThreadLifecycleRecord values")
        records = tuple(sorted(self.records, key=lambda item: item.thread_id.value))
        if len({item.thread_id for item in records}) != len(records):
            raise ValueError("records contain duplicate thread identities")
        object.__setattr__(self, "records", records)
        if any(not isinstance(item, LifecycleJoinRelation) for item in self.joins):
            raise ValueError("joins must contain LifecycleJoinRelation values")
        if any(not isinstance(item, SynchronizationIdentity) for item in self.synchronizations):
            raise ValueError("synchronizations must contain SynchronizationIdentity values")
        if not isinstance(self.completeness, CompletenessState):
            raise ValueError("completeness must be a CompletenessState")
        universe = set(self.thread_universe)
        record_ids = {item.thread_id for item in records}
        if not record_ids.issubset(universe):
            raise ValueError("records contain threads outside the event universe")
        if self.completeness.status is CompletenessStatus.COMPLETE:
            if record_ids != universe:
                raise ValueError("complete lifecycle ledger must account for every thread")
            if any(
                item.completeness.status is not CompletenessStatus.COMPLETE
                for item in records
            ):
                raise ValueError("complete lifecycle ledger cannot contain incomplete record")
            if any(
                item.completeness.status is not CompletenessStatus.COMPLETE
                for item in (*self.joins, *self.synchronizations)
            ):
                raise ValueError("complete lifecycle ledger cannot contain incomplete relation")

    @property
    def missing_thread_ids(self) -> tuple[StableId, ...]:
        recorded = {item.thread_id for item in self.records}
        return tuple(item for item in self.thread_universe if item not in recorded)

    def resolve_handle(self, handle: ThreadHandleId) -> LifecycleResolution:
        """按 handle identity 解析 child；不会按记录或调度顺序配对。"""

        if not isinstance(handle, ThreadHandleId):
            raise ValueError("handle must be a ThreadHandleId")
        if self.completeness.status is not CompletenessStatus.COMPLETE:
            return LifecycleResolution(
                LifecycleResolutionStatus.INCOMPLETE,
                candidates=(),
                reason="lifecycle universe is not complete",
            )
        candidates = tuple(
            item.thread_id for item in self.records if item.handle_id == handle
        )
        if len(candidates) == 1:
            return LifecycleResolution(
                LifecycleResolutionStatus.RESOLVED,
                target_thread=candidates[0],
                candidates=candidates,
            )
        if len(candidates) > 1:
            return LifecycleResolution(
                LifecycleResolutionStatus.AMBIGUOUS,
                candidates=candidates,
                reason="one handle maps to multiple thread instances",
            )
        return LifecycleResolution(
            LifecycleResolutionStatus.INCOMPLETE,
            candidates=(),
            reason="handle has no unique lifecycle record",
        )


__all__ = [
    "LifecycleJoinRelation",
    "LifecycleKind",
    "LifecycleLedger",
    "LifecycleOperationId",
    "LifecycleResolution",
    "LifecycleResolutionStatus",
    "SyncOperationKind",
    "SynchronizationIdentity",
    "ThreadLifecycleRecord",
    "ThreadOrigin",
]
