from __future__ import annotations

from enum import Enum

from pydantic import model_validator

from .common import StrictModel
from .memory_event import AbstractAddress, MemoryEvent, ProgramOrderEdge
from .unknown import UnknownFact


class SharingClass(str, Enum):
    # THREAD_LOCAL 需要 TLS 或未逃逸对象证明。
    THREAD_LOCAL = "ThreadLocal"
    # READ_ONLY_AFTER_CREATE 允许 main 初始化、worker 创建后只读。
    READ_ONLY_AFTER_CREATE = "ReadOnlyAfterCreate"
    # DISJOINT_PARTITION 表示不同线程实例的写集合不重叠。
    DISJOINT_PARTITION = "DisjointPartition"
    # SHARED_KNOWN 表示对象共享且地址边界已知。
    SHARED_KNOWN = "SharedKnown"
    # SHARED_UNKNOWN 是无法封闭地址或 escape 时的默认分类。
    SHARED_UNKNOWN = "SharedUnknown"


class EscapeKind(str, Enum):
    # NO_ESCAPE 只在穷尽已支持的逃逸路径后使用。
    NO_ESCAPE = "NoEscape"
    # THREAD_ESCAPE 表示对象地址传给其他线程。
    THREAD_ESCAPE = "ThreadEscape"
    # OPAQUE_ESCAPE 表示地址流入未建模调用或存储。
    OPAQUE_ESCAPE = "OpaqueEscape"
    # UNKNOWN 是分析能力不足时的保守默认值。
    UNKNOWN = "UnknownEscape"


class ProofReason(str, Enum):
    # TLS_STORAGE 依赖 x86 TLS 段寻址和独立线程实例。
    TLS_STORAGE = "TLSStorage"
    # SINGLE_MAIN_ROLE 表示事件只可能由唯一 main 线程执行。
    SINGLE_MAIN_ROLE = "SingleMainRole"
    # UNESCAPED_STACK 依赖函数中没有栈地址物化。
    UNESCAPED_STACK = "UnescapedStack"
    # READ_ONLY_AFTER_CREATE 依赖 create 支配边和无隐藏 writer。
    READ_ONLY_AFTER_CREATE = "ReadOnlyAfterCreate"
    # DISJOINT_AFFINE 依赖有界仿射集合的 Z3 不相交证明。
    DISJOINT_AFFINE = "DisjointAffine"
    # ATOMIC_COVERED 只用于普通通信已被具体 aq/rl 或 fence 边覆盖的证明。
    ATOMIC_COVERED = "AtomicCovered"
    # SEQUENTIAL_BEFORE_CREATE 表示事件发生时还没有 worker 可以并发访问。
    SEQUENTIAL_BEFORE_CREATE = "SequentialBeforeCreate"
    # SEQUENTIAL_AFTER_JOIN 表示已证明每个成功创建的 worker 都已退出。
    SEQUENTIAL_AFTER_JOIN = "SequentialAfterJoin"
    # SEQUENTIAL_MAIN_CALLEE 表示 main 只在创建前或 join 后进入该函数。
    # worker 对同一函数的访问不在这份证明内。
    SEQUENTIAL_MAIN_CALLEE = "SequentialMainCallee"
    # NON_RETURNING_PATH 只用于 scope 明确排除异常终止的证书。
    NON_RETURNING_PATH = "NonReturningPath"
    # APPLICATION_RUNTIME_BOUNDARY 只在显式 application scope 下移除运行库 effect。
    # 这些 effect 不进入应用通信图，运行库自身的 LOCK/XCHG/Fence 仍由 DBT contract 负责。
    APPLICATION_RUNTIME_BOUNDARY = "ApplicationRuntimeBoundary"
    # FRESH_ALLOCATION 表示每个动态调用得到的新对象，不能和另一线程的
    # 同一 allocation site 返回值重叠；仍需保留逃逸检查。
    FRESH_ALLOCATION = "FreshAllocation"


class AliasRelation(str, Enum):
    # MUST_ALIAS 表示字节区间确定重叠。
    MUST_ALIAS = "MustAlias"
    # NO_ALIAS 必须有地址区间或分片证明。
    NO_ALIAS = "NoAlias"
    # MAY_ALIAS 是无法排除重叠时的默认值。
    MAY_ALIAS = "MayAlias"


class SharedObject(StrictModel):
    # id 稳定标识一组可能指向同一对象的事件。
    id: str
    # address 是对象的规范化抽象地址。
    address: AbstractAddress
    # event_ids 保存该对象覆盖的所有 role/effect。
    event_ids: tuple[str, ...]
    # roles/readers/writers 用于判断是否存在跨线程冲突。
    roles: tuple[str, ...]
    reader_events: tuple[str, ...] = ()
    writer_events: tuple[str, ...] = ()
    # sharing 与 escape 都不允许因缺少证据自动变强。
    sharing: SharingClass
    escape: EscapeKind


class ProofObject(StrictModel):
    # id 让被剪除事件可以引用同一份证明。
    id: str
    # reason 决定 proof checker 需要复核的条件。
    reason: ProofReason
    # event_ids 必须完整列出此次剪除覆盖的事件。
    event_ids: tuple[str, ...]
    # supporting_facts 保存二进制 PC、CFG 边、bounds 或 Z3 结论。
    supporting_facts: tuple[str, ...]


class ConflictCandidate(StrictModel):
    # 两个 event 可以相同，表示同一 role 的不同动态实例可能冲突。
    first_event: str
    second_event: str
    first_role: str
    second_role: str
    # alias 未证明 NoAlias 时必须保留候选边。
    alias: AliasRelation
    # same_role_instances 区分静态 role 与动态线程实例。
    same_role_instances: bool = False


class SynchronizationEdge(StrictModel):
    # source/target 引用 create、join 或已证明同步事件。
    source_event: str
    target_event: str
    # kind 解释边来自 lifecycle、atomic 还是 fence。
    kind: str
    # evidence 绑定实际 binary/summary 事实。
    evidence: tuple[str, ...] = ()
    # complete=False 的 lifecycle 候选不能被 proof 层当成已建立 happens-before。
    complete: bool = False
    # reason 解释缺少 thread relation 还是 target ordering 证据。
    reason: str | None = None

    @model_validator(mode="after")
    def require_incomplete_reason(self) -> "SynchronizationEdge":
        if not self.complete and not self.reason:
            raise ValueError("incomplete synchronization edge requires a reason")
        return self


class PruningCoverage(StrictModel):
    # total_events 是剪枝前的事件数。
    total_events: int
    thread_local_removed: int = 0
    readonly_removed: int = 0
    disjoint_removed: int = 0
    atomic_covered_removed: int = 0
    # remaining_shared_events 是交给 portability 层的事件数。
    remaining_shared_events: int = 0
    # unknown_events 必须留在 slice 中。
    unknown_events: int = 0


class SharedStateReport(StrictModel):
    # objects 保存事件到共享对象的保守分组。
    objects: tuple[SharedObject, ...] = ()
    # kept_event_ids 与 removed_event_ids 明确给出剪枝边界。
    kept_event_ids: tuple[str, ...] = ()
    removed_event_ids: tuple[str, ...] = ()
    # proofs 必须覆盖每个 removed event。
    proofs: tuple[ProofObject, ...] = ()
    # unknowns 传播地址、escape 和 bounds 缺口。
    unknowns: tuple[UnknownFact, ...] = ()

    @model_validator(mode="after")
    def require_proof_for_every_removed_event(self) -> "SharedStateReport":
        covered = {event_id for proof in self.proofs for event_id in proof.event_ids}
        missing = set(self.removed_event_ids) - covered
        if missing:
            raise ValueError(f"removed events lack proof objects: {sorted(missing)}")
        return self


class SharedMemorySlice(StrictModel):
    # events 包含所有未被证明可剪除的共享和未知 effect。
    events: tuple[MemoryEvent, ...] = ()
    # program_order 只保留两端仍在 slice 的边。
    program_order: tuple[ProgramOrderEdge, ...] = ()
    # conflicts 是后续 memory-model checker 的通信候选。
    conflicts: tuple[ConflictCandidate, ...] = ()
    # synchronization 保存已建模 lifecycle/atomic/fence 边。
    synchronization: tuple[SynchronizationEdge, ...] = ()
    # proof_objects 解释每个被移除事件。
    proof_objects: tuple[ProofObject, ...] = ()
    coverage: PruningCoverage
    # unknowns 与未知事件一起进入后续 proof 层。
    unknowns: tuple[UnknownFact, ...] = ()
