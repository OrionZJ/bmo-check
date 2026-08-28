from __future__ import annotations

from enum import Enum

from pydantic import model_validator

from .common import StrictModel
from .instruction import FenceKind, MemoryAccessKind
from .unknown import UnknownFact


class Ordering(str, Enum):
    # RELAXED 不提供跨线程排序。
    RELAXED = "Relaxed"
    # ACQUIRE 只约束后续访存。
    ACQUIRE = "Acquire"
    # RELEASE 只约束先前访存。
    RELEASE = "Release"
    # ACQ_REL 同时覆盖 acquire 与 release 方向。
    ACQ_REL = "AcqRel"
    # FULL 表示显式双向完整屏障。
    FULL = "Full"
    # TSO 表示普通 x86 访存受 source memory model 约束。
    TSO = "TSO"
    # FenceXY 保存显式 fence 的精确 predecessor/successor 集合。
    FENCE_RR = "FenceRR"
    FENCE_RW = "FenceRW"
    FENCE_WW = "FenceWW"
    FENCE_WR = "FenceWR"
    # UNKNOWN 表示实际实现或路径尚未封闭。
    UNKNOWN = "Unknown"


class SynchronizationKind(str, Enum):
    # THREAD_CREATE 发布父线程在创建前完成的初始化。
    THREAD_CREATE = "thread_create"
    # THREAD_JOIN 在返回前汇合目标线程的完成状态。
    THREAD_JOIN = "thread_join"
    # ACQUIRE 对应 lock 成功后的进入边界。
    ACQUIRE = "acquire"
    # RELEASE 对应 unlock 前的发布边界。
    RELEASE = "release"
    # CONDITION_WAIT 同时包含释放、等待和重新获取。
    CONDITION_WAIT = "condition_wait"
    # CONDITION_SIGNAL 唤醒至少一个 waiter。
    CONDITION_SIGNAL = "condition_signal"
    # CONDITION_BROADCAST 唤醒所有 waiter。
    CONDITION_BROADCAST = "condition_broadcast"
    # BARRIER 汇合参与线程的阶段边界。
    BARRIER = "barrier"
    # ONCE 发布一次性初始化的结果。
    ONCE = "once"


class SyncInstructionEvidence(StrictModel):
    # pc 把 ordering 结论定位到实际动态库指令。
    pc: int
    mnemonic: str
    op_str: str
    # LOCK 与 memory XCHG 分开记录，便于核对 DBT6 的两条原子翻译路径。
    has_lock_prefix: bool = False
    is_memory_xchg: bool = False
    # fence 记录显式 x86 fence，不能由 API 名称补造。
    fence: FenceKind | None = None
    # memory_access 暴露 plain store unlock 等弱路径。
    memory_access: MemoryAccessKind | None = None
    # translated_ordering 只按具体指令和 DBT contract 计算。
    translated_ordering: Ordering


class SynchronizationSummary(StrictModel):
    # api 与 kind 描述 pthread 层要求，不代表 target 已满足。
    api: str
    kind: SynchronizationKind
    required_ordering: Ordering
    # 路径、hash 和 Build ID 把摘要绑定到当前动态库版本。
    module_path: str
    module_sha256: str
    module_build_id: str | None = None
    # function_pc/size 限定本次检查的机器码范围。
    function_pc: int
    function_size: int
    # evidence 保存支持 target ordering 的具体指令。
    evidence: tuple[SyncInstructionEvidence, ...] = ()
    # 每条返回路径都参与交集，弱路径不能被强路径掩盖。
    return_path_orderings: tuple[Ordering, ...] = ()
    # target_ordering 是所有已恢复返回路径共同拥有的下界。
    target_ordering: Ordering
    # complete=False 时后续 proof 只能传播 Unknown，不能使用强摘要。
    complete: bool
    reason: str | None = None
    unknowns: tuple[UnknownFact, ...] = ()

    @model_validator(mode="after")
    def require_incomplete_reason(self) -> "SynchronizationSummary":
        if not self.complete and not self.reason:
            raise ValueError("incomplete synchronization summary requires a reason")
        return self


class SynchronizationReport(StrictModel):
    # schema_version 防止旧摘要被新 proof 层直接接受。
    schema_version: int = 1
    # contract_version 绑定生成 translated_ordering 时使用的 DBT 规则。
    contract_version: str
    # library_path/hash 绑定所有函数摘要所属的实际动态库。
    library_path: str
    library_sha256: str
    # summaries 可含同名版本化实现，避免任选一个而漏掉 loader 可能绑定的版本。
    summaries: tuple[SynchronizationSummary, ...] = ()
    # unknowns 汇总缺失符号、反汇编缺口和未组合调用路径。
    unknowns: tuple[UnknownFact, ...] = ()
