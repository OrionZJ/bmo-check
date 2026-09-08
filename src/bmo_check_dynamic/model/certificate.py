from __future__ import annotations

from enum import Enum

from pydantic import Field, model_validator

from .manifest import BinaryFingerprint, StrictModel


class TraceVerdict(str, Enum):
    # TRACE_SAFE 只覆盖证书绑定的事件骨架，不能外推到其他输入或路径。
    TRACE_SAFE = "TRACE_SAFE"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    UNKNOWN = "UNKNOWN"


class TraceScope(StrictModel):
    trace_ids: tuple[str, ...]
    trace_sha256: tuple[str, ...]
    executable: BinaryFingerprint
    libraries: tuple[BinaryFingerprint, ...] = ()
    commands: tuple[tuple[str, ...], ...]
    working_directories: tuple[str, ...]
    # full 检查所有模块；application 只把主 ELF 的普通访存交给求解器。
    analysis_scope: str = "full"
    limitation: str = (
        "结论只覆盖已记录的线程内事件、实际地址和控制流骨架；"
        "不覆盖未执行路径、其他输入或未来调度。"
    )


class ReadFromWitness(StrictModel):
    # read_event 标识取得这些字节的 Load/RMW。
    read_event: str
    # write_event 为 None 时，这个片段读取初始值。
    write_event: str | None
    # address/size 精确标出宽 Load 中由该来源提供的片段。
    address: int
    size: int


class CandidateWitness(StrictModel):
    window_id: str
    read_from: tuple[ReadFromWitness, ...] = ()
    coherence: tuple[tuple[str, str], ...] = ()
    source_cycle: tuple[str, ...] = ()
    validated: bool = False
    reason: str


class WindowResult(StrictModel):
    window_id: str
    event_ids: tuple[str, ...]
    examined_executions: int = 0
    status: str
    reason: str
    witness: CandidateWitness | None = None


class ApplicationPartitionEvidence(StrictModel):
    # status=safe 只说明主模块的 worker 普通写互不重叠，不能替代库窗口证明。
    status: str
    # module_start 是本次 ASLR 映射的起点，筛出主模块发出的访存。
    module_start: int = 0
    # module_end 截止模块范围，避免把紧邻的运行库访问误算成应用输出。
    module_end: int = 0
    # main_thread 单独检查 worker 存活期间的并发访问。
    main_thread: int | None = None
    # worker_threads 是参与两两范围相交检查的线程集合。
    worker_threads: tuple[int, ...] = ()
    # 只读重叠不会产生写传播问题，但保留计数便于解释共享输入。
    readonly_shared_ranges: int = 0
    # worker 写范围一旦相交，就不能用“分离输出”关闭该子问题。
    worker_conflicting_ranges: int = 0
    # 主线程与存活 worker 冲突时，也不能把输出视为线程私有。
    concurrent_main_conflicts: int = 0
    # reasons 说明哪个条件阻止应用分区被标记为 safe。
    reasons: tuple[str, ...] = ()


class DynamicCertificate(StrictModel):
    schema_version: str = "1.1"
    verdict: TraceVerdict
    scope: TraceScope
    dbt_contract_sha256: str
    analyzer_version: str
    trace_complete: bool
    event_count: int
    thread_count: int
    object_count: int
    unique_pc_count: int
    # communication_edge_count 记录精确地址相交得到的原始候选数量。
    communication_edge_count: int
    # application scope 丢弃的边仍计入上面的原始数量，便于审计运行库契约。
    external_runtime_edge_count: int = 0
    indirect_target_count: int
    # 分区证据帮助解释应用访问；整体验证仍由所有 windows 决定。
    application_partition: ApplicationPartitionEvidence | None = None
    windows: tuple[WindowResult, ...] = ()
    unknown_reasons: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()

    @model_validator(mode="after")
    def keep_verdict_strict(self) -> "DynamicCertificate":
        if self.verdict == TraceVerdict.TRACE_SAFE:
            if not self.trace_complete or self.unknown_reasons:
                raise ValueError("TRACE_SAFE requires a complete trace without Unknowns")
            if any(window.status != "safe" for window in self.windows):
                raise ValueError("TRACE_SAFE requires every window to be safe")
        if self.verdict == TraceVerdict.COUNTEREXAMPLE:
            if not self.trace_complete or self.unknown_reasons:
                raise ValueError("COUNTEREXAMPLE requires complete evidence without Unknowns")
            if not any(
                window.witness is not None and window.witness.validated
                for window in self.windows
            ):
                raise ValueError("COUNTEREXAMPLE requires a validated witness")
        return self
