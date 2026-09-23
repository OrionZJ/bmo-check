from __future__ import annotations

import re
from enum import Enum

from bmo_check_core import TraceId
from bmo_check_core import UnknownKind
from pydantic import Field, model_validator

from .manifest import BinaryFingerprint, StrictModel
from .coverage import TraceCoverage


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


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


class DynamicCertificateBinding(StrictModel):
    """动态确定性证书必须绑定的不可变输入摘要。

    scope 和 coverage 记录具体对象与事件全集；这里再绑定生成这些事实的
    manifest、分析配置和工具版本。少一层时，独立 verifier 不能判断证书
    是否来自同一条 trace 或同一组资源边界，只能退回 UNKNOWN。
    """

    schema_version: str = "dynamic-binding-v1"
    manifest_sha256: str
    trace_subject: str
    trace_sha256: str
    executable_sha256: str
    library_closure_sha256: str
    environment_sha256: str
    dbt_contract_sha256: str
    config_sha256: str
    analyzer_version: str
    dynamorio_version: str
    client_version: str

    @model_validator(mode="after")
    def validate_binding(self) -> "DynamicCertificateBinding":
        for name in (
            "manifest_sha256",
            "trace_sha256",
            "executable_sha256",
            "library_closure_sha256",
            "environment_sha256",
            "dbt_contract_sha256",
            "config_sha256",
        ):
            _digest(name, getattr(self, name))
        try:
            TraceId.from_value(self.trace_subject)
        except (TypeError, ValueError) as error:
            raise ValueError("trace_subject must be a TraceId") from error
        for name in (
            "schema_version",
            "analyzer_version",
            "dynamorio_version",
            "client_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{name} must be a non-empty string")
        return self


class ReadFromWitness(StrictModel):
    # read_event 标识取得这些字节的 Load/RMW。
    read_event: str
    # write_event 为 None 时，这个片段读取初始值。
    write_event: str | None
    # address/size 精确标出宽 Load 中由该来源提供的片段。
    address: int
    size: int


class SymbolicModelVariable(StrictModel):
    """P16 shadow 查询中一个具名 Z3 变量及其模型取值。"""

    # semantic_id 把 Z3 内部编号映射回访存、排序或 cycle decision。
    semantic_id: str
    # smt_name 保留求解器里的变量名，便于独立检查模型快照。
    smt_name: str
    # sort 和 value 按 Z3 的稳定文本形式保存，不重建 solver object。
    sort: str
    value: str


class SymbolicModelSnapshot(StrictModel):
    """只用于 shadow replay 的完整模型快照，不是正式反例证书。"""

    schema_version: str = "local-symbolic-model-v1"
    variables: tuple[SymbolicModelVariable, ...]
    # expected_variable_count 由 encoder 声明，replay 会重新推导并核对。
    expected_variable_count: int
    # complete=false 时不得用这份快照验证 FEASIBLE。
    complete: bool
    # digest 绑定变量 identity、sort 和取值，防止报告被静默改写。
    digest: str


class CandidateWitness(StrictModel):
    window_id: str
    read_from: tuple[ReadFromWitness, ...] = ()
    coherence: tuple[tuple[str, str], ...] = ()
    source_cycle: tuple[str, ...] = ()
    # P16 固定复现才保存完整模型；常规运行不额外复制 Z3 模型。
    model_snapshot: SymbolicModelSnapshot | None = None
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
    # 旧手工/工作流 fixture 默认仍是 legacy；producer 要显式写 v2 才能 replay。
    schema_version: str = "1.2"
    verdict: TraceVerdict
    scope: TraceScope
    dbt_contract_sha256: str
    analyzer_version: str
    # 这里只表示 trace 记录本身通过结构校验；诊断 snapshot 还要绑定每个站点的模块身份。
    trace_complete: bool
    event_count: int
    thread_count: int
    object_count: int
    unique_pc_count: int
    # 完整扫描时记录精确相交边数；超预算时记录扫描到的数量并返回 UNKNOWN。
    communication_edge_count: int
    # application scope 排除两端都在外部模块的边；扫描完整时此值精确。
    external_runtime_edge_count: int = 0
    # false 表示通信图尚未完整扫描，或边扫描被资源上限截断。
    communication_edges_complete: bool = True
    indirect_target_count: int
    # 分区证据帮助解释应用访问；整体验证仍由所有 windows 决定。
    application_partition: ApplicationPartitionEvidence | None = None
    windows: tuple[WindowResult, ...] = ()
    # unknown_kinds 给 machine-readable gate 一个稳定分类；unknown_reasons
    # 继续保留具体上下文，但不能单靠自由文本决定是否允许 TRACE_SAFE。
    unknown_kinds: tuple[UnknownKind, ...] = ()
    unknown_reasons: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    # RU5 coverage ledger；旧手工 certificate 缺少它时仍只能作为 legacy reader。
    coverage: TraceCoverage | None = None
    # 顶层 binding 把 manifest、配置和工具版本固定到同一份证书。
    binding: DynamicCertificateBinding | None = None

    @model_validator(mode="after")
    def keep_verdict_strict(self) -> "DynamicCertificate":
        if self.verdict == TraceVerdict.TRACE_SAFE:
            if self.schema_version == "dynamic-certificate-v2" and self.binding is None:
                raise ValueError(
                    "TRACE_SAFE requires dynamic-certificate-v2 immutable binding"
                )
            if not self.trace_complete or self.unknown_reasons:
                raise ValueError("TRACE_SAFE requires a complete trace without Unknowns")
            if self.unknown_kinds:
                raise ValueError("TRACE_SAFE cannot contain typed Unknowns")
            if not self.communication_edges_complete:
                raise ValueError(
                    "TRACE_SAFE requires a complete communication graph"
                )
            if any(window.status != "safe" for window in self.windows):
                raise ValueError("TRACE_SAFE requires every window to be safe")
        if self.verdict == TraceVerdict.COUNTEREXAMPLE:
            if self.schema_version == "dynamic-certificate-v2" and self.binding is None:
                raise ValueError(
                    "COUNTEREXAMPLE requires dynamic-certificate-v2 immutable binding"
                )
            if not self.trace_complete or self.unknown_reasons:
                raise ValueError("COUNTEREXAMPLE requires complete evidence without Unknowns")
            if self.unknown_kinds or not self.communication_edges_complete:
                raise ValueError(
                    "COUNTEREXAMPLE requires complete communication evidence"
                )
            if not any(
                window.witness is not None and window.witness.validated
                for window in self.windows
            ):
                raise ValueError("COUNTEREXAMPLE requires a validated witness")
        return self
