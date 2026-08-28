from __future__ import annotations

from enum import Enum

from pydantic import Field

from .common import StrictModel
from .verdict import Verdict


class PruningLevel(str, Enum):
    # NONE 保留全部 MemoryEvent，作为消融基线。
    NONE = "none"
    # THREAD_LOCAL 只启用 TLS、唯一 main 和未逃逸栈证明。
    THREAD_LOCAL = "thread-local"
    # READ_ONLY 在 ThreadLocal 之上启用 create 前只写证明。
    READ_ONLY = "read-only"
    # DISJOINT 再启用有界仿射分片证明。
    DISJOINT = "disjoint"
    # ATOMIC_COVERED 最后启用具体 atomic/fence 覆盖证明。
    ATOMIC_COVERED = "atomic-covered"


class EvaluationStatus(str, Enum):
    # COMPLETE 表示所有消融证书均已写出。
    COMPLETE = "Complete"
    # RESOURCE_LIMIT 表示独立 worker 超过内存限制或被系统终止。
    RESOURCE_LIMIT = "ResourceLimit"
    # TIMEOUT 表示单 benchmark 前端超过墙钟上限。
    TIMEOUT = "Timeout"
    # FAILED 表示其他显式异常；不能伪装成 UNKNOWN verdict。
    FAILED = "Failed"


class RiskScreeningStatus(str, Enum):
    # PROVED_SAFE 复用严格 certificate SAFE。
    PROVED_SAFE = "ProvedSafe"
    # CONFIRMED_COUNTEREXAMPLE 复用完整 checker 的 target-only witness。
    CONFIRMED_COUNTEREXAMPLE = "ConfirmedCounterexample"
    # POTENTIAL_RISK 是闭合局部窗口中的弱序危险环，用于保守选择 FSM。
    POTENTIAL_RISK = "PotentialRisk"
    # NO_RISK_FOUND 只表示当前规则没找到，不能解释成形式化 SAFE。
    NO_RISK_FOUND = "NoRiskFound"


class RiskFinding(StrictModel):
    # kind 标识 message-publication 等可解释危险图形。
    kind: str
    # event_ids/pcs/roles 把筛查结果定位回具体二进制窗口。
    event_ids: tuple[str, ...]
    pcs: tuple[int, ...]
    roles: tuple[str, ...]
    # objects 保存通信两端的精确 alias class。
    objects: tuple[str, ...]
    # missing_orders 说明 x86 保留而 mo-off target 缺少的边。
    missing_orders: tuple[str, ...]
    # reason 明示它是局部风险还是完整反例。
    reason: str


class BenchmarkDefinition(StrictModel):
    # id 只标识报告行；分析器不得按它选择 verdict。
    id: str
    # executable/run_directory 都相对命令行给定的 PARSEC root。
    executable: str
    run_directory: str
    # argv 中的 {threads} 在建立 execution scope 前替换。
    argv: tuple[str, ...]
    # threads 是该评测配置的固定动态线程数。
    threads: int = Field(ge=1)
    # input_files 只在可选 native run 中复制或链接到临时目录。
    input_files: tuple[str, ...] = ()
    # output_files 与 expected hashes 独立于进程退出状态检查。
    output_files: tuple[str, ...] = ()
    expected_output_sha256: dict[str, str] = Field(default_factory=dict)


class EvaluationSuite(StrictModel):
    # schema 防止旧 suite 文件被新 runner 静默解释。
    schema_version: int = Field(default=1, validation_alias="schema")
    # name 标识这组输入规模和构建配置。
    name: str
    # benchmarks 是数据，不得被分析层用作特判开关。
    benchmarks: tuple[BenchmarkDefinition, ...]


class PhaseTimings(StrictModel):
    # recovery_seconds 覆盖 ELF closure、CFG、线程和同步摘要。
    recovery_seconds: float = 0.0
    # event_seconds 覆盖 MemoryEvent 与 program-order 恢复。
    event_seconds: float = 0.0
    # shared_state_seconds 覆盖 alias、escape 和 proof object 构建。
    shared_state_seconds: float = 0.0
    # slice_seconds 是当前消融级别重建 slice 的时间。
    slice_seconds: float = 0.0
    # checker_seconds 只统计 verifier/checker 与证书生成。
    checker_seconds: float = 0.0
    # screening_seconds 统计不受全局 Unknown 阻塞的局部危险环搜索。
    screening_seconds: float = 0.0


class AblationMeasurement(StrictModel):
    # level 指明当前允许使用哪些剪枝证明。
    level: PruningLevel
    # timings 分开记录共享前端与当前 slice/checker 开销。
    timings: PhaseTimings
    # 事件和 conflict 计数用于量化 slice 缩减。
    total_events: int
    remaining_events: int
    conflict_candidates: int
    # pruning_counts 按 ProofReason 统计实际移除事件。
    pruning_counts: dict[str, int] = Field(default_factory=dict)
    # checker_executions 与 verdict 来自证书，而非 benchmark 名称。
    checker_executions: int
    verdict: Verdict
    relevant_unknowns: int
    # screening_status/findings 与形式化 verdict 分开，避免 NO_RISK_FOUND 冒充 SAFE。
    screening_status: RiskScreeningStatus
    risk_findings: tuple[RiskFinding, ...] = ()
    # certificate 路径/hash 让汇总报告保持紧凑且可复核。
    certificate_file: str
    certificate_sha256: str


class OutputArtifactCheck(StrictModel):
    # path 是 suite 中声明的输出名。
    path: str
    # exists 与进程 exit_code 分开记录。
    exists: bool
    # sha256 只在文件确实生成时存在。
    sha256: str | None = None
    # expected_sha256 缺失表示只采集、不宣称内容正确。
    expected_sha256: str | None = None
    # matches_expected=None 表示 suite 没提供参考 hash。
    matches_expected: bool | None = None


class NativeRunMeasurement(StrictModel):
    # attempted=False 表示本次只评测静态 pipeline。
    attempted: bool = False
    # exit_code、timed_out 和 error 只描述原生程序执行结果。
    exit_code: int | None = None
    timed_out: bool = False
    error: str | None = None
    duration_seconds: float = 0.0
    # stdout/stderr hash 便于比较运行输出而不把大文本塞进报告。
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    # outputs 独立说明文件是否生成、是否匹配参考内容。
    outputs: tuple[OutputArtifactCheck, ...] = ()


class BenchmarkMeasurement(StrictModel):
    # benchmark_id 只关联 suite 配置和结果。
    benchmark_id: str
    # executable/argv/threads 固定本次证书的实际执行范围。
    executable: str
    executable_sha256: str | None = None
    argv: tuple[str, ...]
    threads: int
    # status/failure 区分分析器未完成与 verifier 给出 UNKNOWN。
    status: EvaluationStatus = EvaluationStatus.COMPLETE
    failure: str | None = None
    # ablations 按固定弱到强剪枝顺序输出。
    ablations: tuple[AblationMeasurement, ...] = ()
    # native_run 不参与 verdict，只用于工程回归对照。
    native_run: NativeRunMeasurement


class EvaluationReport(StrictModel):
    # schema_version 保护汇总格式。
    schema_version: int = 1
    # suite_name 与 roots 记录如何复现实验。
    suite_name: str
    parsec_root: str
    library_roots: tuple[str, ...]
    dbt_contract: str
    dbt_revision: str | None = None
    # benchmarks 保存每个程序的独立分析与原生运行结果。
    benchmarks: tuple[BenchmarkMeasurement, ...]
    # total_seconds 是整个批处理的墙钟时间。
    total_seconds: float
