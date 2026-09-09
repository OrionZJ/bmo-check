from __future__ import annotations

from enum import Enum

from pydantic import Field, model_validator

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


class PartitionHint(StrictModel):
    # worker_pc/loop_pc 只定位待验证的机器码范围，不直接批准分片。
    worker_pc: int
    loop_pc: int
    # 两个 global PC 提供程序读取 N/T 的具体位置。
    item_count_pc: int
    thread_count_pc: int
    # start/end/induction_offset 绑定 worker frame 中的半开区间和归纳变量。
    start_offset: int
    end_offset: int
    induction_offset: int
    # item_count 是当前执行输入事实；thread_count 使用 benchmark 的实际线程参数。
    item_count: int = Field(gt=0)
    # object_base/element_size 将已证明的循环区间绑定到具体数组地址式。
    object_base: str
    element_size: int = Field(gt=0)


class LifecycleHint(StrictModel):
    # start_pc 从线程创建循环已完成输入准备的位置开始，避免符号执行 I/O。
    start_pc: int
    # post_join_pc 是只有等待循环结束后才能到达的第一条指令。
    post_join_pc: int
    # create_pc/join_pc 指向主 ELF 中的 pthread PLT 入口。
    create_pc: int
    join_pc: int
    # thread_count_pc 让证明器写入全局线程数；栈变量用下面的 offset。
    thread_count_pc: int | None = None
    # thread_count_stack_offset 绑定 rbp 相对的线程数槽位，避免把栈槽当全局地址。
    thread_count_stack_offset: int | None = None
    # frame_pointer_offsets 列出前缀已分配、后续循环会读取的指针栈槽。
    frame_pointer_offsets: tuple[int, ...] = ()
    # global_pointer_values 给从中途入口开始的证明补上已经完成的全局分配。
    # 每个值都绑定本 ELF 的 offset；不提供时，未知全局指针不能被当成唯一句柄槽。
    global_pointer_values: tuple[tuple[int, int], ...] = ()
    # stack_scalar_values 给中途入口的循环计数器绑定已知整数；它们不能
    # 复用 frame_pointer_offsets 的指针宽度，否则边界比较会保持未知。
    stack_scalar_values: tuple[tuple[int, int], ...] = ()
    # worker_argument_base 可显式绑定 allocation site；缺失时生命周期证明生成本地对象名。
    worker_argument_base: str | None = None
    # worker_argument_alias_base 只给共享 worker 参数命名，供地址传播跨过
    # pthread_create 入口；它不声明不同线程拿到的是不同对象，也不能触发分片剪枝。
    worker_argument_alias_base: str | None = None
    # assume_success 明确限定只认证 pthread create/join 均成功的执行。
    assume_success: bool = False

    @model_validator(mode="after")
    def require_thread_count_location(self) -> "LifecycleHint":
        if (self.thread_count_pc is None) == (
            self.thread_count_stack_offset is None
        ):
            raise ValueError(
                "lifecycle hint must specify exactly one thread-count location"
            )
        return self


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
    # partition_hints 只提供符号执行入口；证明失败时必须保留 Unknown。
    partition_hints: tuple[PartitionHint, ...] = ()
    # lifecycle_hint 只定位机器码循环；证明器仍需逐个匹配 create/join handle。
    lifecycle_hint: LifecycleHint | None = None
    # normal_completion_only 限定证书只覆盖能正常返回的路径。
    # assert、stack check 等必定终止的分支不能污染成功执行的通信图。
    normal_completion_only: bool = False


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
