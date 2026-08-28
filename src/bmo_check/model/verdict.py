from enum import Enum

from pydantic import Field, model_validator

from .common import StrictModel
from .memory_event import EventKind
from .sync import Ordering


class Verdict(str, Enum):
    # SAFE 只用于不依赖有限展开、且全部 proof obligation 已闭合的结论。
    SAFE = "SAFE"
    # UNKNOWN 覆盖超界、超时、不支持输入和 bounded no-counterexample。
    UNKNOWN = "UNKNOWN"
    # COUNTEREXAMPLE 必须同时携带 target 可行、source 不可行的执行。
    COUNTEREXAMPLE = "COUNTEREXAMPLE"


class CheckerConclusion(str, Enum):
    # STRUCTURAL_SAFE 表示共享通信已经被 proof object 全部消除。
    STRUCTURAL_SAFE = "StructuralSafe"
    # TARGET_ONLY 表示同一 rf/co 执行只被 target 接受。
    TARGET_ONLY = "TargetOnlyExecution"
    # BOUNDED_EXHAUSTED 不能证明界限外不存在反例。
    BOUNDED_EXHAUSTED = "BoundedNoCounterexample"
    # INCOMPLETE 表示输入、模型支持集或 solver 没有闭合。
    INCOMPLETE = "Incomplete"


class CheckerLimits(StrictModel):
    # max_events 限制一次送入 SMT 的静态事件数。
    max_events: int = Field(default=24, ge=1)
    # max_threads 限制有限执行中不同 thread role 的数量。
    max_threads: int = Field(default=8, ge=1)
    # max_executions 限制枚举的 target rf/co 关系数。
    max_executions: int = Field(default=4096, ge=1)
    # timeout_ms 同时约束每次 solver 调用和整次 checker。
    timeout_ms: int = Field(default=10_000, ge=1)


class CounterexampleEvent(StrictModel):
    # event_id 绑定 shared-memory slice 中的原事件。
    event_id: str
    # thread_role 指明谁执行该事件。
    thread_role: str
    # module/hash/pc 防止解释报告指向另一版二进制。
    module: str
    module_sha256: str
    pc: int
    # kind 与 object_id 描述这次通信访问了什么。
    kind: EventKind
    object_id: str | None = None
    # source/target ordering 直接展示 DBT lowering 的差异。
    source_ordering: Ordering
    target_ordering: Ordering


class ReadFromChoice(StrictModel):
    # load_event 是观察结果的读事件。
    load_event: str
    # store_event=None 表示读取该对象的初始写。
    store_event: str | None = None
    # object_id 让 initial write 也能准确归属到对象。
    object_id: str


class CoherenceChoice(StrictModel):
    # before_store/after_store 给出同一对象上的写入先后。
    before_store: str
    after_store: str
    # object_id 防止跨对象顺序被误读成 coherence。
    object_id: str


class CounterexampleTrace(StrictModel):
    # events 只列入反例关系涉及的有限事件。
    events: tuple[CounterexampleEvent, ...]
    # read_from 与 coherence 完整描述被比较的同一执行。
    read_from: tuple[ReadFromChoice, ...]
    coherence: tuple[CoherenceChoice, ...] = ()
    # source_cycle 是 x86-TSO 拒绝该执行的闭环证据。
    source_cycle: tuple[str, ...]
    # missing_ordering 说明 target 少了哪条 source preserved-order 边。
    missing_ordering: tuple[str, ...]

    @model_validator(mode="after")
    def require_source_rejection_evidence(self) -> "CounterexampleTrace":
        if len(self.source_cycle) < 2:
            raise ValueError("counterexample requires an x86-TSO rejection cycle")
        if not self.read_from:
            raise ValueError("counterexample requires at least one read-from choice")
        return self


class CheckerReport(StrictModel):
    # backend/version 固定本次结论使用的有限模型实现。
    backend: str
    backend_version: str
    # bounded 始终记录首版 checker 只搜索有限事件执行。
    bounded: bool = True
    # limits 是 certificate 的一部分，不能在复用时偷偷扩大或缩小。
    limits: CheckerLimits
    # conclusion 决定 verifier 可以映射到哪种最终 verdict。
    conclusion: CheckerConclusion
    # examined_executions 便于解释超界和性能退化。
    examined_executions: int = 0
    # reason 说明 UNKNOWN 或结构性 SAFE 的具体依据。
    reason: str
    # unsupported_events 保留阻止编码的事件 ID。
    unsupported_events: tuple[str, ...] = ()
    # assumptions 明示首版有限模型的支持范围。
    assumptions: tuple[str, ...] = ()
