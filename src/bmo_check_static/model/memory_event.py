from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field

from .common import StrictModel
from .sync import Ordering
from .unknown import UnknownFact


class AddressKind(str, Enum):
    # GLOBAL 是 ELF 固定对象或绝对地址。
    GLOBAL = "Global"
    # TLS 通过 fs/gs 访问每线程存储。
    TLS = "TLS"
    # STACK 以具体函数 frame 和常量偏移标识。
    STACK = "Stack"
    # HEAP 需要绑定 allocation site；当前无法恢复时不能使用。
    HEAP = "Heap"
    # AFFINE 保存尚需 bounds 证明的线性地址式。
    AFFINE = "Affine"
    # UNKNOWN 可以与任何共享对象 MayAlias。
    UNKNOWN = "Unknown"


class AbstractAddress(StrictModel):
    # kind 决定哪些别名证明允许使用；Unknown 不能被默认成 NoAlias。
    kind: AddressKind
    # base 标识 global symbol、TLS slot、frame 或 allocation site。
    base: str | None = None
    # offset 是相对 base 的常量字节偏移。
    offset: int | None = None
    # expression 保存尚未完全求值的寄存器或仿射地址式。
    expression: str | None = None
    # thread_coefficient 描述 tid 对地址的线性贡献。
    thread_coefficient: int | None = None
    # index_coefficient 描述循环下标对地址的线性贡献。
    index_coefficient: int | None = None
    # index bounds 必须同时存在，分片证明才可封闭写集合。
    index_lower: int | None = None
    index_upper: int | None = None
    # thread bounds 来自受约束的执行配置，而不是一次 profile。
    thread_lower: int | None = None
    thread_upper: int | None = None
    # provenance 保存地址分类依赖的原始 operand 和二进制事实。
    provenance: dict[str, Any] = Field(default_factory=dict)


class EventKind(str, Enum):
    # LOAD 读取普通内存。
    LOAD = "Load"
    # STORE 写入普通内存。
    STORE = "Store"
    # ATOMIC_RMW 只来自 LOCK 或 memory XCHG 事实。
    ATOMIC_RMW = "AtomicRMW"
    # FENCE 保存显式 x86 fence。
    FENCE = "Fence"
    # THREAD_CREATE/JOIN 保存 pthread lifecycle 调用点。
    THREAD_CREATE = "ThreadCreate"
    THREAD_JOIN = "ThreadJoin"
    # ACQUIRE/RELEASE/BARRIER 需要具体动态库摘要支持。
    ACQUIRE = "Acquire"
    RELEASE = "Release"
    BARRIER = "Barrier"
    # OPAQUE_CALL 表示 callee memory effect 没有闭合。
    OPAQUE_CALL = "OpaqueCall"
    # SYSCALL 在缺少 syscall summary 时保留未知 effect。
    SYSCALL = "Syscall"
    # UNKNOWN_MEMORY_EFFECT 是失败和不可达代码缺口的哨兵。
    UNKNOWN_MEMORY_EFFECT = "UnknownMemoryEffect"


class MemoryEvent(StrictModel):
    # id 在同一报告内稳定标识一个 role 下的一个内存 effect。
    id: str
    # module 与 module_sha256 防止事件被复用到另一版 ELF。
    module: str
    module_sha256: str
    # pc 指向产生 effect 的 x86 指令。
    pc: int
    # block_pc 让 program-order 边回到 CFG block。
    block_pc: int | None = None
    function: str | None = None
    function_pc: int | None = None
    # kind 区分普通、原子、生命周期和未知 effect。
    kind: EventKind
    # address=None 只允许 fence/lifecycle 等不访问具体对象的事件。
    address: AbstractAddress | None = None
    size: int | None = None
    # source/target ordering 分别来自 x86 事实和 DBT contract。
    source_ordering: Ordering = Ordering.UNKNOWN
    target_ordering: Ordering = Ordering.UNKNOWN
    # thread_role 缺失必须伴随 Unknown，不能当成单线程事件。
    thread_role: str | None = None
    guard: str | None = None
    # operand_index 区分一条指令的多个内存 operand/effect。
    operand_index: int | None = None
    # provenance 保留 raw bytes、mnemonic 和 DBT rule。
    provenance: dict[str, Any] = Field(default_factory=dict)


class ProgramOrderEdge(StrictModel):
    # source/target 是同一 thread role 上可能连续执行的事件。
    source_event: str
    target_event: str
    # thread_role 防止跨角色边被误当成程序顺序。
    thread_role: str
    # evidence 说明边来自块内顺序还是 CFG successor。
    evidence: str


class MemoryEventReport(StrictModel):
    # module_path/hash 绑定本次事件提取的主 ELF。
    module_path: str
    module_sha256: str
    # events 包含未知 effect；失败不能返回看似完整的空集合。
    events: tuple[MemoryEvent, ...] = ()
    # program_order 只保存 CFG 能支持的边，不按 PC 猜跨分支顺序。
    program_order: tuple[ProgramOrderEdge, ...] = ()
    # unknowns 传播地址、角色和不透明调用缺口。
    unknowns: tuple[UnknownFact, ...] = ()
