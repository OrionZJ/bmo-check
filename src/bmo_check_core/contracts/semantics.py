"""memory-order primitive 的稳定边界。

这里先定义 primitive 的身份，不实现任一路由的排序规则。static、dynamic
和独立 oracle 必须先用同一个身份描述固定执行，才能把差异报告为语义漂移；
本模块故意不返回 ``SAFE``、``TRACE_SAFE`` 或任何具体 legality 结论。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RangeRelation(StrEnum):
    """两个带对象身份的字节范围之间的唯一关系。"""

    # 两个范围没有共享字节，或属于不同 allocation/object。
    DISJOINT = "disjoint"
    # 两个范围覆盖同一对象上的完全相同字节。
    EXACT = "exact"
    # 左范围覆盖右范围，但两者不是完全相同的范围。
    LEFT_CONTAINS_RIGHT = "left_contains_right"
    # 右范围覆盖左范围，但两者不是完全相同的范围。
    RIGHT_CONTAINS_LEFT = "right_contains_left"
    # 两个范围只部分相交，不能按任一完整对象处理。
    PARTIAL_OVERLAP = "partial_overlap"


class MemoryAccessKind(StrEnum):
    """RU1.3 characterization 支持的普通内存操作类别。"""

    # Load 从范围读取值。
    LOAD = "load"
    # Store 向范围写入值。
    STORE = "store"
    # RMW 同时读写范围，后续 atomic boundary 单独建模。
    RMW = "rmw"


@dataclass(frozen=True, slots=True)
class AccessRange:
    """带对象身份的精确字节区间。

    ``object_id`` 与 ``offset`` 必须同时参与比较。只比较数值地址会把
    地址复用或不同 allocation 错误合并；只比较 object_id 又会把字段
    之间的 partial overlap 错误扩大成整个对象冲突。
    """

    # object_id 标识 allocation/lifetime，而不是一次遍历中的临时行号。
    object_id: str
    # offset 是对象内的起始字节位置。
    offset: int
    # size 是本次访问覆盖的字节数，必须为正。
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.object_id, str) or not self.object_id or "\x00" in self.object_id:
            raise ValueError("object_id must be a non-empty string")
        if isinstance(self.offset, bool) or not isinstance(self.offset, int) or self.offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size <= 0:
            raise ValueError("size must be a positive integer")

    @property
    def end(self) -> int:
        """返回不包含在区间内的结束偏移。"""

        return self.offset + self.size


@dataclass(frozen=True, slots=True)
class MemoryOperation:
    """固定执行 characterization 使用的普通访存事实。"""

    # event_id 绑定同一固定执行中的操作，而不是一次遍历的数组下标。
    event_id: str
    # thread_id 区分程序顺序和跨线程关系。
    thread_id: str
    # sequence 是该线程内的程序顺序位置。
    sequence: int
    # access 是带 object identity 的精确字节范围。
    access: AccessRange
    # kind 区分 Load、Store 和尚未展开的 RMW。
    kind: MemoryAccessKind

    def __post_init__(self) -> None:
        for field in ("event_id", "thread_id"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{field} must be a non-empty string")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise ValueError("sequence must be an integer")


def source_ppo_preserved(before: MemoryOperation, after: MemoryOperation) -> bool:
    """判断普通操作是否属于 x86-TSO 的保留程序顺序。

    Store→Load 只有在访问范围不重叠时允许通过 store buffer 越过；同址
    forwarding 仍保留顺序。Fence、LOCK/XCHG 和同步事件不在这个窄接口内，
    不能借它们的缺省值生成 ordering。
    """

    if before.thread_id != after.thread_id or before.sequence >= after.sequence:
        return False
    if before.kind is MemoryAccessKind.STORE and after.kind is MemoryAccessKind.LOAD:
        return ranges_overlap(before.access, after.access)
    return True


def relate_ranges(left: AccessRange, right: AccessRange) -> RangeRelation:
    """按对象身份和精确字节边界分类两个访问范围。"""

    if left.object_id != right.object_id:
        return RangeRelation.DISJOINT
    if left.end <= right.offset or right.end <= left.offset:
        return RangeRelation.DISJOINT
    if left.offset == right.offset and left.end == right.end:
        return RangeRelation.EXACT
    if left.offset <= right.offset and left.end >= right.end:
        return RangeRelation.LEFT_CONTAINS_RIGHT
    if right.offset <= left.offset and right.end >= left.end:
        return RangeRelation.RIGHT_CONTAINS_LEFT
    return RangeRelation.PARTIAL_OVERLAP


def ranges_overlap(left: AccessRange, right: AccessRange) -> bool:
    """只把同一对象上共享至少一个字节的范围视为相交。"""

    return relate_ranges(left, right) is not RangeRelation.DISJOINT


class SemanticPrimitive(StrEnum):
    """RU1 需要独立比较的最小关系单元。"""

    # PPO 是同一线程内的保留程序顺序；不能和一次观测到的执行顺序混同。
    PPO = "ppo"
    # SAME_ADDRESS 描述重叠字节上的地址顺序，不能用 allocation 身份代替。
    SAME_ADDRESS = "same_address"
    # READ_FROM 描述一次读取选择哪个写入，不表示该选择一定可行。
    READ_FROM = "read_from"
    # COHERENCE 描述同一地址写入的全序候选，缺一对时不能闭合执行。
    COHERENCE = "coherence"
    # FROM_READ 描述读取之后仍可见的更晚写入，必须由 rf/co 一起推导。
    FROM_READ = "from_read"
    # EXPLICIT_FENCE 表示 LFENCE/SFENCE/MFENCE 的显式边界。
    EXPLICIT_FENCE = "explicit_fence"
    # ATOMIC_BOUNDARY 表示 LOCK/XCHG 等原子 lowering 的不可跨越边界。
    ATOMIC_BOUNDARY = "atomic_boundary"
    # SYNCHRONIZATION 表示锁、join、futex 等同步事件的已证明边。
    SYNCHRONIZATION = "synchronization"


@dataclass(frozen=True, slots=True)
class SemanticPrimitiveRef:
    """固定执行 characterization 使用的 primitive 身份。

    该值对象只绑定模型和 DBT contract 的版本；它不携带事件列表、观测值
    或 proof fact，避免测试 fixture 反向成为 verifier 的证据来源。
    """

    primitive: SemanticPrimitive
    source_model: str
    target_model: str
    contract_version: str

    def __post_init__(self) -> None:
        for field in ("source_model", "target_model", "contract_version"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{field} must be a non-empty string")


__all__ = [
    "AccessRange",
    "MemoryAccessKind",
    "MemoryOperation",
    "RangeRelation",
    "SemanticPrimitive",
    "SemanticPrimitiveRef",
    "ranges_overlap",
    "relate_ranges",
    "source_ppo_preserved",
]
