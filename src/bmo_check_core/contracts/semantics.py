"""memory-order primitive 的稳定边界。

这里先定义 primitive 的身份，不实现任一路由的排序规则。static、dynamic
和独立 oracle 必须先用同一个身份描述固定执行，才能把差异报告为语义漂移；
本模块故意不返回 ``SAFE``、``TRACE_SAFE`` 或任何具体 legality 结论。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

from ..identity import PropositionId


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


class RelationKind(StrEnum):
    """固定 execution 中三类内存关系的方向。"""

    # RF 从写入（或隐含初始写）指向读取。
    READ_FROM = "read_from"
    # CO 在同一对象范围的写入之间给出候选全序。
    COHERENCE = "coherence"
    # FR 从读取指向 coherence 中更晚的写入。
    FROM_READ = "from_read"


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


@dataclass(frozen=True, slots=True)
class MemoryRelation:
    """带端点事实的 RF/CO/FR 命题。

    ``MemoryOperation`` 身份和 ``RelationKind`` 必须同时保留。只保存两个
    event id 会把不同对象、不同宽度或不同关系方向错误合并；partial-width
    关系先保留为命题，但 exact-width checker 必须显式拒绝它。
    """

    # kind 是命题类型，不能由调用方所在的 tuple 字段隐式推断。
    kind: RelationKind
    # RF 可以从隐含初始写读取，因此 source 允许为 None。
    source: MemoryOperation | None
    # target 是关系的后端点；方向由 kind 固定。
    target: MemoryOperation

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RelationKind):
            raise ValueError("kind must be a RelationKind")
        if not isinstance(self.target, MemoryOperation):
            raise ValueError("target must be a MemoryOperation")
        if self.source is not None and not isinstance(self.source, MemoryOperation):
            raise ValueError("source must be a MemoryOperation or None")
        if self.source is not None and self.source.event_id == self.target.event_id:
            raise ValueError("relation endpoints must have distinct event ids")

        source_kinds = {
            RelationKind.READ_FROM: {MemoryAccessKind.STORE, MemoryAccessKind.RMW},
            RelationKind.COHERENCE: {MemoryAccessKind.STORE, MemoryAccessKind.RMW},
            RelationKind.FROM_READ: {MemoryAccessKind.LOAD, MemoryAccessKind.RMW},
        }
        target_kinds = {
            RelationKind.READ_FROM: {MemoryAccessKind.LOAD, MemoryAccessKind.RMW},
            RelationKind.COHERENCE: {MemoryAccessKind.STORE, MemoryAccessKind.RMW},
            RelationKind.FROM_READ: {MemoryAccessKind.STORE, MemoryAccessKind.RMW},
        }
        if self.target.kind not in target_kinds[self.kind]:
            raise ValueError(
                f"{self.kind.value} target must be a load/store-compatible operation"
            )
        if self.source is None:
            if self.kind is not RelationKind.READ_FROM:
                raise ValueError("only read_from may use an implicit initial write")
        elif self.source.kind not in source_kinds[self.kind]:
            raise ValueError(
                f"{self.kind.value} source has an incompatible access kind"
            )

    @property
    def range_relation(self) -> RangeRelation:
        """返回端点范围关系；初始写隐含覆盖 target 的同一 exact range。"""

        if self.source is None:
            return RangeRelation.EXACT
        return relate_ranges(self.source.access, self.target.access)

    @property
    def exact_width_supported(self) -> bool:
        """当前共同 checker 只接受 exact-width relation。"""

        return self.range_relation is RangeRelation.EXACT

    @property
    def proposition_key(self) -> tuple[object, ...]:
        """返回不依赖遍历顺序的关系命题身份。"""

        def operation_key(operation: MemoryOperation | None) -> tuple[object, ...] | None:
            if operation is None:
                return None
            return (
                operation.event_id,
                operation.access.object_id,
                operation.access.offset,
                operation.access.size,
            )

        return (
            self.kind.value,
            operation_key(self.source),
            operation_key(self.target),
        )

    @property
    def proposition_id(self) -> PropositionId:
        """把 proposition key 编码成可序列化、可重算的稳定 identity。"""

        def term(operation: MemoryOperation | None) -> str:
            if operation is None:
                return "initial"
            return json.dumps(
                (
                    operation.event_id,
                    operation.access.object_id,
                    operation.access.offset,
                    operation.access.size,
                ),
                ensure_ascii=True,
                separators=(",", ":"),
            )

        return PropositionId.from_parts(
            self.kind.value,
            (term(self.source), term(self.target)),
        )


@dataclass(frozen=True, slots=True)
class ExecutionRelations:
    """固定 execution 的 typed RF/CO/FR 集合，不执行模型 legality 判定。"""

    # 每个 load/RMW 至多绑定一个 RF 命题；完整性由上层 obligation 检查。
    read_from: tuple[MemoryRelation, ...] = ()
    # CO 和 FR 只记录命题，不把它们自动转成 ordering edge。
    coherence: tuple[MemoryRelation, ...] = ()
    from_read: tuple[MemoryRelation, ...] = ()

    def __post_init__(self) -> None:
        families = (
            ("read_from", self.read_from, RelationKind.READ_FROM),
            ("coherence", self.coherence, RelationKind.COHERENCE),
            ("from_read", self.from_read, RelationKind.FROM_READ),
        )
        seen: set[tuple[object, ...]] = set()
        for name, relations, expected_kind in families:
            if not isinstance(relations, tuple):
                raise ValueError(f"{name} must be a tuple of MemoryRelation")
            for relation in relations:
                if not isinstance(relation, MemoryRelation):
                    raise ValueError(f"{name} must contain MemoryRelation values")
                if relation.kind is not expected_kind:
                    raise ValueError(
                        f"{name} contains a {relation.kind.value} relation"
                    )
                if relation.proposition_key in seen:
                    raise ValueError("duplicate memory relation proposition")
                seen.add(relation.proposition_key)
        read_targets = [relation.target.event_id for relation in self.read_from]
        if len(read_targets) != len(set(read_targets)):
            raise ValueError("read_from must contain at most one source per target")

    def exact_width_issues(self) -> tuple[str, ...]:
        """列出无法进入共同 exact-width 子集的命题，供上层映射为 UNKNOWN。"""

        issues: list[str] = []
        for relation in (*self.read_from, *self.coherence, *self.from_read):
            if not relation.exact_width_supported:
                source = (
                    "initial"
                    if relation.source is None
                    else relation.source.event_id
                )
                issues.append(
                    f"{relation.kind.value}:{source}->{relation.target.event_id}:"
                    f"{relation.range_relation.value}"
                )
        return tuple(issues)

    @property
    def all_exact_width(self) -> bool:
        """只判断已提交命题的宽度，不声称 RF/CO/FR 集合完整。"""

        return not self.exact_width_issues()

    @property
    def proposition_ids(self) -> tuple[PropositionId, ...]:
        """返回排序后的命题身份；不表示 relation universe 已完整。"""

        relations = (*self.read_from, *self.coherence, *self.from_read)
        return tuple(
            sorted(
                (relation.proposition_id for relation in relations),
                key=lambda item: item.value,
            )
        )


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
    "MemoryRelation",
    "RangeRelation",
    "RelationKind",
    "ExecutionRelations",
    "SemanticPrimitive",
    "SemanticPrimitiveRef",
    "ranges_overlap",
    "relate_ranges",
    "source_ppo_preserved",
]
