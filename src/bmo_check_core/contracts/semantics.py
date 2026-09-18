"""memory-order primitive 的稳定边界。

这里先定义 primitive 的身份，不实现任一路由的排序规则。static、dynamic
和独立 oracle 必须先用同一个身份描述固定执行，才能把差异报告为语义漂移；
本模块故意不返回 ``SAFE``、``TRACE_SAFE`` 或任何具体 legality 结论。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


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


__all__ = ["SemanticPrimitive", "SemanticPrimitiveRef"]
