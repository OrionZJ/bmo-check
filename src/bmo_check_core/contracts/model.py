"""DBT memory-order contract 的 canonical 值对象。

这里保存 lowering 的语义，不保存 YAML/Pydantic 的输入形状。静态和动态
入口可以各自解析配置，但最终只能把同一组 typed contract 字段交给 proof
和 certificate 层；否则同一个 ``contract_version`` 可能被两条路线解释成
不同的排序。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ContractError(ValueError):
    """contract 字段缺少稳定语义或不满足 canonical 约束。"""


class TargetOrdering(StrEnum):
    # RELAXED 表示普通访存没有额外 aq/rl 或 Fence 排序。
    RELAXED = "relaxed"
    # ACQUIRE/RELEASE 描述单方向的 target ordering。
    ACQUIRE = "acquire"
    RELEASE = "release"
    # ACQ_REL 是 LOCK/XCHG 等原子边界常用的双向排序。
    ACQ_REL = "acq_rel"
    # FULL 表示完整 target 内存屏障或等价排序。
    FULL = "full"
    # UNKNOWN 只能导致不支持或 UNKNOWN，不能被当成 relaxed。
    UNKNOWN = "unknown"


class TargetFence(StrEnum):
    # 四个字段沿用 RISC-V fence 的 predecessor/successor 文本。
    RR = "r,r"
    RW = "r,w"
    WR = "w,r"
    WW = "w,w"
    RWRW = "rw,rw"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ContractIssue:
    # field 是 canonical 字段路径，不依赖输入文件中的字典顺序。
    field: str
    # actual/expected 使用稳定文本，供 CLI 和 Unknown 解释器引用。
    actual: str
    expected: str

    def render(self) -> str:
        return (
            f"unsupported DBT contract field {self.field}: "
            f"{self.actual!r} != {self.expected!r}"
        )


@dataclass(frozen=True, slots=True)
class TranslationContract:
    # 普通 load/store 的 lowering 是 mo-off 与其它模式的关键差异。
    plain_load: TargetOrdering
    plain_store: TargetOrdering
    # 原子和 XCHG 必须独立记录，不能把 LOCK 前缀误归入普通访存。
    lock_rmw: TargetOrdering
    memory_xchg: TargetOrdering
    # 显式 x86 fence 的 target 指令必须逐类绑定。
    lfence: TargetFence
    sfence: TargetFence
    mfence: TargetFence
    # syscall 不自动提供 guest 可见的排序；缺省 unknown 防止过度假设。
    syscall: TargetOrdering = TargetOrdering.UNKNOWN

    def __post_init__(self) -> None:
        for name in (
            "plain_load",
            "plain_store",
            "lock_rmw",
            "memory_xchg",
            "syscall",
        ):
            if not isinstance(getattr(self, name), TargetOrdering):
                raise ContractError(f"{name} must be a TargetOrdering")
        for name in ("lfence", "sfence", "mfence"):
            if not isinstance(getattr(self, name), TargetFence):
                raise ContractError(f"{name} must be a TargetFence")


@dataclass(frozen=True, slots=True)
class MemoryOrderContract:
    # schema_version 让同名 contract 的字段解释可以显式演进。
    schema_version: int
    # contract_version 绑定具体 DBT lowering 规则，而不是抽象内存模型。
    contract_version: str
    # arch/model 分开保存，避免仅凭 arch 猜排序规则。
    guest_arch: str
    guest_memory_model: str
    host_arch: str
    host_memory_model: str
    translation: TranslationContract

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, int) or isinstance(self.schema_version, bool):
            raise ContractError("schema_version must be an integer")
        if self.schema_version < 1:
            raise ContractError("schema_version must be positive")
        for name in (
            "contract_version",
            "guest_arch",
            "guest_memory_model",
            "host_arch",
            "host_memory_model",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ContractError(f"{name} must be a non-empty string")
        if not isinstance(self.translation, TranslationContract):
            raise ContractError("translation must be a TranslationContract")

    @classmethod
    def from_wire(
        cls,
        *,
        schema_version: int,
        contract_version: str,
        guest_arch: str,
        guest_memory_model: str,
        host_arch: str,
        host_memory_model: str,
        plain_load: str,
        plain_store: str,
        lock_rmw: str,
        memory_xchg: str,
        lfence: str,
        sfence: str,
        mfence: str,
        syscall: str = TargetOrdering.UNKNOWN.value,
    ) -> "MemoryOrderContract":
        """把外部文本一次性归一化，避免各入口各自解释同一字段。"""

        def ordering(field: str, value: str) -> TargetOrdering:
            try:
                return TargetOrdering(value)
            except ValueError as error:
                raise ContractError(
                    ContractIssue(field, value, "known target ordering").render()
                ) from error

        def fence(field: str, value: str) -> TargetFence:
            try:
                return TargetFence(value)
            except ValueError as error:
                raise ContractError(
                    ContractIssue(field, value, "known target fence").render()
                ) from error

        return cls(
            schema_version=schema_version,
            contract_version=contract_version,
            guest_arch=guest_arch,
            guest_memory_model=guest_memory_model,
            host_arch=host_arch,
            host_memory_model=host_memory_model,
            translation=TranslationContract(
                plain_load=ordering("translation.plain_load", plain_load),
                plain_store=ordering("translation.plain_store", plain_store),
                lock_rmw=ordering("translation.lock_rmw", lock_rmw),
                memory_xchg=ordering("translation.memory_xchg", memory_xchg),
                lfence=fence("translation.lfence", lfence),
                sfence=fence("translation.sfence", sfence),
                mfence=fence("translation.mfence", mfence),
                syscall=ordering("translation.syscall", syscall),
            ),
        )

    def unsupported_field(self) -> ContractIssue | None:
        """返回首个超出当前 source/target checker 支持集的字段。"""

        expected = (
            ("guest.arch", self.guest_arch, "x86_64"),
            ("guest.memory_model", self.guest_memory_model, "x86_tso"),
            ("host.arch", self.host_arch, "riscv64"),
            ("host.memory_model", self.host_memory_model, "rvwmo"),
            ("translation.plain_load", self.translation.plain_load.value, "relaxed"),
            ("translation.plain_store", self.translation.plain_store.value, "relaxed"),
            ("translation.lock_rmw", self.translation.lock_rmw.value, "acq_rel"),
            ("translation.memory_xchg", self.translation.memory_xchg.value, "acq_rel"),
            ("translation.lfence", self.translation.lfence.value, "r,r"),
            ("translation.sfence", self.translation.sfence.value, "w,w"),
            ("translation.mfence", self.translation.mfence.value, "rw,rw"),
        )
        for field, actual, wanted in expected:
            if actual != wanted:
                return ContractIssue(field, actual, wanted)
        return None


__all__ = [
    "ContractError",
    "ContractIssue",
    "MemoryOrderContract",
    "TargetFence",
    "TargetOrdering",
    "TranslationContract",
]
