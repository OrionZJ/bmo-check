from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag


class EventKind(IntEnum):
    # 普通访存参与 mo-off 差分检查。
    LOAD = 1
    STORE = 2
    # 原子区已有 LR/SC 排序，验证器只把它当不可跨越边界。
    ATOMIC_RMW = 3
    LFENCE = 4
    SFENCE = 5
    MFENCE = 6
    THREAD_START = 10
    THREAD_END = 11
    SYNC_ACQUIRE = 12
    SYNC_RELEASE = 13
    SYNC_FULL = 14
    THREAD_CREATE = 15
    THREAD_JOIN = 16
    ALLOC = 20
    FREE = 21
    MMAP = 22
    MUNMAP = 23
    THREAD_STACK = 24
    THREAD_STACK_END = 25
    MODULE_LOAD = 30
    MODULE_UNLOAD = 31
    INDIRECT_TARGET = 32
    SYSCALL = 33
    SIGNAL = 34

    @property
    def is_memory(self) -> bool:
        return self in {self.LOAD, self.STORE, self.ATOMIC_RMW}

    @property
    def is_read(self) -> bool:
        return self in {self.LOAD, self.ATOMIC_RMW}

    @property
    def is_write(self) -> bool:
        return self in {self.STORE, self.ATOMIC_RMW}

    @property
    def is_boundary(self) -> bool:
        return self in {
            self.ATOMIC_RMW,
            self.LFENCE,
            self.SFENCE,
            self.MFENCE,
        }


class EventFlags(IntFlag):
    NONE = 0
    VALUE_KNOWN = 1 << 0
    LOCK_PREFIX = 1 << 1
    XCHG = 1 << 2
    CONTROL_CLOSED = 1 << 3
    # FS/GS 相对访存属于当前线程的 TLS，不能按相同数值地址跨线程连边。
    TLS = 1 << 4


@dataclass(frozen=True, slots=True)
class TraceEvent:
    # thread_id 与 sequence 共同定义 guest 的线程内程序序。
    thread_id: int
    sequence: int
    # ticket 只排序生命周期和同步事件；普通访存不能借它获得额外顺序。
    ticket: int
    pc: int
    kind: EventKind
    address: int = 0
    size: int = 0
    value: int = 0
    flags: EventFlags = EventFlags.NONE
    aux: int = 0

    @property
    def event_id(self) -> str:
        return f"t{self.thread_id}:e{self.sequence}"

    @property
    def end_address(self) -> int:
        return self.address + self.size

    def overlaps(self, other: "TraceEvent") -> bool:
        return self.address < other.end_address and other.address < self.end_address
