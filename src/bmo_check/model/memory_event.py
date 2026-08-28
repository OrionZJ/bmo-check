from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field

from .common import StrictModel


class AddressKind(str, Enum):
    GLOBAL = "Global"
    TLS = "TLS"
    STACK = "Stack"
    HEAP = "Heap"
    AFFINE = "Affine"
    UNKNOWN = "Unknown"


class AbstractAddress(StrictModel):
    kind: AddressKind
    base: str | None = None
    offset: int | None = None
    expression: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)


class EventKind(str, Enum):
    LOAD = "Load"
    STORE = "Store"
    ATOMIC_RMW = "AtomicRMW"
    FENCE = "Fence"
    THREAD_CREATE = "ThreadCreate"
    THREAD_JOIN = "ThreadJoin"
    ACQUIRE = "Acquire"
    RELEASE = "Release"
    BARRIER = "Barrier"
    OPAQUE_CALL = "OpaqueCall"
    SYSCALL = "Syscall"
    UNKNOWN_MEMORY_EFFECT = "UnknownMemoryEffect"


class MemoryEvent(StrictModel):
    id: str
    module: str
    pc: int
    function: str | None = None
    kind: EventKind
    address: AbstractAddress | None = None
    size: int | None = None
    source_ordering: str = "Unknown"
    target_ordering: str = "Unknown"
    thread_role: str | None = None
    guard: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)
