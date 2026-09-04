from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from bmo_check_dynamic.model import EventKind, TraceEvent


class DynamicObjectKind(str, Enum):
    HEAP = "heap"
    MAPPING = "mapping"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DynamicObject:
    object_id: str
    kind: DynamicObjectKind
    base: int
    size: int
    generation: int
    live: bool = True

    def contains(self, event: TraceEvent) -> bool:
        return self.base <= event.address and event.end_address <= self.base + self.size


class ObjectTracker:
    """generation 区分同一地址的多次分配，防止把无关生命周期连成通信。"""

    def __init__(self) -> None:
        self._generation: dict[int, int] = {}
        self._live: dict[int, DynamicObject] = {}

    def observe(self, event: TraceEvent) -> DynamicObject | None:
        if event.kind in {EventKind.ALLOC, EventKind.MMAP}:
            generation = self._generation.get(event.address, 0) + 1
            self._generation[event.address] = generation
            kind = (
                DynamicObjectKind.HEAP
                if event.kind == EventKind.ALLOC
                else DynamicObjectKind.MAPPING
            )
            obj = DynamicObject(
                object_id=f"{kind.value}:0x{event.address:x}:g{generation}",
                kind=kind,
                base=event.address,
                size=event.size,
                generation=generation,
            )
            self._live[event.address] = obj
            return obj
        if event.kind in {EventKind.FREE, EventKind.MUNMAP}:
            return self._live.pop(event.address, None)
        if event.kind.is_memory:
            for obj in self._live.values():
                if obj.contains(event):
                    return obj
        return None
