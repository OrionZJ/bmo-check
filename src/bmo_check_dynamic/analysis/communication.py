from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from bmo_check_dynamic.storage import TraceStore


@dataclass(frozen=True, slots=True)
class CommunicationEdge:
    # 两端使用动态 event_id，报告可以直接回到 thread 和 PC。
    first_event: str
    second_event: str
    address: int
    size: int


def find_communication_edges(store: TraceStore) -> Iterator[CommunicationEdge]:
    """只保留真实地址重叠且至少一端写入的跨线程访问。"""

    # 单线程轨迹不可能产生通信边。跳过同页自连接，否则循环和库初始化会把
    # 同一页上的大量事件展开成无意义的二次方候选。
    if store.thread_count() < 2:
        return

    cursor = store.connection.execute(
        """
        SELECT DISTINCT
            a.event_id, b.event_id,
            greatest(a.address, b.address) AS overlap_start,
            least(a.address + a.size, b.address + b.size) -
                greatest(a.address, b.address) AS overlap_size
        FROM event_pages pa
        JOIN event_pages pb ON pa.page = pb.page AND pa.event_id < pb.event_id
        JOIN events a ON a.event_id = pa.event_id
        JOIN events b ON b.event_id = pb.event_id
        WHERE a.thread_id <> b.thread_id
          AND a.address < b.address + b.size
          AND b.address < a.address + a.size
          AND (a.kind IN (2, 3) OR b.kind IN (2, 3))
          AND (a.object_id IS NULL OR b.object_id IS NULL OR a.object_id = b.object_id)
        ORDER BY a.event_id, b.event_id
        """
    )
    while rows := cursor.fetchmany(10_000):
        for first, second, address, size in rows:
            yield CommunicationEdge(str(first), str(second), int(address), int(size))
