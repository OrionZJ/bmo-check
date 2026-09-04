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


def find_communication_edges(
    store: TraceStore, *, limit: int | None = None
) -> Iterator[CommunicationEdge]:
    """只保留真实地址重叠且至少一端写入的跨线程访问。"""

    # 单线程轨迹不可能产生通信边。跳过同页自连接，否则循环和库初始化会把
    # 同一页上的大量事件展开成无意义的二次方候选。
    if store.thread_count() < 2:
        return

    cursor = store.connection.execute(
        """
        WITH eligible_pages AS (
            SELECT ep.page
            FROM event_pages ep
            JOIN events e USING (event_id)
            GROUP BY ep.page
            HAVING count(DISTINCT e.thread_id) > 1
               AND count(*) FILTER (WHERE e.kind IN (2, 3)) > 0
        )
        SELECT ep.page, e.event_id, e.thread_id, e.address, e.size, e.kind,
               e.object_id
        FROM event_pages ep
        JOIN eligible_pages p USING (page)
        JOIN events e USING (event_id)
        ORDER BY ep.page, e.address, e.event_id
        """
    )
    current_page: int | None = None
    active: list[tuple[str, int, int, int, int, str | None]] = []
    emitted = 0
    while rows := cursor.fetchmany(10_000):
        for page_value, event_id_value, thread, address, size, kind, object_id in rows:
            page = int(page_value)
            start = int(address)
            end = start + int(size)
            if page != current_page:
                current_page = page
                active.clear()
            active = [candidate for candidate in active if candidate[2] > start]
            event_id = str(event_id_value)
            for other_id, other_start, other_end, other_thread, other_kind, other_object in active:
                if other_thread == int(thread):
                    continue
                if int(kind) not in (2, 3) and other_kind not in (2, 3):
                    continue
                if object_id is not None and other_object is not None and object_id != other_object:
                    continue
                overlap_start = max(start, other_start)
                overlap_end = min(end, other_end)
                if overlap_start >= overlap_end or overlap_start >> 12 != page:
                    continue
                first, second = sorted((event_id, other_id))
                yield CommunicationEdge(first, second, overlap_start, overlap_end - overlap_start)
                emitted += 1
                if limit is not None and emitted >= limit:
                    return
            active.append(
                (event_id, start, end, int(thread), int(kind), None if object_id is None else str(object_id))
            )
