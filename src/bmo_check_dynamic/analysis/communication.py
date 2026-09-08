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


class CommunicationLimitError(RuntimeError):
    """扫描活动集合超限，调用者必须报告 UNKNOWN。"""


@dataclass(frozen=True, slots=True)
class _ThreadHandoff:
    # parent_thread 是记录 create/join 的线程；其他 worker 不能冒充父线程。
    parent_thread: int
    # worker_thread 是 create/start/join 证据唯一对应的子线程。
    worker_thread: int
    # start_ticket 之前的父线程访存已经发布给子线程。
    start_ticket: int
    # join_ticket 之后的父线程访存已经看到子线程退出前的结果。
    join_ticket: int
    # end_ticket 用来限制 join 前确实属于该 worker 的事件。
    end_ticket: int


def find_communication_edges(
    store: TraceStore, *, limit: int | None = None, max_active_events: int = 100_000
) -> Iterator[CommunicationEdge]:
    """只保留真实地址重叠且至少一端写入的跨线程访问。"""

    # 单线程轨迹不可能产生通信边。跳过同页自连接，否则循环和库初始化会把
    # 同一页上的大量事件展开成无意义的二次方候选。
    if store.thread_count() < 2:
        return

    handoffs = _thread_handoffs(store)

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
        SELECT ep.page, e.event_id, e.thread_id, e.ticket, e.address, e.size,
               e.kind, e.object_id
        FROM event_pages ep
        JOIN eligible_pages p USING (page)
        JOIN events e USING (event_id)
        ORDER BY ep.page, e.address, e.event_id
        """
    )
    current_page: int | None = None
    active: list[tuple[str, int, int, int, int, int, str | None]] = []
    emitted = 0
    while rows := cursor.fetchmany(10_000):
        for page_value, event_id_value, thread, ticket, address, size, kind, object_id in rows:
            page = int(page_value)
            start = int(address)
            end = start + int(size)
            if page != current_page:
                current_page = page
                active.clear()
            active = [candidate for candidate in active if candidate[2] > start]
            event_id = str(event_id_value)
            for other_id, other_start, other_end, other_thread, other_ticket, other_kind, other_object in active:
                if other_thread == int(thread):
                    continue
                if int(kind) not in (2, 3) and other_kind not in (2, 3):
                    continue
                if _is_thread_handoff_edge(
                    event_id,
                    int(thread),
                    int(ticket),
                    int(kind),
                    other_id,
                    other_thread,
                    other_ticket,
                    other_kind,
                    handoffs,
                ):
                    continue
                if (
                    object_id is not None and other_object is not None
                    and object_id != other_object
                    and not str(object_id).startswith("tls:")
                    and not str(other_object).startswith("tls:")
                    and str(object_id).rsplit(":g", 1)[0]
                    == str(other_object).rsplit(":g", 1)[0]
                ):
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
            # 同址只读事件也会累积；输出边上限无法限制这个集合。
            if len(active) >= max_active_events:
                raise CommunicationLimitError(
                    f"communication active set exceeds {max_active_events} events"
                )
            active.append(
                (event_id, start, end, int(thread), int(ticket), int(kind),
                 None if object_id is None else str(object_id))
            )


def _thread_handoffs(store: TraceStore) -> dict[int, _ThreadHandoff]:
    """只接受 create/start/end/join 顺序唯一的线程交接。

    只有成功的 pthread_create 和 pthread_join 都能在轨迹中与同一 worker
    对上时，才把交接前后的访问当作共同的 happens-before 边界。缺证据时
    保留通信边，宁可让窗口变大，也不能把普通时间先后当成同步。
    """

    lifetimes = store.connection.execute(
        """
        SELECT thread_id,
               min(ticket) FILTER (WHERE kind = 10) AS start_ticket,
               max(ticket) FILTER (WHERE kind = 11) AS end_ticket
        FROM events
        WHERE kind IN (10, 11)
        GROUP BY thread_id
        ORDER BY start_ticket, thread_id
        """
    ).fetchall()
    if len(lifetimes) < 2 or any(row[1] is None or row[2] is None for row in lifetimes):
        return {}
    main_thread = int(lifetimes[0][0])
    workers = [(int(row[0]), int(row[1]), int(row[2])) for row in lifetimes[1:]]
    creates = [
        (int(row[0]), int(row[1]))
        for row in store.connection.execute(
            "SELECT ticket, address FROM events WHERE kind = 15 AND thread_id = ? ORDER BY ticket",
            (main_thread,),
        ).fetchall()
    ]
    joins = [int(row[0]) for row in store.connection.execute(
        "SELECT ticket FROM events WHERE kind = 16 AND thread_id = ? ORDER BY ticket",
        (main_thread,),
    ).fetchall()]
    if len(creates) < len(workers) or len(joins) < len(workers):
        return {}
    result: dict[int, _ThreadHandoff] = {}
    used_creates: set[int] = set()
    assigned_creates: dict[int, int] = {}
    # clone fallback 把 child tid 放进 address；它能消除“多个 child 已创建但
    # 还没调度到 THREAD_START”时的时间顺序歧义。pthread wrapper 的 handle
    # 不是 tid，仍需下面的严格时间配对。
    for worker_thread, start_ticket, _end_ticket in workers:
        direct = [
            index
            for index, (ticket, address) in enumerate(creates)
            if index not in used_creates
            and address == worker_thread
            and ticket < start_ticket
        ]
        if len(direct) > 1:
            return {}
        if direct:
            index = direct[0]
            used_creates.add(index)
            assigned_creates[worker_thread] = creates[index][0]
    for worker_thread, start_ticket, _end_ticket in workers:
        if worker_thread in assigned_creates:
            continue
        candidates = [
            index
            for index, (ticket, _address) in enumerate(creates)
            if index not in used_creates and ticket < start_ticket
        ]
        # 剩余 wrapper 事件必须恰好对应一个尚未配对的 worker；多个候选时
        # 不能靠“最近一次 create”猜测，否则会把两个线程的发布边界接反。
        if len(candidates) != 1:
            return {}
        index = candidates[0]
        used_creates.add(index)
        assigned_creates[worker_thread] = creates[index][0]
    for index, (worker_thread, start_ticket, end_ticket) in enumerate(workers):
        create_ticket = assigned_creates[worker_thread]
        join_ticket = joins[index]
        if create_ticket >= start_ticket or join_ticket <= end_ticket:
            return {}
        result[worker_thread] = _ThreadHandoff(
            main_thread, worker_thread, start_ticket, join_ticket, end_ticket
        )
    return result


def _is_thread_handoff_edge(
    current_id: str,
    current_thread: int,
    current_ticket: int,
    current_kind: int,
    other_id: str,
    other_thread: int,
    other_ticket: int,
    other_kind: int,
    handoffs: dict[int, _ThreadHandoff],
) -> bool:
    """剪掉已由 pthread create/join 共同排序的父子线程交接边。"""

    if current_thread in handoffs and other_thread == handoffs[current_thread].parent_thread:
        handoff = handoffs[current_thread]
    elif other_thread in handoffs and current_thread == handoffs[other_thread].parent_thread:
        handoff = handoffs[other_thread]
    else:
        return False

    worker_thread = handoff.worker_thread
    if current_thread == worker_thread:
        worker_ticket, worker_kind = current_ticket, current_kind
        parent_ticket, parent_kind = other_ticket, other_kind
    else:
        worker_ticket, worker_kind = other_ticket, other_kind
        parent_ticket, parent_kind = current_ticket, current_kind
    if worker_kind not in (1, 2, 3) or parent_kind not in (1, 2, 3):
        return False
    # create 前父线程的全部访存已经发布给 worker；join 后父线程的访存
    # 已经读取 worker 退出前的结果。同步边在 source/target 中相同，
    # 不需要再把这些 handoff 字节当作可重排的普通通信边。
    return (
        (parent_ticket < handoff.start_ticket)
        or (parent_ticket > handoff.join_ticket and worker_ticket <= handoff.end_ticket)
    )
