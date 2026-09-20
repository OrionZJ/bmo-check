from __future__ import annotations

from array import array
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from heapq import heappop, heappush
from typing import Protocol

from bmo_check_dynamic.model import EventKind
from bmo_check_dynamic.storage import TraceStore


@dataclass(frozen=True, slots=True)
class CommunicationEndpoint:
    # 窗口图用 event_id 识别同一个访存节点。
    event_id: str
    # 按 thread_id 分组后，只在同一线程内补程序序边。
    thread_id: int
    # sequence 表示 guest 线程内顺序，不借全局 ticket 推断跨线程顺序。
    sequence: int
    # Fence 只跨越它覆盖的访存类型，窗口切分需要保留这个区别。
    kind: EventKind


@dataclass(frozen=True, slots=True)
class CommunicationEdge:
    # 两端使用动态 event_id，报告可以直接回到 thread 和 PC。
    first_event: str
    second_event: str
    address: int
    size: int
    # 缓存扫描时已读到的端点事实，避免窗口构建再从大轨迹库取一次。
    first_endpoint: CommunicationEndpoint | None = field(default=None, compare=False)
    # 手工构造的旧边没有端点事实；比较边身份时也不把缓存内容算进去。
    second_endpoint: CommunicationEndpoint | None = field(default=None, compare=False)


_ActiveEntry = tuple[
    str,
    int,
    int,
    int,
    int,
    int,
    str | None,
    int,
    int | None,
    int | None,
    int,
]


class CommunicationLimitError(RuntimeError):
    """扫描活动集合超限，调用者必须报告 UNKNOWN。"""


@dataclass(slots=True)
class CommunicationScanStats:
    # total_edges 包含 application scope 排除的纯外部模块边。
    total_edges: int = 0
    # external_edges 只计两端都不在指定主模块范围内的精确重叠边。
    external_edges: int = 0
    # 命中返回边数上限或活动集合上限时为 false，不能据此给出 TRACE_SAFE。
    complete: bool = False
    # candidate_page_count 是进入页扫描的候选页数量；页外事件不会被当成已扫描。
    candidate_page_count: int = 0
    # candidate_event_count 是候选页上的去重访存事件数量。
    candidate_event_count: int = 0
    # 扫描器按页读取同一事件可能多次；这里记录实际读过的 event-page 记录。
    scanned_event_page_records: int = 0
    # 只有完整扫描时才能把去重事件数确定为 candidate_event_count。
    scanned_event_count: int | None = None
    # 不在候选页上的访存事件及其过滤原因，不能被解释为通信不存在。
    filtered_event_count: int = 0
    filtered_event_reasons: dict[str, int] = field(default_factory=dict)
    # 资源闸门触发时，未处理事件的精确数量可能无法知道；原因仍必须保留。
    resource_limited_event_count: int | None = None
    resource_limit_reason: str | None = None
    # 防止 pipeline 的资源预检和真正扫描重复计算事件全集。
    universe_recorded: bool = False


class CommunicationEdgeSink(Protocol):
    """扫描器的可选落点；实现可以把边压缩或直接落盘。"""

    def add(
        self,
        first_event: str,
        second_event: str,
        address: int,
        size: int,
        first_endpoint: CommunicationEndpoint,
        second_endpoint: CommunicationEndpoint,
    ) -> None: ...


class CompactCommunicationEdges:
    """用整数节点和紧凑数组保存通信边，避免大轨迹创建百万个 dataclass。

    端点名称仍按原 event_id 保存，只有真正送入小窗口的边才重新构造
    ``CommunicationEdge``。这不会改变边集合，只改变中间存储方式。
    """

    __slots__ = (
        "_event_nodes",
        "event_ids",
        "thread_ids",
        "sequences",
        "kinds",
        "left_nodes",
        "right_nodes",
        "addresses",
        "sizes",
    )

    def __init__(self) -> None:
        # event_id 到紧凑节点号的映射只存在于本次扫描，窗口输出仍使用原 ID。
        self._event_nodes: dict[str, int] = {}
        # 节点名称用于把真正入窗的整数节点还原成 trace event_id。
        self.event_ids: list[str] = []
        # 以下三个数组保存端点的线程内事实，避免每条边重复存一份。
        self.thread_ids = array("I")
        self.sequences = array("Q")
        self.kinds = array("B")
        # 边端点使用节点号；同一对事件的不同页重叠仍分别保留。
        self.left_nodes = array("I")
        self.right_nodes = array("I")
        # 每条通信边的精确重叠地址和长度，供小窗口恢复原边。
        self.addresses = array("Q")
        self.sizes = array("I")

    @property
    def edge_count(self) -> int:
        return len(self.left_nodes)

    @property
    def node_count(self) -> int:
        return len(self.event_ids)

    def _intern(self, endpoint: CommunicationEndpoint) -> int:
        return self._intern_values(
            endpoint.event_id,
            endpoint.thread_id,
            endpoint.sequence,
            int(endpoint.kind),
        )

    def _intern_values(
        self, event_id: str, thread_id: int, sequence: int, kind: int
    ) -> int:
        node = self._event_nodes.get(event_id)
        if node is None:
            node = len(self.event_ids)
            self._event_nodes[event_id] = node
            self.event_ids.append(event_id)
            self.thread_ids.append(thread_id)
            self.sequences.append(sequence)
            self.kinds.append(kind)
            return node
        if (
            self.thread_ids[node] != thread_id
            or self.sequences[node] != sequence
            or self.kinds[node] != kind
        ):
            raise ValueError(f"conflicting endpoint facts for {event_id}")
        return node

    def add(
        self,
        first_event: str,
        second_event: str,
        address: int,
        size: int,
        first_endpoint: CommunicationEndpoint,
        second_endpoint: CommunicationEndpoint,
    ) -> None:
        first = self._intern(first_endpoint)
        second = self._intern(second_endpoint)
        if first_event != first_endpoint.event_id or second_event != second_endpoint.event_id:
            raise ValueError("edge endpoint name does not match endpoint fact")
        if first_event > second_event:
            first, second = second, first
        self.left_nodes.append(first)
        self.right_nodes.append(second)
        self.addresses.append(address)
        self.sizes.append(size)

    def add_raw(
        self,
        first_event: str,
        second_event: str,
        address: int,
        size: int,
        first_thread: int,
        first_sequence: int,
        first_kind: int,
        second_thread: int,
        second_sequence: int,
        second_kind: int,
    ) -> None:
        """接收扫描器的标量端点事实，不为每条边创建 endpoint 对象。"""

        first = self._intern_values(
            first_event, first_thread, first_sequence, first_kind
        )
        second = self._intern_values(
            second_event, second_thread, second_sequence, second_kind
        )
        if first_event > second_event:
            first, second = second, first
        self.left_nodes.append(first)
        self.right_nodes.append(second)
        self.addresses.append(address)
        self.sizes.append(size)

    def endpoint(self, node: int) -> CommunicationEndpoint:
        return CommunicationEndpoint(
            self.event_ids[node],
            int(self.thread_ids[node]),
            int(self.sequences[node]),
            EventKind(int(self.kinds[node])),
        )

    def edge(self, index: int) -> CommunicationEdge:
        left = int(self.left_nodes[index])
        right = int(self.right_nodes[index])
        return CommunicationEdge(
            self.event_ids[left],
            self.event_ids[right],
            int(self.addresses[index]),
            int(self.sizes[index]),
            self.endpoint(left),
            self.endpoint(right),
        )


def thread_handoffs_complete(store: TraceStore) -> bool:
    """返回每个已记录 worker 是否都有唯一 create/join 交接证据。"""

    return bool(_thread_handoffs(store))


def max_communication_page_events(
    store: TraceStore, *, required_pc_range: tuple[int, int] | None = None
) -> int:
    """返回候选页中事件数的上界，供调用者在全局排序前检查预算。

    这里不按地址展开交叉积，只按页聚合；超过活动集合预算时，继续排序
    只会把必然的 UNKNOWN 变成更高的峰值内存。
    """

    page_filter = ""
    params: tuple[int, ...] = ()
    if required_pc_range is not None:
        page_filter = "AND bool_or(e.pc >= ? AND e.pc < ?)"
        params = tuple(int(value) for value in required_pc_range)
    row = store.connection.execute(
        f"""
        WITH eligible_pages AS (
            SELECT ep.page
            FROM event_pages ep
            JOIN events e USING (event_id)
            GROUP BY ep.page
            HAVING count(DISTINCT e.thread_id) > 1
               AND count(*) FILTER (WHERE e.kind IN (2, 3)) > 0
               {page_filter}
        ), page_sizes AS (
            SELECT ep.page, count(*) AS event_count
            FROM event_pages ep
            JOIN eligible_pages p USING (page)
            GROUP BY ep.page
        )
        SELECT coalesce(max(event_count), 0) FROM page_sizes
        """,
        params,
    ).fetchone()
    return int(row[0] or 0)


def prepare_communication_scan_stats(
    store: TraceStore,
    *,
    required_pc_range: tuple[int, int] | None,
    stats: CommunicationScanStats,
) -> None:
    """记录通信扫描的候选页、候选事件和页外过滤账本。

    event_pages 只索引访存事件。候选页要求跨线程且至少包含一个写入；
    其余访存事件属于页级过滤输入。这个统计不把过滤事件当成“没有通信”，
    只说明它们没有进入本轮地址重叠扫描。
    """

    if stats.universe_recorded:
        return
    page_filter = ""
    params: tuple[int, ...] = ()
    if required_pc_range is not None:
        page_filter = "AND bool_or(e.pc >= ? AND e.pc < ?)"
        params = tuple(int(value) for value in required_pc_range)
    eligible_pages = f"""
        WITH eligible_pages AS (
            SELECT ep.page
            FROM event_pages ep
            JOIN events e USING (event_id)
            GROUP BY ep.page
            HAVING count(DISTINCT e.thread_id) > 1
               AND count(*) FILTER (WHERE e.kind IN (2, 3)) > 0
               {page_filter}
        )
    """
    page_row = store.connection.execute(
        eligible_pages + "SELECT count(*) FROM eligible_pages",
        params,
    ).fetchone()
    event_row = store.connection.execute(
        eligible_pages
        + """
        SELECT count(DISTINCT ep.event_id)
        FROM event_pages ep
        JOIN eligible_pages p USING (page)
        """,
        params,
    ).fetchone()
    input_row = store.connection.execute(
        "SELECT count(*) FROM events WHERE kind IN (1, 2, 3, 37)"
    ).fetchone()
    stats.candidate_page_count = int(page_row[0] or 0)
    stats.candidate_event_count = int(event_row[0] or 0)
    input_event_count = int(input_row[0] or 0)
    stats.filtered_event_count = max(input_event_count - stats.candidate_event_count, 0)
    if stats.filtered_event_count:
        stats.filtered_event_reasons["not_candidate_page"] = stats.filtered_event_count
    stats.universe_recorded = True


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
    store: TraceStore,
    *,
    limit: int | None = None,
    max_active_events: int = 600_000,
    required_pc_range: tuple[int, int] | None = None,
    edge_pc_range: tuple[int, int] | None = None,
    stats: CommunicationScanStats | None = None,
    edge_sink: CommunicationEdgeSink | None = None,
) -> Iterator[CommunicationEdge]:
    """只保留真实地址重叠且至少一端写入的跨线程访问。

    ``required_pc_range`` 只缩小候选页集合：页上至少要出现一个来自主
    ELF 的访存。``edge_pc_range`` 才会在精确重叠后排除两端都不在该范围
    的边；主程序与运行库之间的混合边仍会返回。
    """

    if stats is not None:
        # 一个 stats 对象只描述本次扫描。重用对象时不能把上一次完整扫描的
        # 标记带到本次受限扫描，否则早退会被错误解释成完整图。
        stats.complete = False
        stats.total_edges = 0
        stats.external_edges = 0
        stats.candidate_page_count = 0
        stats.candidate_event_count = 0
        stats.scanned_event_page_records = 0
        stats.scanned_event_count = None
        stats.filtered_event_count = 0
        stats.filtered_event_reasons.clear()
        stats.resource_limited_event_count = None
        stats.resource_limit_reason = None
        stats.universe_recorded = False

    # 单线程轨迹不可能产生通信边。跳过同页自连接，否则循环和库初始化会把
    # 同一页上的大量事件展开成无意义的二次方候选。
    if store.thread_count() < 2:
        if stats is not None:
            stats.complete = True
            stats.scanned_event_count = 0
        return

    handoffs = _thread_handoffs(store)

    page_filter = ""
    page_params: tuple[int, ...] = ()
    if required_pc_range is not None:
        page_filter = """
               AND bool_or(e.pc >= ? AND e.pc < ?)
        """
        page_params = tuple(int(value) for value in required_pc_range)
    if stats is not None:
        prepare_communication_scan_stats(
            store,
            required_pc_range=required_pc_range,
            stats=stats,
        )
    page_cursor = store.connection.execute(
        f"""
        WITH eligible_pages AS (
            SELECT ep.page
            FROM event_pages ep
            JOIN events e USING (event_id)
            GROUP BY ep.page
            HAVING count(DISTINCT e.thread_id) > 1
               AND count(*) FILTER (WHERE e.kind IN (2, 3)) > 0
               {page_filter}
        )
        SELECT page FROM eligible_pages ORDER BY page
        """,
        page_params,
    )
    emitted = 0
    while pages := page_cursor.fetchmany(1_000):
        for (page_value,) in pages:
            page = int(page_value)
            # 每页单独排序，避免 DuckDB 为整个轨迹建立一个无法受控的
            # ORDER BY；active 只保存当前页的地址区间。
            cursor = store.connection.execute(
                """
                SELECT e.event_id, e.thread_id, e.sequence, e.ticket, e.address, e.size,
                       e.kind, e.object_id, e.pc, o.start_ticket, o.end_ticket
                FROM event_pages ep
                JOIN events e USING (event_id)
                LEFT JOIN objects o ON o.object_id = e.object_id
                WHERE ep.page = ?
                ORDER BY e.address, e.event_id
                """,
                (page,),
            )
            active: dict[str, _ActiveEntry] = {}
            active_by_thread: dict[int, dict[str, _ActiveEntry]] = defaultdict(dict)
            active_writes_by_thread: dict[int, dict[str, _ActiveEntry]] = defaultdict(dict)
            expirations: list[tuple[int, str]] = []
            endpoint_cache: dict[str, CommunicationEndpoint] = {}
            while rows := cursor.fetchmany(10_000):
                if stats is not None:
                    stats.scanned_event_page_records += len(rows)
                for (
                    event_id_value,
                    thread,
                    sequence,
                    ticket,
                    address,
                    size,
                    kind,
                    object_id,
                    pc,
                    object_start,
                    object_end,
                ) in rows:
                    start = int(address)
                    end = start + int(size)
                    while expirations and expirations[0][0] <= start:
                        _expired_end, expired_id = heappop(expirations)
                        expired = active.pop(expired_id, None)
                        if expired is None:
                            continue
                        expired_thread = expired[3]
                        del active_by_thread[expired_thread][expired_id]
                        if not active_by_thread[expired_thread]:
                            del active_by_thread[expired_thread]
                        if expired[5] in (2, 3):
                            del active_writes_by_thread[expired_thread][expired_id]
                            if not active_writes_by_thread[expired_thread]:
                                del active_writes_by_thread[expired_thread]
                    event_id = str(event_id_value)
                    thread_id = int(thread)
                    kind_id = int(kind)
                    current_object = None if object_id is None else str(object_id)
                    current_object_start = (
                        None if object_start is None else int(object_start)
                    )
                    current_object_end = None if object_end is None else int(object_end)
                    candidate_buckets = (
                        active_by_thread
                        if kind_id in (2, 3)
                        else active_writes_by_thread
                    )
                    for other_thread, candidates in candidate_buckets.items():
                        if other_thread == thread_id:
                            continue
                        for candidate in candidates.values():
                            (
                                other_id,
                                other_start,
                                other_end,
                                _other_thread,
                                other_ticket,
                                other_kind,
                                other_object,
                                _other_pc,
                                other_object_start,
                                other_object_end,
                                other_sequence,
                            ) = candidate
                            if _is_thread_handoff_edge(
                                event_id,
                                thread_id,
                                int(ticket),
                                kind_id,
                                other_id,
                                other_thread,
                                other_ticket,
                                other_kind,
                                handoffs,
                            ):
                                continue
                            if _different_lifetimes(
                                current_object,
                                current_object_start,
                                current_object_end,
                                other_object,
                                other_object_start,
                                other_object_end,
                            ):
                                continue
                            overlap_start = max(start, other_start)
                            overlap_end = min(end, other_end)
                            if overlap_start >= overlap_end or overlap_start >> 12 != page:
                                continue
                            if stats is not None:
                                stats.total_edges += 1
                            if edge_pc_range is not None and not (
                                edge_pc_range[0] <= int(pc) < edge_pc_range[1]
                                or edge_pc_range[0] <= _other_pc < edge_pc_range[1]
                            ):
                                if stats is not None:
                                    stats.external_edges += 1
                                continue
                            if event_id < other_id:
                                first, second = event_id, other_id
                                first_endpoint_args = (
                                    thread_id, int(sequence), kind_id,
                                    other_thread, other_sequence, other_kind,
                                )
                            else:
                                first, second = other_id, event_id
                                first_endpoint_args = (
                                    other_thread, other_sequence, other_kind,
                                    thread_id, int(sequence), kind_id,
                                )
                            if edge_sink is not None:
                                if isinstance(edge_sink, CompactCommunicationEdges):
                                    edge_sink.add_raw(
                                        first,
                                        second,
                                        overlap_start,
                                        overlap_end - overlap_start,
                                        *first_endpoint_args,
                                    )
                                else:
                                    first_endpoint = _cached_communication_endpoint(
                                        endpoint_cache,
                                        first,
                                        first_endpoint_args[0],
                                        first_endpoint_args[1],
                                        first_endpoint_args[2],
                                    )
                                    second_endpoint = _cached_communication_endpoint(
                                        endpoint_cache,
                                        second,
                                        first_endpoint_args[3],
                                        first_endpoint_args[4],
                                        first_endpoint_args[5],
                                    )
                                    edge_sink.add(
                                        first,
                                        second,
                                        overlap_start,
                                        overlap_end - overlap_start,
                                        first_endpoint,
                                        second_endpoint,
                                    )
                            else:
                                first_endpoint = _cached_communication_endpoint(
                                    endpoint_cache,
                                    first,
                                    first_endpoint_args[0],
                                    first_endpoint_args[1],
                                    first_endpoint_args[2],
                                )
                                second_endpoint = _cached_communication_endpoint(
                                    endpoint_cache,
                                    second,
                                    first_endpoint_args[3],
                                    first_endpoint_args[4],
                                    first_endpoint_args[5],
                                )
                                yield CommunicationEdge(
                                    first,
                                    second,
                                    overlap_start,
                                    overlap_end - overlap_start,
                                    first_endpoint,
                                    second_endpoint,
                                )
                            emitted += 1
                            if limit is not None and emitted >= limit:
                                if stats is not None:
                                    stats.resource_limit_reason = (
                                        "communication edge limit reached before all candidate pages were scanned"
                                    )
                                    stats.resource_limited_event_count = (
                                        stats.candidate_event_count
                                    )
                                return
                    # 只查可能产生边的其他线程访存；结束地址堆淘汰过期项，
                    # 避免同线程和读-读访问让每个事件都重扫整个活动集合。
                    if len(active) >= max_active_events:
                        if stats is not None:
                            stats.resource_limit_reason = (
                                f"communication active set exceeds {max_active_events} events"
                            )
                            stats.resource_limited_event_count = (
                                stats.candidate_event_count
                            )
                        raise CommunicationLimitError(
                            f"communication active set exceeds {max_active_events} events"
                        )
                    entry = (
                        event_id,
                        start,
                        end,
                        thread_id,
                        int(ticket),
                        kind_id,
                        current_object,
                        int(pc),
                        current_object_start,
                        current_object_end,
                        int(sequence),
                    )
                    active[event_id] = entry
                    active_by_thread[thread_id][event_id] = entry
                    if kind_id in (2, 3):
                        active_writes_by_thread[thread_id][event_id] = entry
                    heappush(expirations, (end, event_id))
    if stats is not None:
        stats.complete = True
        stats.scanned_event_count = stats.candidate_event_count


def _cached_communication_endpoint(
    cache: dict[str, CommunicationEndpoint],
    event_id: str,
    thread_id: int,
    sequence: int,
    kind: int,
) -> CommunicationEndpoint:
    endpoint = cache.get(event_id)
    if endpoint is None:
        endpoint = CommunicationEndpoint(
            event_id, thread_id, sequence, EventKind(kind)
        )
        cache[event_id] = endpoint
    return endpoint


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


def _different_lifetimes(
    left_id: str | None,
    left_start: int | None,
    left_end: int | None,
    right_id: str | None,
    right_start: int | None,
    right_end: int | None,
) -> bool:
    """地址相交但对象生命周期不交叠时，不把两代映射连成通信边。"""

    if (
        left_id is None
        or right_id is None
        or left_id == right_id
        or left_id.startswith("tls:")
        or right_id.startswith("tls:")
        or left_start is None
        or right_start is None
    ):
        return False
    return (
        left_end is not None and left_end < right_start
    ) or (
        right_end is not None and right_end < left_start
    )
