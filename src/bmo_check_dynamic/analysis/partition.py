from __future__ import annotations

from pathlib import Path

from bmo_check_dynamic.model.certificate import ApplicationPartitionEvidence
from bmo_check_dynamic.storage import TraceStore


def analyze_application_partition(
    store: TraceStore, modules_path: Path, executable: str
) -> ApplicationPartitionEvidence:
    module_range = _module_range(modules_path, executable)
    if module_range is None:
        return ApplicationPartitionEvidence(
            status="unknown", reasons=("executable module range is missing",)
        )
    start, end = module_range
    lifetimes = store.connection.execute(
        """
        SELECT thread_id,
               min(ticket) FILTER (WHERE kind = 10),
               max(ticket) FILTER (WHERE kind = 11)
        FROM events WHERE kind IN (10, 11) GROUP BY thread_id ORDER BY 2
        """
    ).fetchall()
    if not lifetimes or any(row[1] is None or row[2] is None for row in lifetimes):
        return ApplicationPartitionEvidence(
            status="unknown", module_start=start, module_end=end,
            reasons=("thread lifetime is incomplete",),
        )
    main_thread = int(lifetimes[0][0])
    if len(lifetimes) == 1:
        # 只有一个完整生命周期时，轨迹里不存在跨线程普通访存边。
        # 这不是把未观察到的线程当成私有；线程集合本身由完整轨迹固定下来。
        return ApplicationPartitionEvidence(
            status="safe",
            module_start=start,
            module_end=end,
            main_thread=main_thread,
        )
    worker_lifetimes = tuple(
        (int(row[0]), int(row[1]), int(row[2])) for row in lifetimes[1:]
    )
    workers = tuple(row[0] for row in worker_lifetimes)
    pair_clause, pair_params = _overlapping_worker_pairs(worker_lifetimes)
    if not pair_params:
        # 两个 worker 的整个生命周期没有交集，不能把地址复用当成并发写。
        # 这不是把 ticket 当内存序，而是使用已记录的 THREAD_START/END 边界。
        worker_conflicts = 0
        readonly_ranges = 0
    else:
        worker_conflicts = int(
            store.connection.execute(
                f"""
                WITH accesses AS (
                    SELECT DISTINCT thread_id, address, size,
                                    kind IN (2, 3) AS writes, object_id
                    FROM events
                    WHERE pc >= ? AND pc < ? AND kind IN (1, 2) AND thread_id <> ?
                )
                SELECT count(*) FROM accesses a JOIN accesses b
                  ON a.thread_id < b.thread_id
                 AND a.address < b.address + b.size
                 AND b.address < a.address + a.size
                 AND (a.writes OR b.writes)
                 AND ({pair_clause})
                 AND NOT ({_different_generation_sql('a', 'b')})
                """,
                (start, end, main_thread, *pair_params),
            ).fetchone()[0]
        )
        readonly_ranges = int(
            store.connection.execute(
                f"""
                WITH accesses AS (
                    SELECT DISTINCT thread_id, address, size,
                                    kind IN (2, 3) AS writes, object_id
                    FROM events
                    WHERE pc >= ? AND pc < ? AND kind IN (1, 2) AND thread_id <> ?
                )
                SELECT count(*) FROM accesses a JOIN accesses b
                  ON a.thread_id < b.thread_id
                 AND a.address < b.address + b.size
                 AND b.address < a.address + a.size
                 AND NOT a.writes AND NOT b.writes
                 AND ({pair_clause})
                 AND NOT ({_different_generation_sql('a', 'b')})
                """,
                (start, end, main_thread, *pair_params),
            ).fetchone()[0]
        )
    concurrent_main_conflicts = 0
    for thread_id, lifetime_start, lifetime_end in lifetimes[1:]:
        concurrent_main_conflicts += int(
            store.connection.execute(
                """
                WITH worker AS (
                    SELECT DISTINCT address, size, kind IN (2, 3) AS writes, object_id
                    FROM events
                    WHERE pc >= ? AND pc < ? AND kind IN (1, 2) AND thread_id = ?
                )
                SELECT count(*) FROM events main JOIN worker
                  ON main.address < worker.address + worker.size
                 AND worker.address < main.address + main.size
                 AND (main.kind = 2 OR worker.writes)
                 AND NOT (
                     main.object_id IS NOT NULL AND worker.object_id IS NOT NULL
                     AND main.object_id <> worker.object_id
                     AND substr(main.object_id, 1, 4) <> 'tls:'
                     AND substr(worker.object_id, 1, 4) <> 'tls:'
                     AND split_part(main.object_id, ':g', 1)
                         = split_part(worker.object_id, ':g', 1)
                 )
                WHERE main.pc >= ? AND main.pc < ? AND main.kind IN (1, 2)
                  AND main.thread_id = ? AND main.ticket BETWEEN ? AND ?
                """,
                (
                    start, end, int(thread_id), start, end, main_thread,
                    int(lifetime_start), int(lifetime_end),
                ),
            ).fetchone()[0]
        )
    reasons: list[str] = []
    if worker_conflicts:
        reasons.append(f"worker output ranges overlap in {worker_conflicts} cases")
    if concurrent_main_conflicts:
        reasons.append(
            f"main thread has {concurrent_main_conflicts} conflicting accesses during worker lifetimes"
        )
    return ApplicationPartitionEvidence(
        status="safe" if not reasons else "unknown",
        module_start=start,
        module_end=end,
        main_thread=main_thread,
        worker_threads=workers,
        readonly_shared_ranges=readonly_ranges,
        worker_conflicting_ranges=worker_conflicts,
        concurrent_main_conflicts=concurrent_main_conflicts,
        reasons=tuple(reasons),
    )


def _overlapping_worker_pairs(
    workers: tuple[tuple[int, int, int], ...],
) -> tuple[str, tuple[int, ...]]:
    pairs = [
        (left[0], right[0])
        for index, left in enumerate(workers)
        for right in workers[index + 1 :]
        if left[2] >= right[1] and right[2] >= left[1]
    ]
    if not pairs:
        return "", ()
    clause = " OR ".join(
        "(a.thread_id = ? AND b.thread_id = ?)" for _ in pairs
    )
    return clause, tuple(value for pair in pairs for value in pair)


def _different_generation_sql(left: str, right: str) -> str:
    """复用通信扫描的对象规则，避免把生命周期外的地址复用算成冲突。"""

    return (
        f"{left}.object_id IS NOT NULL AND {right}.object_id IS NOT NULL "
        f"AND {left}.object_id <> {right}.object_id "
        f"AND substr({left}.object_id, 1, 4) <> 'tls:' "
        f"AND substr({right}.object_id, 1, 4) <> 'tls:' "
        f"AND EXISTS ("
        f"SELECT 1 FROM objects lo JOIN objects ro "
        f"ON lo.object_id = {left}.object_id "
        f"AND ro.object_id = {right}.object_id "
        f"WHERE (lo.end_ticket IS NOT NULL "
        f"AND lo.end_ticket < ro.start_ticket) "
        f"OR (ro.end_ticket IS NOT NULL "
        f"AND ro.end_ticket < lo.start_ticket))"
    )


def _module_range(path: Path, executable: str) -> tuple[int, int] | None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split("\t", 2)
        if len(fields) == 3 and fields[2] == executable:
            return int(fields[0], 16), int(fields[1], 16)
    return None
