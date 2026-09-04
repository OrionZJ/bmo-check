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
    if len(lifetimes) < 2 or any(row[1] is None or row[2] is None for row in lifetimes):
        return ApplicationPartitionEvidence(
            status="unknown", module_start=start, module_end=end,
            reasons=("thread lifetime is incomplete",),
        )
    main_thread = int(lifetimes[0][0])
    workers = tuple(int(row[0]) for row in lifetimes[1:])
    worker_conflicts = int(
        store.connection.execute(
            """
            WITH accesses AS (
                SELECT DISTINCT thread_id, address, size, kind IN (2, 3) AS writes
                FROM events
                WHERE pc >= ? AND pc < ? AND kind IN (1, 2) AND thread_id <> ?
            )
            SELECT count(*) FROM accesses a JOIN accesses b
              ON a.thread_id < b.thread_id
             AND a.address < b.address + b.size
             AND b.address < a.address + a.size
             AND (a.writes OR b.writes)
            """,
            (start, end, main_thread),
        ).fetchone()[0]
    )
    readonly_ranges = int(
        store.connection.execute(
            """
            WITH accesses AS (
                SELECT DISTINCT thread_id, address, size, kind IN (2, 3) AS writes
                FROM events
                WHERE pc >= ? AND pc < ? AND kind IN (1, 2) AND thread_id <> ?
            )
            SELECT count(*) FROM accesses a JOIN accesses b
              ON a.thread_id < b.thread_id
             AND a.address < b.address + b.size
             AND b.address < a.address + a.size
             AND NOT a.writes AND NOT b.writes
            """,
            (start, end, main_thread),
        ).fetchone()[0]
    )
    concurrent_main_conflicts = 0
    for thread_id, lifetime_start, lifetime_end in lifetimes[1:]:
        concurrent_main_conflicts += int(
            store.connection.execute(
                """
                WITH worker AS (
                    SELECT DISTINCT address, size, kind IN (2, 3) AS writes
                    FROM events
                    WHERE pc >= ? AND pc < ? AND kind IN (1, 2) AND thread_id = ?
                )
                SELECT count(*) FROM events main JOIN worker
                  ON main.address < worker.address + worker.size
                 AND worker.address < main.address + main.size
                 AND (main.kind = 2 OR worker.writes)
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
