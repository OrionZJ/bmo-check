from __future__ import annotations

import csv
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent


class TraceStoreError(RuntimeError):
    pass


class TraceStore:
    """轨迹写入磁盘数据库，避免大型程序把所有事件留在 Python 对象中。"""

    def __init__(self, path: Path | str = ":memory:") -> None:
        try:
            import duckdb
        except ImportError as error:
            raise TraceStoreError("DuckDB is required; run `uv sync`") from error
        self.path = path
        self.connection: Any = duckdb.connect(str(path))
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events(
                event_id VARCHAR PRIMARY KEY,
                thread_id UINTEGER NOT NULL,
                sequence UBIGINT NOT NULL,
                ticket UBIGINT NOT NULL,
                pc UBIGINT NOT NULL,
                kind USMALLINT NOT NULL,
                address UBIGINT NOT NULL,
                size UINTEGER NOT NULL,
                value UBIGINT NOT NULL,
                flags USMALLINT NOT NULL,
                aux UINTEGER NOT NULL,
                object_id VARCHAR
            );
            CREATE TABLE IF NOT EXISTS event_pages(
                event_id VARCHAR NOT NULL,
                page UBIGINT NOT NULL
            );
            """
        )

    def add_events(
        self,
        events: Iterable[TraceEvent],
        *,
        max_pages_per_access: int,
        batch_size: int,
    ) -> tuple[int, tuple[str, ...]]:
        rows: list[tuple[object, ...]] = []
        page_rows: list[tuple[str, int]] = []
        unsupported: list[str] = []
        count = 0
        for event in events:
            rows.append(
                (
                    event.event_id,
                    event.thread_id,
                    event.sequence,
                    event.ticket,
                    event.pc,
                    int(event.kind),
                    event.address,
                    event.size,
                    event.value,
                    int(event.flags),
                    event.aux,
                )
            )
            count += 1
            if event.kind.is_memory:
                first = event.address >> 12
                last = (event.end_address - 1) >> 12
                if last - first + 1 > max_pages_per_access:
                    unsupported.append(
                        f"{event.event_id} spans more than {max_pages_per_access} pages"
                    )
                else:
                    page_rows.extend((event.event_id, page) for page in range(first, last + 1))
            if len(rows) >= batch_size:
                self._flush(rows, page_rows)
        self._flush(rows, page_rows)
        return count, tuple(unsupported)

    def _flush(
        self, rows: list[tuple[object, ...]], page_rows: list[tuple[str, int]]
    ) -> None:
        if rows:
            self._copy_rows(
                "events",
                (
                    "event_id",
                    "thread_id",
                    "sequence",
                    "ticket",
                    "pc",
                    "kind",
                    "address",
                    "size",
                    "value",
                    "flags",
                    "aux",
                ),
                rows,
            )
            rows.clear()
        if page_rows:
            self._copy_rows("event_pages", ("event_id", "page"), page_rows)
            page_rows.clear()

    def _copy_rows(
        self,
        table: str,
        columns: tuple[str, ...],
        rows: list[tuple[object, ...]],
    ) -> None:
        # DuckDB 的逐行 Python 接口会主导大型轨迹的导入时间。临时文件只保存
        # 当前 batch，COPY 完成后立即删除，因此内存和临时空间都不会随轨迹累积。
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="", delete=False
            ) as stream:
                temporary_path = Path(stream.name)
                writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
                writer.writerows(rows)
            escaped_path = temporary_path.as_posix().replace("'", "''")
            column_list = ", ".join(columns)
            self.connection.execute(
                f"COPY {table} ({column_list}) FROM '{escaped_path}' "
                "(FORMAT CSV, DELIMITER '\\t', HEADER false)"
            )
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def thread_count(self) -> int:
        return int(
            self.connection.execute("SELECT count(DISTINCT thread_id) FROM events").fetchone()[0]
        )

    def iter_events(self) -> Iterator[TraceEvent]:
        cursor = self.connection.execute(
            "SELECT thread_id, sequence, ticket, pc, kind, address, size, value, flags, aux "
            "FROM events ORDER BY thread_id, sequence"
        )
        while rows := cursor.fetchmany(10_000):
            for row in rows:
                yield _row_to_event(row)

    def materialize_objects(self) -> int:
        """用 lifecycle epoch 绑定 allocation generation，不把 epoch 当内存序。"""

        self.connection.execute(
            """
            CREATE OR REPLACE TABLE objects AS
            WITH allocations AS (
                SELECT
                    address AS base,
                    size,
                    ticket AS start_ticket,
                    kind,
                    row_number() OVER (PARTITION BY address ORDER BY ticket) AS generation
                FROM events
                WHERE kind IN (20, 22, 24, 30) AND size > 0
            )
            SELECT
                concat(CASE kind
                           WHEN 20 THEN 'heap'
                           WHEN 22 THEN 'mapping'
                           WHEN 24 THEN 'stack'
                           ELSE 'module'
                       END,
                       ':0x', hex(base), ':g', generation) AS object_id,
                base,
                size,
                start_ticket,
                (
                    SELECT min(f.ticket)
                    FROM events f
                    WHERE f.kind IN (21, 23, 25, 31)
                      AND f.address = allocations.base
                      AND f.ticket >= allocations.start_ticket
                ) AS end_ticket
            FROM allocations
            """
        )
        self.connection.execute(
            """
            UPDATE events AS e
            SET object_id = (
                SELECT o.object_id
                FROM objects o
                WHERE e.address >= o.base
                  AND e.address + e.size <= o.base + o.size
                  AND e.ticket >= o.start_ticket
                  AND (o.end_ticket IS NULL OR e.ticket <= o.end_ticket)
                ORDER BY o.start_ticket DESC
                LIMIT 1
            )
            WHERE e.kind IN (1, 2, 3)
              AND (e.flags & 16) = 0
            """
        )
        # TLS 的数值地址来自线程私有 FS/GS base。把 thread_id 写进身份，防止
        # 两个线程复用相同 offset 时被误判为共享对象。
        self.connection.execute(
            """
            UPDATE events
            SET object_id = concat('tls:t', thread_id)
            WHERE kind IN (1, 2, 3) AND (flags & 16) <> 0
            """
        )
        return int(
            self.connection.execute(
                "SELECT count(DISTINCT object_id) FROM events WHERE object_id IS NOT NULL"
            ).fetchone()[0]
        )

    def get_events(self, event_ids: Iterable[str]) -> tuple[TraceEvent, ...]:
        ids = tuple(event_ids)
        if not ids:
            return ()
        placeholders = ",".join("?" for _ in ids)
        rows = self.connection.execute(
            "SELECT thread_id, sequence, ticket, pc, kind, address, size, value, flags, aux "
            f"FROM events WHERE event_id IN ({placeholders}) ORDER BY thread_id, sequence",
            ids,
        ).fetchall()
        return tuple(_row_to_event(row) for row in rows)

    def events_between(self, thread_id: int, first: int, last: int) -> tuple[TraceEvent, ...]:
        rows = self.connection.execute(
            "SELECT thread_id, sequence, ticket, pc, kind, address, size, value, flags, aux "
            "FROM events WHERE thread_id = ? AND sequence BETWEEN ? AND ? ORDER BY sequence",
            (thread_id, first, last),
        ).fetchall()
        return tuple(_row_to_event(row) for row in rows)

    def boundaries_between(
        self, thread_id: int, first: int, last: int
    ) -> tuple[TraceEvent, ...]:
        rows = self.connection.execute(
            "SELECT thread_id, sequence, ticket, pc, kind, address, size, value, flags, aux "
            "FROM events WHERE thread_id = ? AND sequence BETWEEN ? AND ? "
            "AND kind IN (3, 4, 5, 6) ORDER BY sequence",
            (thread_id, first, last),
        ).fetchall()
        return tuple(_row_to_event(row) for row in rows)

    def event_count(self) -> int:
        return int(self.connection.execute("SELECT count(*) FROM events").fetchone()[0])

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "TraceStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _row_to_event(row: tuple[object, ...]) -> TraceEvent:
    return TraceEvent(
        thread_id=int(row[0]),
        sequence=int(row[1]),
        ticket=int(row[2]),
        pc=int(row[3]),
        kind=EventKind(int(row[4])),
        address=int(row[5]),
        size=int(row[6]),
        value=int(row[7]),
        flags=EventFlags(int(row[8])),
        aux=int(row[9]),
    )
