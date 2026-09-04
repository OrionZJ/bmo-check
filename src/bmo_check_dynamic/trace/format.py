from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterator
from pathlib import Path

from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent


MAGIC = b"BMOTRACE"
VERSION_MAJOR = 1
VERSION_MINOR = 0
HEADER = struct.Struct("<8sHHI")
# kind, flags, thread, sequence, ticket, pc, address, value, size, aux
RECORD = struct.Struct("<HHIQQQQQII")


class TraceFormatError(ValueError):
    pass


class TraceWriter:
    """测试和转换器共用的 writer；生产追踪器使用完全相同的定长布局。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream = path.open("wb")
        self._stream.write(HEADER.pack(MAGIC, VERSION_MAJOR, VERSION_MINOR, RECORD.size))

    def write(self, event: TraceEvent) -> None:
        self._stream.write(
            RECORD.pack(
                int(event.kind),
                int(event.flags),
                event.thread_id,
                event.sequence,
                event.ticket,
                event.pc,
                event.address,
                event.value,
                event.size,
                event.aux,
            )
        )

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> "TraceWriter":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class TraceReader:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __iter__(self) -> Iterator[TraceEvent]:
        with self.path.open("rb") as stream:
            raw_header = stream.read(HEADER.size)
            if len(raw_header) != HEADER.size:
                raise TraceFormatError(f"truncated trace header: {self.path}")
            magic, major, _minor, record_size = HEADER.unpack(raw_header)
            if magic != MAGIC or major != VERSION_MAJOR or record_size != RECORD.size:
                raise TraceFormatError(f"unsupported trace format: {self.path}")
            while raw := stream.read(RECORD.size):
                if len(raw) != RECORD.size:
                    raise TraceFormatError(f"truncated event record: {self.path}")
                (
                    kind,
                    flags,
                    thread_id,
                    sequence,
                    ticket,
                    pc,
                    address,
                    value,
                    size,
                    aux,
                ) = RECORD.unpack(raw)
                try:
                    event_kind = EventKind(kind)
                except ValueError as error:
                    raise TraceFormatError(f"unknown event kind {kind}: {self.path}") from error
                yield TraceEvent(
                    thread_id=thread_id,
                    sequence=sequence,
                    ticket=ticket,
                    pc=pc,
                    kind=event_kind,
                    address=address,
                    size=size,
                    value=value,
                    flags=EventFlags(flags),
                    aux=aux,
                )


def event_files(trace_dir: Path) -> tuple[Path, ...]:
    return tuple(sorted(trace_dir.glob("events-*.bin")))


def trace_digest(trace_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in (trace_dir / "manifest.json", *event_files(trace_dir)):
        if not path.is_file():
            continue
        digest.update(path.name.encode("utf-8"))
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()
