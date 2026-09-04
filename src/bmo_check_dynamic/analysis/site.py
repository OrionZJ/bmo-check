from __future__ import annotations

from collections import Counter
from pathlib import Path

from bmo_check_dynamic.model import EventKind, InstructionSiteEvidence
from bmo_check_dynamic.trace.format import (
    HEADER,
    MAGIC,
    RECORD,
    VERSION_MAJOR,
    TraceFormatError,
    event_files,
)


def locate_instruction_site(
    trace_dir: Path, module_path: str, module_offset: int
) -> InstructionSiteEvidence:
    runtime_pcs = _runtime_pcs(trace_dir / "modules.tsv", module_path, module_offset)
    pc_set = set(runtime_pcs)
    thread_counts: Counter[int] = Counter()
    kind_counts: Counter[str] = Counter()
    size_counts: Counter[int] = Counter()
    flag_counts: Counter[int] = Counter()
    sequence_bounds: dict[int, tuple[int, int]] = {}

    for path in event_files(trace_dir):
        for record in _iter_raw_records(path):
            kind, flags, thread_id, sequence, _ticket, pc, *_rest = record
            if pc not in pc_set:
                continue
            try:
                kind_name = EventKind(kind).name
            except ValueError:
                kind_name = f"UNKNOWN_{kind}"
            size = int(record[8])
            thread_counts[thread_id] += 1
            kind_counts[kind_name] += 1
            size_counts[size] += 1
            flag_counts[flags] += 1
            bounds = sequence_bounds.get(thread_id)
            sequence_bounds[thread_id] = (
                sequence if bounds is None else min(bounds[0], sequence),
                sequence if bounds is None else max(bounds[1], sequence),
            )

    return InstructionSiteEvidence(
        module_path=module_path,
        module_offset=module_offset,
        runtime_pcs=runtime_pcs,
        event_count=sum(thread_counts.values()),
        thread_event_counts=tuple(sorted(thread_counts.items())),
        thread_sequence_bounds=tuple(
            (thread_id, bounds[0], bounds[1])
            for thread_id, bounds in sorted(sequence_bounds.items())
        ),
        kind_counts=tuple(sorted(kind_counts.items())),
        size_counts=tuple(sorted(size_counts.items())),
        flag_counts=tuple(sorted(flag_counts.items())),
    )


def _runtime_pcs(path: Path, module_path: str, offset: int) -> tuple[int, ...]:
    if offset < 0:
        raise ValueError("module offset must not be negative")
    result: list[int] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split("\t", 2)
        if len(fields) != 3 or fields[2] != module_path:
            continue
        start, end = int(fields[0], 16), int(fields[1], 16)
        pc = start + offset
        if pc >= end:
            raise ValueError(
                f"module offset 0x{offset:x} is outside mapping {module_path}"
            )
        result.append(pc)
    if not result:
        raise ValueError(f"module is absent from trace: {module_path}")
    return tuple(sorted(set(result)))


def _iter_raw_records(path: Path):
    records_per_chunk = 65_536
    with path.open("rb") as stream:
        raw_header = stream.read(HEADER.size)
        if len(raw_header) != HEADER.size:
            raise TraceFormatError(f"truncated trace header: {path}")
        magic, major, _minor, record_size = HEADER.unpack(raw_header)
        if magic != MAGIC or major != VERSION_MAJOR or record_size != RECORD.size:
            raise TraceFormatError(f"unsupported trace format: {path}")
        while raw := stream.read(RECORD.size * records_per_chunk):
            if len(raw) % RECORD.size:
                raise TraceFormatError(f"truncated event record: {path}")
            yield from RECORD.iter_unpack(raw)
