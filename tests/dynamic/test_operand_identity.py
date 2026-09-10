from __future__ import annotations

from pathlib import Path

from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent
from bmo_check_dynamic.trace import TraceReader, TraceWriter, validate_trace
from bmo_check_dynamic.trace.format import HEADER


def test_new_trace_round_trip_preserves_memory_operand_index(tmp_path: Path) -> None:
    path = tmp_path / "events-1.bin"
    event = TraceEvent(
        1,
        1,
        0,
        0x1000,
        EventKind.STORE,
        0x2000,
        8,
        operand_index=3,
    )
    with TraceWriter(path) as writer:
        writer.write(event)

    decoded = tuple(TraceReader(path))
    assert decoded == (event,)
    assert decoded[0].flags & EventFlags.OPERAND_INDEX
    assert decoded[0].operand_index == 3


def test_old_site_only_event_remains_without_operand_identity(tmp_path: Path) -> None:
    path = tmp_path / "events-1.bin"
    event = TraceEvent(1, 1, 0, 0x1000, EventKind.LOAD, 0x2000, 4)
    with TraceWriter(path) as writer:
        writer.write(event)

    decoded = tuple(TraceReader(path))
    assert decoded[0].operand_index is None
    assert not decoded[0].flags & EventFlags.OPERAND_INDEX


def test_operand_flag_on_non_memory_event_is_rejected(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0, EventKind.THREAD_START))
    path = trace_dir / "events-1.bin"
    payload = bytearray(path.read_bytes())
    # flags field starts after kind (2 bytes) in the fixed record.
    payload[HEADER.size + 2 : HEADER.size + 4] = int(EventFlags.OPERAND_INDEX).to_bytes(
        2, "little"
    )
    path.write_bytes(payload)

    result = validate_trace(trace_dir)
    assert not result.valid
    assert "operand discriminator on non-memory" in " ".join(result.reasons)
