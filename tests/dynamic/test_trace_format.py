from __future__ import annotations

from pathlib import Path

import pytest

from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.trace import TraceFormatError, TraceReader, TraceWriter, validate_trace


def test_trace_round_trip_and_validation(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    events = (
        TraceEvent(7, 1, 1, 0x1000, EventKind.THREAD_START),
        TraceEvent(7, 2, 0, 0x1010, EventKind.LOAD, 0x4000, 8),
        TraceEvent(7, 3, 2, 0x1020, EventKind.THREAD_END),
    )
    with TraceWriter(trace_dir / "events-7.bin") as writer:
        for event in events:
            writer.write(event)

    assert tuple(TraceReader(trace_dir / "events-7.bin")) == events
    validation = validate_trace(trace_dir)
    assert validation.valid
    assert validation.event_count == 3
    assert validation.thread_ids == (7,)


def test_truncated_trace_is_unknown(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    path = trace_dir / "events-1.bin"
    with TraceWriter(path) as writer:
        writer.write(TraceEvent(1, 1, 0, 0x1000, EventKind.LOAD, 0x2000, 4))
    path.write_bytes(path.read_bytes()[:-1])

    with pytest.raises(TraceFormatError):
        tuple(TraceReader(path))
    assert not validate_trace(trace_dir).valid


def test_incomplete_manifest_never_validates(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir, complete=False)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0, EventKind.THREAD_START))
    validation = validate_trace(trace_dir)
    assert not validation.valid
    assert "clean process exit" in validation.reasons[0]


def test_validation_error_list_is_bounded(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        for sequence in range(1, 151):
            writer.write(
                TraceEvent(1, sequence, 0, 0x1000, EventKind.LOAD, 0x2000, 0)
            )

    validation = validate_trace(trace_dir)
    assert not validation.valid
    assert len(validation.reasons) == 101
    assert validation.reasons[-1] == "trace validation omitted 50 additional errors"


def test_nonzero_program_exit_is_unknown(trace_manifest, tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    manifest = trace_manifest(trace_dir)
    manifest.model_copy(update={"exit_code": 7}).save(trace_dir / "manifest.json")
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 1, 0, EventKind.THREAD_START))
    validation = validate_trace(trace_dir)
    assert not validation.valid
    assert "status 7" in " ".join(validation.reasons)
