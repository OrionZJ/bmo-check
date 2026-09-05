from __future__ import annotations

from pathlib import Path

import pytest

from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent
from bmo_check_dynamic.trace import (
    TraceFormatError,
    TraceReader,
    TraceWriter,
    trace_digest,
    validate_trace,
)


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


def test_trace_digest_binds_module_and_completion_metadata(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 1, 0, EventKind.THREAD_START))
    (trace_dir / "modules.tsv").write_text("0x1000\t0x2000\t/program\n")
    (trace_dir / ".dropped").write_text("0\n")
    (trace_dir / ".drop-reasons").write_text("")
    (trace_dir / ".complete").touch()
    original = trace_digest(trace_dir)

    (trace_dir / "modules.tsv").write_text("0x1000\t0x3000\t/program\n")

    assert trace_digest(trace_dir) != original


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


@pytest.mark.parametrize("sequences", [(2,), (1, 3), (1, 1), (1, 2, 1)])
def test_missing_or_repeated_sequences_fail_validation(
    trace_manifest, tmp_path: Path, sequences
) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        for sequence in sequences:
            writer.write(TraceEvent(1, sequence, 0, 0x10, EventKind.LOAD, 0x1000, 4))
    validation = validate_trace(trace_dir)
    assert not validation.valid
    assert any("sequence gap or duplicate" in reason for reason in validation.reasons)


def test_duplicate_thread_records_in_another_file_fail_validation(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    for suffix in ("1", "2"):
        with TraceWriter(trace_dir / f"events-{suffix}.bin") as writer:
            writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4))
    assert not validate_trace(trace_dir).valid


@pytest.mark.parametrize("address,size,flags", [
    (0x1000, 4, EventFlags(1 << 15)),
    ((1 << 64) - 2, 4, EventFlags.NONE),
])
def test_unsupported_record_fields_fail_validation(
    trace_manifest, tmp_path: Path, address, size, flags
) -> None:
    trace_dir = tmp_path / "trace"
    trace_manifest(trace_dir)
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, address, size, flags=flags))
    assert not validate_trace(trace_dir).valid
