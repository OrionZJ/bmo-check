from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from bmo_check_dynamic.capture import capture_program
from bmo_check_dynamic.capture.launcher import dynamorio_version
from bmo_check_dynamic.model import EventFlags, EventKind
from bmo_check_dynamic.trace import TraceReader
from bmo_check_dynamic.trace import validate_trace
from bmo_check_dynamic.trace.format import event_files


def _native_environment() -> tuple[Path, Path, str] | None:
    home_value = os.environ.get("DYNAMORIO_HOME")
    compiler = shutil.which("cc")
    if platform.system() != "Linux" or not home_value or compiler is None:
        return None
    home = Path(home_value)
    client = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "bmo_check_dynamic"
        / "native"
        / "build"
        / "libbmo_trace.so"
    )
    if not (home / "bin64" / "drrun").is_file() or not client.is_file():
        return None
    return home, client, compiler


def test_dynamorio_version_is_read_from_cmake_package(tmp_path: Path) -> None:
    cmake = tmp_path / "cmake"
    cmake.mkdir()
    (cmake / "DynamoRIOConfigVersion.cmake").write_text(
        "set(PACKAGE_VERSION 11.3.0)\n", encoding="utf-8"
    )
    assert dynamorio_version(tmp_path) == "11.3.0"


@pytest.mark.skipif(
    _native_environment() is None,
    reason="DYNAMORIO_HOME, cc, and the built native client are required",
)
def test_pthread_and_object_lifecycle_capture(tmp_path: Path) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, compiler = environment
    source = Path(__file__).parent / "native" / "pthread_lifecycle.c"
    executable = tmp_path / "pthread-lifecycle"
    subprocess.run(
        [compiler, "-O0", "-pthread", str(source), "-o", str(executable)],
        check=True,
    )

    trace_dir = tmp_path / "trace"
    manifest = capture_program(
        (str(executable),),
        trace_dir,
        dynamorio_home=home,
        client_path=client,
    )
    events = tuple(
        event
        for path in event_files(trace_dir)
        for event in TraceReader(path)
    )
    kinds = {event.kind for event in events}

    assert manifest.complete
    assert manifest.dropped_events == 0, manifest.dropped_by_reason
    assert len({event.thread_id for event in events}) >= 2
    assert {
        EventKind.ATOMIC_RMW,
        EventKind.LFENCE,
        EventKind.SFENCE,
        EventKind.MFENCE,
        EventKind.THREAD_CREATE,
        EventKind.THREAD_JOIN,
        EventKind.SYNC_ACQUIRE,
        EventKind.SYNC_RELEASE,
        EventKind.ALLOC,
        EventKind.FREE,
        EventKind.MMAP,
        EventKind.MUNMAP,
        EventKind.THREAD_STACK,
        EventKind.THREAD_STACK_END,
        EventKind.MODULE_LOAD,
        EventKind.MODULE_UNLOAD,
        EventKind.INDIRECT_TARGET,
        EventKind.SIGNAL,
        EventKind.SYSCALL,
    } <= kinds
    atomic_flags = [event.flags for event in events if event.kind == EventKind.ATOMIC_RMW]
    assert any(flags & EventFlags.LOCK_PREFIX for flags in atomic_flags)
    assert any(flags & EventFlags.XCHG for flags in atomic_flags)


@pytest.mark.skipif(
    _native_environment() is None,
    reason="DYNAMORIO_HOME, cc, and the built native client are required",
)
def test_openmp_runtime_threads_are_captured(tmp_path: Path) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, compiler = environment
    source = Path(__file__).parent / "native" / "openmp_smoke.c"
    executable = tmp_path / "openmp-smoke"
    result = subprocess.run(
        [compiler, "-O0", "-fopenmp", str(source), "-o", str(executable)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"OpenMP compiler support is unavailable: {result.stderr.strip()}")

    trace_dir = tmp_path / "trace"
    manifest = capture_program(
        (str(executable),),
        trace_dir,
        dynamorio_home=home,
        client_path=client,
        environment={"OMP_NUM_THREADS": "2"},
    )
    thread_ids = {
        event.thread_id
        for path in event_files(trace_dir)
        for event in TraceReader(path)
    }

    assert manifest.complete
    assert manifest.dropped_events == 0, manifest.dropped_by_reason
    assert len(thread_ids) >= 2


@pytest.mark.skipif(
    _native_environment() is None,
    reason="DYNAMORIO_HOME, cc, and the built native client are required",
)
def test_shared_mapping_forces_unknown(tmp_path: Path) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, compiler = environment
    source = Path(__file__).parent / "native" / "unsupported_shared.c"
    executable = tmp_path / "unsupported-shared"
    subprocess.run(
        [compiler, "-O0", str(source), "-o", str(executable)],
        check=True,
    )

    trace_dir = tmp_path / "trace"
    manifest = capture_program(
        (str(executable),),
        trace_dir,
        dynamorio_home=home,
        client_path=client,
    )

    assert manifest.complete
    assert manifest.dropped_by_reason.get("unsupported") == 1
    validation = validate_trace(trace_dir)
    assert not validation.valid
    assert "unsupported" in " ".join(validation.reasons)


@pytest.mark.skipif(_native_environment() is None, reason="native capture environment required")
def test_sync_calls_preserve_failure_and_barrier_success(tmp_path: Path) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, compiler = environment
    executable = tmp_path / "sync-calls"
    subprocess.run([compiler, "-O0", "-pthread",
                    str(Path(__file__).parent / "native" / "sync_calls.c"),
                    "-o", str(executable)], check=True)
    trace_dir = tmp_path / "trace"
    manifest = capture_program((str(executable),), trace_dir,
                               dynamorio_home=home, client_path=client)
    assert manifest.exit_code == 0
    assert manifest.dropped_events == 0
    assert validate_trace(trace_dir).valid
    calls = [event for path in event_files(trace_dir) for event in TraceReader(path)
             if event.kind == EventKind.SYNC_CALL]
    returns = {event.aux >> 1: event.value for event in calls if event.aux & 1}
    import errno
    assert returns[2] == errno.ETIMEDOUT
    assert returns[5] == (1 << 64) - 1
    assert returns[7] == (1 << 64) - 1
    assert returns[8] == (1 << 64) - 1
    assert all(returns[api] == 0 for api in (3, 4, 6, 9))
    assert next(event.value for event in calls if event.aux == 4) != 0
