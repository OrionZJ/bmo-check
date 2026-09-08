from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from bmo_check_dynamic.capture import capture_program
from bmo_check_dynamic.capture.launcher import dynamorio_version
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import EventFlags, EventKind, TraceVerdict
from bmo_check_dynamic.pipeline import analyze_trace
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


def _contract() -> Path:
    return Path(__file__).resolve().parents[2] / "specs" / "dynamic" / "dbt6-mo-off.yaml"


def _symbol_address(executable: Path, name: str) -> int:
    result = subprocess.run(
        ["nm", "-n", str(executable)], capture_output=True, text=True, check=True
    )
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] == name:
            return int(fields[0], 16)
    raise AssertionError(f"missing symbol {name}")


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
    certificate = analyze_trace(trace_dir, dbt_contract=_contract())
    assert certificate.verdict == TraceVerdict.UNKNOWN
    # 成功的 FUTEX_WAIT 已经物化为同步字读；具体样例可能继续落到窗口
    # 资源门或 symbolic 候选，关键是不能越过 UNKNOWN 门给出 SAFE。
    assert certificate.unknown_reasons


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
    certificate = analyze_trace(
        trace_dir,
        dbt_contract=_contract(),
        config=DynamicConfig(max_communication_edges=1, max_window_events=32),
    )
    assert certificate.verdict == TraceVerdict.UNKNOWN
    assert "syscall" not in " ".join(certificate.unknown_reasons)


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
    certificate = analyze_trace(trace_dir, dbt_contract=_contract())
    assert certificate.verdict == TraceVerdict.TRACE_SAFE


@pytest.mark.skipif(_native_environment() is None, reason="native capture environment required")
def test_rep_string_records_every_iteration_address(tmp_path: Path) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, compiler = environment
    executable = tmp_path / "rep-string"
    subprocess.run(
        [
            compiler,
            "-O0",
            "-fno-pie",
            "-no-pie",
            str(Path(__file__).parent / "native" / "rep_string.c"),
            "-o",
            str(executable),
        ],
        check=True,
    )
    source = _symbol_address(executable, "rep_source")
    target = _symbol_address(executable, "rep_target")
    trace_dir = tmp_path / "trace"
    manifest = capture_program(
        (str(executable),), trace_dir, dynamorio_home=home, client_path=client
    )
    events = [
        event for path in event_files(trace_dir) for event in TraceReader(path)
    ]

    assert manifest.dropped_events == 0, manifest.dropped_by_reason
    assert {
        event.address
        for event in events
        if event.kind == EventKind.LOAD and source <= event.address < source + 64
    } >= set(range(source, source + 64))
    assert {
        event.address
        for event in events
        if event.kind == EventKind.STORE and target <= event.address < target + 64
    } >= set(range(target, target + 64))


@pytest.mark.skipif(
    _native_environment() is None or "avx2" not in Path("/proc/cpuinfo").read_text(),
    reason="native capture environment and AVX2 are required",
)
def test_gather_records_every_selected_address(tmp_path: Path) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, compiler = environment
    executable = tmp_path / "gather"
    subprocess.run(
        [
            compiler,
            "-O0",
            "-mavx2",
            "-fno-pie",
            "-no-pie",
            str(Path(__file__).parent / "native" / "gather.c"),
            "-o",
            str(executable),
        ],
        check=True,
    )
    source = _symbol_address(executable, "gather_source")
    expected = {source + index * 4 for index in (0, 3, 7, 12, 18, 25, 33, 42)}
    trace_dir = tmp_path / "trace"
    manifest = capture_program(
        (str(executable),), trace_dir, dynamorio_home=home, client_path=client
    )
    observed = {
        event.address
        for path in event_files(trace_dir)
        for event in TraceReader(path)
        if event.kind == EventKind.LOAD and event.address in expected
    }

    assert manifest.exit_code == 0
    assert manifest.dropped_events == 0, manifest.dropped_by_reason
    assert observed == expected


@pytest.mark.skipif(_native_environment() is None, reason="native capture environment required")
def test_stack_call_float_and_vector_memory_forms(tmp_path: Path) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, compiler = environment
    executable = tmp_path / "memory-forms"
    subprocess.run(
        [
            compiler,
            "-O0",
            "-fno-pie",
            "-no-pie",
            str(Path(__file__).parent / "native" / "memory_forms.c"),
            "-o",
            str(executable),
        ],
        check=True,
    )
    sites = {
        name: _symbol_address(executable, name)
        for name in (
            "bmo_push_site",
            "bmo_pop_site",
            "bmo_call_site",
            "bmo_ret_site",
            "bmo_fld_site",
            "bmo_fst_site",
            "bmo_vector_load_site",
            "bmo_vector_store_site",
        )
    }
    trace_dir = tmp_path / "trace"
    manifest = capture_program(
        (str(executable),), trace_dir, dynamorio_home=home, client_path=client
    )
    events_by_pc = {
        address: [
            event
            for path in event_files(trace_dir)
            for event in TraceReader(path)
            if event.pc == address
        ]
        for address in sites.values()
    }

    assert manifest.exit_code == 0
    assert manifest.dropped_events == 0, manifest.dropped_by_reason
    expected = {
        "bmo_push_site": (EventKind.STORE, 8),
        "bmo_pop_site": (EventKind.LOAD, 8),
        "bmo_call_site": (EventKind.STORE, 8),
        "bmo_ret_site": (EventKind.LOAD, 8),
        "bmo_fld_site": (EventKind.LOAD, 8),
        "bmo_fst_site": (EventKind.STORE, 8),
        "bmo_vector_load_site": (EventKind.LOAD, 16),
        "bmo_vector_store_site": (EventKind.STORE, 16),
    }
    for name, (kind, size) in expected.items():
        assert any(
            event.kind == kind and event.size == size
            for event in events_by_pc[sites[name]]
        ), name


@pytest.mark.skipif(_native_environment() is None, reason="native capture environment required")
def test_native_event_budget_marks_trace_unknown(tmp_path: Path) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, compiler = environment
    executable = tmp_path / "rep-budget"
    subprocess.run(
        [
            compiler,
            "-O0",
            str(Path(__file__).parent / "native" / "rep_string.c"),
            "-o",
            str(executable),
        ],
        check=True,
    )
    trace_dir = tmp_path / "trace"
    manifest = capture_program(
        (str(executable),),
        trace_dir,
        dynamorio_home=home,
        client_path=client,
        max_thread_events=10,
    )

    assert manifest.complete
    assert manifest.dropped_by_reason == {"resource_limit": 1}
    assert "per-thread event budget: 10" in manifest.limitations
    validation = validate_trace(trace_dir)
    assert not validation.valid
    assert "resource_limit" in " ".join(validation.reasons)


@pytest.mark.skipif(_native_environment() is None, reason="native capture environment required")
def test_relative_trace_path_survives_target_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = _native_environment()
    assert environment is not None
    home, client, _compiler = environment
    target_cwd = tmp_path / "target-cwd"
    target_cwd.mkdir()
    monkeypatch.chdir(tmp_path)

    manifest = capture_program(
        ("/bin/true",),
        Path("relative-trace"),
        dynamorio_home=home,
        client_path=client,
        working_directory=target_cwd,
    )

    assert manifest.complete
    assert (tmp_path / "relative-trace" / "manifest.json").is_file()
