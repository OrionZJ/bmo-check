from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from bmo_check_static.analysis import analyze_shared_state, extract_memory_events
from bmo_check_static.binary.dependency_closure import build_program_manifest
from bmo_check_static.controlflow import recover_control_flow
from bmo_check_static.model import (
    AddressKind,
    ExecutionScope,
    ProofReason,
    Ordering,
    SynchronizationKind,
    SynchronizationReport,
    SynchronizationSummary,
    SharingClass,
    UnknownKind,
)
from bmo_check_static.slicing import build_shared_memory_slice
from bmo_check_static.threading import discover_pthread_threads


def _compile(tmp_path: Path, name: str, source_text: str) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.fail("gcc is required for shared-state integration tests")
    source = tmp_path / f"{name}.c"
    source.write_text(source_text, encoding="utf-8")
    executable = tmp_path / name
    subprocess.run(
        [
            gcc,
            "-O1",
            "-fno-inline",
            "-fno-stack-protector",
            "-o",
            str(executable),
            str(source),
            "-pthread",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return executable


def _pipeline(
    executable: Path,
    *,
    create_release: bool = False,
    normal_completion_only: bool = False,
):
    roots = tuple(
        path
        for path in (
            Path("/lib64"),
            Path("/lib/x86_64-linux-gnu"),
            Path("/usr/lib/x86_64-linux-gnu"),
        )
        if path.is_dir()
    )
    manifest = build_program_manifest(
        executable,
        roots,
        ExecutionScope(thread_count_min=2, thread_count_max=4),
        "dbt6-mo-off-v1",
        "test-revision",
    )
    assert manifest.executable is not None
    cfg = recover_control_flow(manifest.executable, manifest)
    threads = discover_pthread_threads(manifest.executable, manifest, cfg)
    synchronization = ()
    if create_release:
        synchronization = (
            SynchronizationReport(
                contract_version="dbt6-mo-off-v1",
                library_path="libpthread-fixture.so",
                library_sha256="b" * 64,
                summaries=(
                    SynchronizationSummary(
                        api="pthread_create",
                        kind=SynchronizationKind.THREAD_CREATE,
                        required_ordering=Ordering.RELEASE,
                        module_path="libpthread-fixture.so",
                        module_sha256="b" * 64,
                        function_pc=0x1000,
                        function_size=1,
                        target_ordering=Ordering.RELEASE,
                        complete=True,
                    ),
                ),
            ),
        )
    events = extract_memory_events(
        manifest.executable, cfg, threads, synchronization
    )
    state = analyze_shared_state(
        manifest.executable,
        cfg,
        threads,
        events,
        normal_completion_only=normal_completion_only,
    )
    shared_slice = build_shared_memory_slice(events, state, threads)
    return events, state, shared_slice


def test_tls_and_readonly_after_create_are_pruned_with_proofs(tmp_path: Path) -> None:
    executable = _compile(
        tmp_path,
        "tls-readonly",
        "#include <pthread.h>\n"
        "static volatile int shared_data;\n"
        "static __thread volatile int local_tls;\n"
        "static void *worker(void *arg) { local_tls = shared_data; return 0; }\n"
        "int main(void) { pthread_t t; shared_data = 7; "
        "pthread_create(&t, 0, worker, 0); pthread_join(t, 0); return 0; }\n",
    )
    _, state, shared_slice = _pipeline(executable, create_release=True)

    reasons = {proof.reason for proof in state.proofs}
    assert ProofReason.TLS_STORAGE in reasons
    assert ProofReason.READ_ONLY_AFTER_CREATE in reasons
    assert any(obj.address.kind == AddressKind.TLS for obj in state.objects)
    assert any(obj.sharing == SharingClass.READ_ONLY_AFTER_CREATE for obj in state.objects)
    assert shared_slice.coverage.thread_local_removed > 0
    assert shared_slice.coverage.readonly_removed > 0


def test_unescaped_stack_is_local_but_passed_stack_pointer_is_unknown(
    tmp_path: Path,
) -> None:
    local = _compile(
        tmp_path,
        "local-stack",
        "int main(void) { volatile int value = 3; return value; }\n",
    )
    _, local_state, _ = _pipeline(local)
    assert any(
        proof.reason == ProofReason.UNESCAPED_STACK for proof in local_state.proofs
    )

    escaped = _compile(
        tmp_path,
        "escaped-stack",
        "#include <pthread.h>\n"
        "static void *worker(void *arg) { return (void *)(long)*(volatile int *)arg; }\n"
        "int main(void) { pthread_t t; volatile int value = 3; volatile int local = 4; "
        "pthread_create(&t, 0, worker, (void *)&value); pthread_join(t, 0); return local; }\n",
    )
    _, escaped_state, escaped_slice = _pipeline(escaped)
    assert any(
        item.kind == UnknownKind.UNKNOWN_ESCAPE for item in escaped_state.unknowns
    )
    stack_event_ids = {
        event_id
        for obj in escaped_state.objects
        if obj.address.kind == AddressKind.STACK
        for event_id in obj.event_ids
    }
    assert stack_event_ids.intersection(escaped_state.kept_event_ids)
    assert any(event.id in stack_event_ids for event in escaped_slice.events)
    assert any(
        proof.reason == ProofReason.UNESCAPED_STACK
        for proof in escaped_state.proofs
    )

    opaque = _compile(
        tmp_path,
        "opaque-stack",
        "static void (*volatile sink)(void *);\n"
        "int main(void) { volatile int value = 3; "
        "if (sink) sink((void *)&value); return value; }\n",
    )
    opaque_events, opaque_state, opaque_slice = _pipeline(opaque)
    assert any(event.kind.value == "OpaqueCall" for event in opaque_events.events)
    assert any(item.kind == UnknownKind.UNKNOWN_ESCAPE for item in opaque_state.unknowns)
    assert opaque_slice.coverage.unknown_events > 0


def test_dynamic_stack_escape_does_not_poison_fixed_frame_slots(
    tmp_path: Path,
) -> None:
    executable = _compile(
        tmp_path,
        "dynamic-stack",
        "#include <pthread.h>\n"
        "static void *worker(void *arg) { ((volatile int *)arg)[0] = 7; return 0; }\n"
        "int main(int argc, char **argv) { pthread_t t; volatile int fixed = argc; "
        "volatile int values[argc + 2]; pthread_create(&t, 0, worker, (void *)values); "
        "pthread_join(t, 0); return fixed + (argv != 0); }\n",
    )
    _, state, _ = _pipeline(executable)

    # VLA 会跨线程，但编译器为它下移 rsp；这不能污染上方的固定栈槽。
    assert any(
        proof.reason == ProofReason.UNESCAPED_STACK
        and any("never materialized" in fact for fact in proof.supporting_facts)
        for proof in state.proofs
    )


def test_normal_completion_scope_removes_only_blocks_without_return_path(
    tmp_path: Path,
) -> None:
    executable = _compile(
        tmp_path,
        "normal-completion",
        "#include <stdlib.h>\n"
        "static volatile int fail; static volatile int shared;\n"
        "static int work(void) { if (fail) { shared = 9; abort(); } "
        "shared = 7; return shared; }\n"
        "int main(void) { return work(); }\n",
    )
    events, state, _ = _pipeline(executable, normal_completion_only=True)

    proof = next(
        item for item in state.proofs
        if item.reason == ProofReason.NON_RETURNING_PATH
    )
    removed = {event.id for event in events.events if event.id in proof.event_ids}
    assert removed
    assert any(event.pc for event in events.events if event.id in removed)
    assert any(
        event.provenance.get("can_reach_function_return") is True
        and event.id not in removed
        for event in events.events
    )
