from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from bmo_check_core import ProofFact
from bmo_check_static.binary.dependency_closure import build_program_manifest
from bmo_check_static.binary.angr_backend import load_cfg
from bmo_check_static.controlflow import recover_control_flow
from bmo_check_static.model import ExecutionScope, UnknownKind
from bmo_check_static.threading import (
    discover_pthread_threads,
    discover_pthread_threads_with_evidence,
)
from bmo_check_static.threading.callback import (
    resolve_argument_locations,
    resolve_callback_targets,
)


def _compile_recovery_app(tmp_path: Path) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.fail("gcc is required for CFG integration tests")
    source = tmp_path / "recovery.c"
    source.write_text(
        "#include <pthread.h>\n"
        "extern int puts(const char *);\n"
        "static void *worker(void *arg) { return arg; }\n"
        "#define FN(N) static __attribute__((noinline)) int f##N(void) { return N; }\n"
        "FN(0) FN(1) FN(2) FN(3) FN(4) FN(5) FN(6) FN(7)\n"
        "static int pick(int n) { switch (n) {\n"
        "case 0:return f0(); case 1:return f1(); case 2:return f2(); case 3:return f3();\n"
        "case 4:return f4(); case 5:return f5(); case 6:return f6(); case 7:return f7();\n"
        "default:return -1; } }\n"
        "static int (*volatile callback)(const char *);\n"
        "int main(int argc, char **argv) {\n"
        "  pthread_t thread;\n"
        "  pthread_create(&thread, 0, worker, (void *)7);\n"
        "  pthread_join(thread, 0);\n"
        "  puts(\"direct PLT\");\n"
        "  return callback ? callback(\"indirect\") : pick(argc);\n"
        "}\n",
        encoding="utf-8",
    )
    executable = tmp_path / "recovery-app"
    subprocess.run(
        [gcc, "-O2", "-fno-inline", "-o", str(executable), str(source), "-pthread"],
        check=True,
        capture_output=True,
        text=True,
    )
    return executable


def _manifest(executable: Path):
    roots = tuple(
        path
        for path in (
            Path("/lib64"),
            Path("/lib/x86_64-linux-gnu"),
            Path("/usr/lib/x86_64-linux-gnu"),
        )
        if path.is_dir()
    )
    return build_program_manifest(
        executable,
        roots,
        ExecutionScope(),
        "dbt6-mo-off-v1",
        "test-revision",
    )


def test_cfg_marks_every_indirect_site_complete_or_explicitly_incomplete(
    tmp_path: Path,
) -> None:
    manifest = _manifest(_compile_recovery_app(tmp_path))
    assert manifest.executable is not None
    report = recover_control_flow(manifest.executable, manifest)

    assert any(call.target_symbol == "puts" for call in report.call_sites)
    assert report.indirect_sites
    assert all(site.targets.complete or site.targets.reason for site in report.indirect_sites)
    assert any(not site.targets.complete for site in report.indirect_sites)
    assert any(
        fact.kind == UnknownKind.INCOMPLETE_INDIRECT_TARGET
        for fact in report.unknowns
    )


def test_pthread_create_recovers_direct_worker_and_join_role(tmp_path: Path) -> None:
    manifest = _manifest(_compile_recovery_app(tmp_path))
    assert manifest.executable is not None
    control_flow = recover_control_flow(manifest.executable, manifest)
    report = discover_pthread_threads(manifest.executable, manifest, control_flow)

    assert len(report.creates) == 1
    assert report.creates[0].start_targets.complete
    assert report.creates[0].start_targets.known_targets[0].symbol == "worker"
    assert len(report.joins) == 1
    assert report.joins[0].complete
    assert report.joins[0].candidate_child_roles == (report.creates[0].child_role,)
    assert not any(item.kind == UnknownKind.UNKNOWN_THREAD_ENTRY for item in report.unknowns)


def test_runtime_pthread_callback_stays_unknown(tmp_path: Path) -> None:
    gcc = shutil.which("gcc")
    assert gcc is not None
    source = tmp_path / "unknown-worker.c"
    source.write_text(
        "#include <pthread.h>\n"
        "static void launch(void *(*start)(void *)) {\n"
        "  pthread_t thread; pthread_create(&thread, 0, start, 0);\n"
        "}\n"
        "int main(int argc, char **argv) {\n"
        "  launch((void *(*)(void *))(argc > 1 ? argv[1] : 0)); return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    executable = tmp_path / "unknown-worker"
    subprocess.run(
        [gcc, "-O1", "-fno-inline", "-o", str(executable), str(source), "-pthread"],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = _manifest(executable)
    assert manifest.executable is not None
    control_flow = recover_control_flow(manifest.executable, manifest)
    report = discover_pthread_threads(manifest.executable, manifest, control_flow)

    assert len(report.creates) == 1
    assert report.creates[0].parent_role == "main"
    assert not report.creates[0].start_targets.complete
    assert any(item.kind == UnknownKind.UNKNOWN_THREAD_ENTRY for item in report.unknowns)


def test_parameterized_pthread_wrapper_recovers_closed_callback(tmp_path: Path) -> None:
    gcc = shutil.which("gcc")
    assert gcc is not None
    source = tmp_path / "wrapper-worker.c"
    source.write_text(
        "#include <pthread.h>\n"
        "static void *worker(void *arg) { return arg; }\n"
        "static void launch(void *(*start)(void *), void *arg) {\n"
        "  pthread_t thread; pthread_create(&thread, 0, start, arg);\n"
        "  pthread_join(thread, 0);\n"
        "}\n"
        "int main(void) { launch(worker, 0); return 0; }\n",
        encoding="utf-8",
    )
    executable = tmp_path / "wrapper-worker"
    subprocess.run(
        [gcc, "-O2", "-fno-inline", "-o", str(executable), str(source), "-pthread"],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = _manifest(executable)
    assert manifest.executable is not None
    control_flow = recover_control_flow(manifest.executable, manifest)
    report = discover_pthread_threads(manifest.executable, manifest, control_flow)

    assert len(report.creates) == 1
    assert report.creates[0].start_targets.complete
    assert report.creates[0].start_targets.known_targets[0].symbol == "worker"
    assert report.creates[0].parent_role == "main"
    assert not any(item.kind == UnknownKind.UNKNOWN_THREAD_ENTRY for item in report.unknowns)

    # 回调和 pthread_t 槽位必须沿同一条 wrapper 调用链恢复；只恢复函数地址
    # 会让 join 仍然依赖“恰好只有一个 child”的不安全猜测。
    create_call = next(
        call
        for call in control_flow.call_sites
        if call.target_symbol == "pthread_create"
    )
    context = load_cfg(manifest.executable)
    callback = resolve_callback_targets(
        context, manifest.executable, control_flow, create_call, "rdx"
    )
    handle = resolve_argument_locations(
        context, manifest.executable, control_flow, create_call, "rdi"
    )
    assert callback.complete
    assert callback.call_contexts
    assert handle.complete
    assert handle.locations


def test_multiple_wrapper_calls_map_join_handles_to_distinct_roles(
    tmp_path: Path,
) -> None:
    gcc = shutil.which("gcc")
    assert gcc is not None
    source = tmp_path / "multi-wrapper.c"
    source.write_text(
        "#include <pthread.h>\n"
        "typedef void *(*start_fn)(void *);\n"
        "static volatile int sink;\n"
        "static __attribute__((noinline)) void *worker_a(void *arg) { sink = 1; return arg; }\n"
        "static __attribute__((noinline)) void *worker_b(void *arg) { sink = 2; return arg; }\n"
        "static __attribute__((noinline)) void launch(pthread_t *slot, start_fn fn) {\n"
        "  pthread_create(slot, 0, fn, 0);\n"
        "}\n"
        "static __attribute__((noinline)) void wait_one(pthread_t *slot) {\n"
        "  pthread_join(*slot, 0);\n"
        "}\n"
        "int main(void) {\n"
        "  pthread_t first, second;\n"
        "  launch(&first, worker_a); launch(&second, worker_b);\n"
        "  wait_one(&first); wait_one(&second);\n"
        "  return sink == 2 ? 0 : 1;\n"
        "}\n",
        encoding="utf-8",
    )
    executable = tmp_path / "multi-wrapper"
    subprocess.run(
        [
            gcc,
            "-O0",
            "-fno-omit-frame-pointer",
            "-o",
            str(executable),
            str(source),
            "-pthread",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = _manifest(executable)
    assert manifest.executable is not None
    control_flow = recover_control_flow(manifest.executable, manifest)
    report = discover_pthread_threads(manifest.executable, manifest, control_flow)

    assert len(report.creates) == 2
    assert {fact.parent_role for fact in report.creates} == {"main"}
    assert all(fact.start_targets.complete for fact in report.creates)
    assert all(fact.handle_locations for fact in report.creates)
    assert len(report.joins) == 2
    assert all(fact.complete for fact in report.joins)
    assert {
        role
        for fact in report.joins
        for role in fact.candidate_child_roles
    } == {fact.child_role for fact in report.creates}
    assert not any(
        item.kind
        in {
            UnknownKind.UNKNOWN_THREAD_ENTRY,
            UnknownKind.UNKNOWN_JOIN_RELATION,
        }
        for item in report.unknowns
    )

    evidence = discover_pthread_threads_with_evidence(
        manifest.executable,
        manifest,
        control_flow,
    )
    assert evidence.report == report
    assert evidence.proof_ids
    assert all(
        isinstance(evidence.ledger.get(item), ProofFact)
        for item in evidence.proof_ids
    )


def test_wrapper_called_from_main_and_worker_keeps_lifecycle_contexts(
    tmp_path: Path,
) -> None:
    """同一 callback wrapper 的不同父角色必须各自形成可回查生命周期事实。"""

    gcc = shutil.which("gcc")
    assert gcc is not None
    source = tmp_path / "multi-caller-wrapper.c"
    source.write_text(
        "#include <pthread.h>\n"
        "typedef void *(*start_fn)(void *);\n"
        "static volatile int sink;\n"
        "static __attribute__((noinline)) void *worker(void *arg) { sink = 1; return arg; }\n"
        "static __attribute__((noinline)) void launch(start_fn fn) {\n"
        "  pthread_t local; pthread_create(&local, 0, fn, 0);\n"
        "  pthread_join(local, 0);\n"
        "}\n"
        "static __attribute__((noinline)) void *parent(void *arg) {\n"
        "  launch(worker); return arg;\n"
        "}\n"
        "int main(void) {\n"
        "  pthread_t outer; pthread_create(&outer, 0, parent, 0);\n"
        "  launch(worker); pthread_join(outer, 0);\n"
        "  return sink != 1;\n"
        "}\n",
        encoding="utf-8",
    )
    executable = tmp_path / "multi-caller-wrapper"
    subprocess.run(
        [
            gcc,
            "-O0",
            "-fno-omit-frame-pointer",
            "-o",
            str(executable),
            str(source),
            "-pthread",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = _manifest(executable)
    assert manifest.executable is not None
    control_flow = recover_control_flow(manifest.executable, manifest)
    report = discover_pthread_threads(manifest.executable, manifest, control_flow)

    assert len(report.creates) == 3
    assert all(fact.start_targets.complete for fact in report.creates)
    assert all(fact.handle_locations for fact in report.creates)
    assert len(report.joins) == 3
    assert all(fact.complete for fact in report.joins)
    assert {fact.parent_role for fact in report.creates} == {
        "main",
        next(
            fact.child_role
            for fact in report.creates
            if fact.start_targets.known_targets[0].symbol == "parent"
        ),
    }
    assert not any(
        item.kind
        in {
            UnknownKind.REACHING_DEFINITION_FAILURE,
            UnknownKind.UNKNOWN_THREAD_ENTRY,
            UnknownKind.UNKNOWN_JOIN_RELATION,
        }
        for item in report.unknowns
    )


def test_openmp_wrapper_keeps_parallel_contexts_per_caller(tmp_path: Path) -> None:
    """OpenMP callback 也按调用点区分 main 与 worker 的并行阶段。"""

    gcc = shutil.which("gcc")
    assert gcc is not None
    source = tmp_path / "openmp-wrapper.c"
    source.write_text(
        "#include <pthread.h>\n"
        "static volatile int sink;\n"
        "static __attribute__((noinline)) void run_parallel(void) {\n"
        "  #pragma omp parallel\n"
        "  { sink += 1; }\n"
        "}\n"
        "static __attribute__((noinline)) void *parent(void *arg) {\n"
        "  run_parallel(); return arg;\n"
        "}\n"
        "int main(void) {\n"
        "  pthread_t outer; pthread_create(&outer, 0, parent, 0);\n"
        "  run_parallel(); pthread_join(outer, 0);\n"
        "  return sink == 0;\n"
        "}\n",
        encoding="utf-8",
    )
    executable = tmp_path / "openmp-wrapper"
    subprocess.run(
        [
            gcc,
            "-O0",
            "-fno-omit-frame-pointer",
            "-fopenmp",
            "-o",
            str(executable),
            str(source),
            "-pthread",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = _manifest(executable)
    assert manifest.executable is not None
    control_flow = recover_control_flow(manifest.executable, manifest)
    report = discover_pthread_threads(manifest.executable, manifest, control_flow)

    assert len(report.creates) == 1
    assert report.creates[0].parent_role == "main"
    assert report.creates[0].start_targets.complete
    assert len(report.parallel_regions) == 2
    assert all(region.complete for region in report.parallel_regions)
    assert not any(
        item.kind
        in {
            UnknownKind.REACHING_DEFINITION_FAILURE,
            UnknownKind.UNKNOWN_THREAD_ENTRY,
        }
        for item in report.unknowns
    )
