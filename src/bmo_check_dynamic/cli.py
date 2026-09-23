from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import time
import sys
try:
    import resource
except ImportError:  # pragma: no cover - benchmark workers run on Linux/WSL.
    resource = None
from pathlib import Path

import yaml

from bmo_check_dynamic.application import (
    AnalyzeRequest,
    CaptureRequest,
    analyze as analyze_request,
    candidate_slices as candidate_slices_request,
    characterize as characterize_request,
    slice_plan as slice_plan_request,
    obligation_bottleneck as obligation_bottleneck_request,
    cycle_relevance as cycle_relevance_request,
    ppo_reduction as ppo_reduction_request,
    ppo_certificate_profile as ppo_certificate_profile_request,
    ppo_replay as ppo_replay_request,
    ppo_solver as ppo_solver_request,
    ppo_solver_replay as ppo_solver_replay_request,
    ppo_solver_side as ppo_solver_side_request,
    graph_first as graph_first_request,
    cegar_prototype as cegar_request,
    cegar_ab as cegar_ab_request,
    p17_global_validation as p17_global_validation_request,
    capture as capture_request,
)
from bmo_check_dynamic.capture import CaptureError
from bmo_check_dynamic.adapters import (
    DynamicTraceBindingError,
    replay_dynamic_certificate,
)
from bmo_check_dynamic.analysis import find_frozen_p15_mode, locate_instruction_site
from bmo_check_dynamic.analysis import run_isolated_solver_benchmark
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import (
    CampaignMember,
    CampaignSummary,
    DynamicCertificate,
    TracePpoReductionCertificate,
    CegarExperimentMode,
    CandidateDiscoveryResourcePolicy,
    TraceReducedSolverRunCertificate,
    CegarExperimentReport,
    GlobalConstraintValidationReport,
    TraceVerdict,
    BenchmarkSide,
    SolverBenchmarkChildReport,
    ShadowSolverPhase,
    SolverDiagnosticProfile,
)
from bmo_check_dynamic.storage import TraceStoreError
from bmo_check_dynamic.report import explain_certificate


EXIT_CODES = {
    TraceVerdict.TRACE_SAFE: 0,
    TraceVerdict.COUNTEREXAMPLE: 1,
    TraceVerdict.UNKNOWN: 2,
}


def _default_contract() -> Path:
    repository_spec = (
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml"
    )
    if repository_spec.is_file():
        return repository_spec
    return Path(__file__).resolve().parent / "data" / "dbt6-mo-off.yaml"


def _environment(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, content = value.partition("=")
        if not separator or not key:
            raise argparse.ArgumentTypeError("--env requires KEY=VALUE")
        result[key] = content
    return result


def _command(values: list[str]) -> tuple[str, ...]:
    if values and values[0] == "--":
        values = values[1:]
    if not values:
        raise argparse.ArgumentTypeError("missing program after --")
    return tuple(values)


def _capture(args: argparse.Namespace) -> int:
    manifest = capture_request(
        CaptureRequest(
            command=_command(args.command),
            output_dir=args.output,
            dynamorio_home=args.dynamorio_home,
            client_path=args.client,
            environment=tuple(sorted(_environment(args.env).items())),
            working_directory=args.cwd,
            max_thread_events=args.max_thread_events,
        )
    )
    print(manifest.model_dump_json(indent=2))
    return 0 if manifest.complete else 2


def _analysis_config(args: argparse.Namespace) -> DynamicConfig:
    return DynamicConfig(
        max_window_events=args.max_window_events,
        max_executions=args.max_executions,
        max_communication_edges=args.max_communication_edges,
        max_communication_active_events=args.max_communication_active_events,
        max_object_events=args.max_object_events,
        max_pages_per_access=args.max_pages_per_access,
        batch_size=args.batch_size,
        solver_timeout_ms=args.solver_timeout_ms,
        max_symbolic_terms=args.max_symbolic_terms,
        database_memory_limit_mb=args.database_memory_limit_mb,
        database_path=args.database,
        application_only=args.application_only,
    )


def _analyze(args: argparse.Namespace) -> int:
    certificate = analyze_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(certificate.model_dump_json(indent=2), encoding="utf-8")
    print(explain_certificate(certificate))
    return EXIT_CODES[certificate.verdict]


def _characterize(args: argparse.Namespace) -> int:
    report = characterize_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _slice_candidates(args: argparse.Namespace) -> int:
    report = candidate_slices_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _slice_plan(args: argparse.Namespace) -> int:
    report = slice_plan_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _obligation_bottleneck(args: argparse.Namespace) -> int:
    report = obligation_bottleneck_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    # 这是只读表征命令，不把诊断状态映射成 verdict exit code。
    return 0


def _cycle_relevance(args: argparse.Namespace) -> int:
    report = cycle_relevance_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _ppo_reduction(args: argparse.Namespace) -> int:
    report = ppo_reduction_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if args.certificate is not None:
        certificate = TracePpoReductionCertificate(
            trace_id=report.trace_id,
            windows=tuple(item.certificate for item in report.windows),
        )
        args.certificate.parent.mkdir(parents=True, exist_ok=True)
        args.certificate.write_text(
            certificate.model_dump_json(indent=2),
            encoding="utf-8",
        )
    print(report.model_dump_json(indent=2))
    return 0


def _ppo_certificate_profile(args: argparse.Namespace) -> int:
    report = ppo_certificate_profile_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        cache_dir=args.cache_dir,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _graph_first(args: argparse.Namespace) -> int:
    reduction = None
    if args.reduction_certificate is not None:
        reduction = TracePpoReductionCertificate.model_validate_json(
            args.reduction_certificate.read_text(encoding="utf-8")
        )
    report = graph_first_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        reduction,
        max_cycle_length=args.max_cycle_length,
        max_cycles=args.max_cycles,
        max_search_states=args.max_search_states,
        local_timeout_ms=args.local_timeout_ms,
        local_max_symbolic_terms=args.local_max_symbolic_terms,
        execute_local_solver=not args.encoding_only,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    # graph-first 是 bounded shadow diagnosis，永远不把 local SAT/UNSAT
    # 映射成 TRACE_SAFE、COUNTEREXAMPLE 或 UNKNOWN 退出码。
    return 0


def _cegar_prototype(args: argparse.Namespace) -> int:
    reduction = None
    if args.reduction_certificate is not None:
        reduction = TracePpoReductionCertificate.model_validate_json(
            args.reduction_certificate.read_text(encoding="utf-8")
        )
    report = cegar_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        reduction,
        max_cycle_length=args.max_cycle_length,
        max_search_states=args.max_search_states,
        max_local_queries=args.max_local_queries,
        max_generated_candidates=args.max_generated_candidates,
        local_timeout_ms=args.local_timeout_ms,
        local_max_symbolic_terms=args.local_max_symbolic_terms,
        execute_local_solver=not args.encoding_only,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    # CEGAR 仍是 bounded diagnostic：即使找到 replay-valid candidate，
    # 也不能把结果映射为正式 COUNTEREXAMPLE 或 SAFE。
    return 0


def _cegar_ab(args: argparse.Namespace) -> int:
    reduction = None
    if args.reduction_certificate is not None:
        reduction = TracePpoReductionCertificate.model_validate_json(
            args.reduction_certificate.read_text(encoding="utf-8")
        )
    report = cegar_ab_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        reduction,
        fixture=args.fixture,
        max_cycle_length=args.max_cycle_length,
        max_search_states=args.max_search_states,
        max_local_queries=args.max_local_queries,
        local_timeout_ms=args.local_timeout_ms,
        local_max_symbolic_terms=args.local_max_symbolic_terms,
        execute_local_solver=not args.encoding_only,
        include_structured=args.include_structured,
        only_mode=(
            CegarExperimentMode(args.only_mode)
            if args.only_mode is not None
            else None
        ),
        discovery_only=args.discovery_only,
        include_bounded=args.include_bounded,
        include_candidate_records=args.include_candidate_records,
        capture_model=args.capture_model,
        close_feasible_candidates=args.close_feasible_candidates,
        closure_timeout_ms=args.closure_timeout_ms,
        closure_max_symbolic_terms=args.closure_max_symbolic_terms,
        discovery_resource_policy=(
            CandidateDiscoveryResourcePolicy(
                max_in_memory_frontier=args.max_in_memory_frontier,
                max_rss_mb=args.max_rss_mb,
                max_search_states=args.max_search_states,
                max_wall_time_ms=args.max_wall_time_ms,
                sample_every=args.memory_sample_every,
                checkpoint_path=(str(args.checkpoint) if args.checkpoint else None),
                resume_checkpoint=(str(args.resume_checkpoint) if args.resume_checkpoint else None),
                progress_path=(str(args.progress) if args.progress else None),
            )
            if args.include_bounded or args.only_mode == CegarExperimentMode.STRUCTURED_P15.value
            else None
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _write_json_atomically(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.writing")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _p17_global_validation_worker(args: argparse.Namespace) -> int:
    if os.environ.get("BMO_P17_LIMITED_WORKER") != "1":
        raise ValueError("P17 worker must be launched by the bounded parent command")
    if resource is None or os.name != "posix":
        raise ValueError("bounded P17 worker requires POSIX resource limits")
    address_space_limit = args.process_memory_limit_mb * 1024 * 1024
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_AS)
    if (
        soft_limit == resource.RLIM_INFINITY
        or hard_limit == resource.RLIM_INFINITY
        or soft_limit > address_space_limit
        or hard_limit > address_space_limit
    ):
        raise ValueError("P17 worker address-space limit was not installed by its parent")
    candidate_report = CegarExperimentReport.model_validate_json(
        args.fixed_candidate_report.read_text(encoding="utf-8")
    )
    reduction_certificate = TracePpoReductionCertificate.model_validate_json(
        args.reduction_certificate.read_text(encoding="utf-8")
    )
    report = p17_global_validation_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        candidate_report,
        reduction_certificate,
        partial_timeout_ms=args.partial_timeout_ms,
        full_timeout_ms=args.full_timeout_ms,
        max_symbolic_terms=args.p17_max_symbolic_terms,
        max_queries_per_solver_session=args.max_queries_per_solver_session,
        process_wall_limit_seconds=args.process_wall_limit_seconds,
        process_memory_limit_mb=args.process_memory_limit_mb,
        expected_candidate_count=args.expected_candidate_count,
        progress_path=args.progress,
    )
    report = report.model_copy(
        update={"resource_enforcement": "posix_rlimit_as+parent_wall_timeout"}
    )
    _write_json_atomically(args.output, report.model_dump_json(indent=2))
    return 0


def _p17_global_validation(args: argparse.Namespace) -> int:
    if resource is None or os.name != "posix":
        raise ValueError("bounded P17 execution requires WSL/Linux resource limits")
    if args.process_wall_limit_seconds <= 0 or args.process_memory_limit_mb <= 0:
        raise ValueError("P17 wall and address-space limits must be positive")
    progress_path = args.progress or args.output.with_name(
        f"{args.output.stem}.progress{args.output.suffix}"
    )
    if args.output.resolve() == progress_path.resolve():
        raise ValueError("P17 final report and progress checkpoint paths must differ")
    stdout_path = args.output.with_name(f"{args.output.name}.stdout.log")
    stderr_path = args.output.with_name(f"{args.output.name}.stderr.log")
    occupied = tuple(
        path
        for path in (args.output, progress_path, stdout_path, stderr_path)
        if path.exists()
    )
    if occupied:
        raise ValueError(
            "refusing to overwrite P17 outputs: "
            + ", ".join(str(path) for path in occupied)
        )
    candidate_report = CegarExperimentReport.model_validate_json(
        args.fixed_candidate_report.read_text(encoding="utf-8")
    )
    comparison, frozen = find_frozen_p15_mode(candidate_report)
    command = [
        sys.executable,
        "-m",
        "bmo_check_dynamic.cli",
        "_p17-global-validation-worker",
        str(args.trace.resolve()),
        "--fixed-candidate-report",
        str(args.fixed_candidate_report.resolve()),
        "--reduction-certificate",
        str(args.reduction_certificate.resolve()),
        "--output",
        str(args.output.resolve()),
        "--progress",
        str(progress_path.resolve()),
        "--partial-timeout-ms",
        str(args.partial_timeout_ms),
        "--full-timeout-ms",
        str(args.full_timeout_ms),
        "--p17-max-symbolic-terms",
        str(args.p17_max_symbolic_terms),
        "--max-queries-per-solver-session",
        str(args.max_queries_per_solver_session),
        "--process-wall-limit-seconds",
        str(args.process_wall_limit_seconds),
        "--process-memory-limit-mb",
        str(args.process_memory_limit_mb),
        "--expected-candidate-count",
        str(args.expected_candidate_count),
        "--dbt-contract",
        str(args.dbt_contract.resolve()),
        "--max-window-events",
        str(args.max_window_events),
        "--max-executions",
        str(args.max_executions),
        "--max-communication-edges",
        str(args.max_communication_edges),
        "--max-communication-active-events",
        str(args.max_communication_active_events),
        "--max-object-events",
        str(args.max_object_events),
        "--max-pages-per-access",
        str(args.max_pages_per_access),
        "--batch-size",
        str(args.batch_size),
        "--solver-timeout-ms",
        str(args.solver_timeout_ms),
        "--max-symbolic-terms",
        str(args.max_symbolic_terms),
        "--database-memory-limit-mb",
        str(args.database_memory_limit_mb),
    ]
    if args.database is not None:
        command.extend(("--database", str(args.database.resolve())))
    if args.application_only:
        command.append("--application-only")

    limit_bytes = args.process_memory_limit_mb * 1024 * 1024

    def impose_address_space_limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))

    environment = os.environ.copy()
    environment["BMO_P17_LIMITED_WORKER"] = "1"
    started = time.monotonic()
    timed_out = False
    return_code: int | None = None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        worker = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            env=environment,
            start_new_session=True,
            preexec_fn=impose_address_space_limit,
        )
        try:
            return_code = worker.wait(timeout=args.process_wall_limit_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(worker.pid, signal.SIGTERM)
                worker.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(worker.pid, signal.SIGKILL)
                return_code = worker.wait()
            except ProcessLookupError:
                return_code = worker.poll()
            if return_code is None:
                return_code = worker.poll()
    wall_ms = max(0, int((time.monotonic() - started) * 1000))
    peak_rss_mb = None
    if resource is not None:
        peak_rss_mb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024

    source = args.output if args.output.is_file() else progress_path
    if source.is_file():
        report = GlobalConstraintValidationReport.model_validate_json(
            source.read_text(encoding="utf-8")
        )
    else:
        report = GlobalConstraintValidationReport(
            trace_id=candidate_report.trace_id or "unknown",
            trace_sha256=candidate_report.trace_sha256 or "unknown",
            contract_sha256=candidate_report.contract_sha256 or "unknown",
            window_id=comparison.window_id,
            event_count=comparison.event_count,
            ppo_certificate_digest=comparison.certificate_digest or "unknown",
            candidate_skeleton_ids=frozen.candidate_skeleton_ids,
            max_partial_timeout_ms=args.partial_timeout_ms,
            max_full_timeout_ms=args.full_timeout_ms,
            max_symbolic_terms=args.p17_max_symbolic_terms,
            max_queries_per_solver_session=args.max_queries_per_solver_session,
            process_wall_limit_seconds=args.process_wall_limit_seconds,
            process_memory_limit_mb=args.process_memory_limit_mb,
            limitations=("Worker exited before writing its first progress checkpoint.",),
        )
    if timed_out:
        termination_reason = "process_wall_limit_exceeded"
    elif return_code == 0 and args.output.is_file():
        termination_reason = "completed"
    elif return_code is not None and return_code < 0:
        termination_reason = f"worker_terminated_by_signal_{-return_code}"
    else:
        termination_reason = "worker_failed"
    report = report.model_copy(
        update={
            "termination_reason": termination_reason,
            "resource_enforcement": "posix_rlimit_as+parent_wall_timeout",
            "process_peak_rss_mb": peak_rss_mb,
            "worker_wall_time_ms": wall_ms,
            "worker_exit_code": return_code,
            "limitations": tuple(
                dict.fromkeys(
                    report.limitations
                    + (
                        f"Worker outcome: {termination_reason}; the latest durable progress checkpoint is retained.",
                        "Address-space cap is RLIMIT_AS; peak RSS is measured separately.",
                    )
                )
            ),
        }
    )
    _write_json_atomically(args.output, report.model_dump_json(indent=2))
    print(
        json.dumps(
            {
                "output": str(args.output),
                "termination_reason": report.termination_reason,
                "completed_progressive_candidates": len(report.progressive_runs),
                "completed_incremental_sessions": len(report.incremental_session_builds),
                "worker_wall_time_ms": report.worker_wall_time_ms,
                "process_peak_rss_mb": report.process_peak_rss_mb,
            },
            ensure_ascii=False,
        )
    )
    return 0 if termination_reason == "completed" else 2


def _ppo_replay(args: argparse.Namespace) -> int:
    certificate = TracePpoReductionCertificate.model_validate_json(
        args.certificate.read_text(encoding="utf-8")
    )
    report = ppo_replay_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        certificate,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0 if all(item.accepted for item in report.windows) else 2


def _ppo_solver(args: argparse.Namespace) -> int:
    reduction = None
    if args.reduction_certificate is not None:
        reduction = TracePpoReductionCertificate.model_validate_json(
            args.reduction_certificate.read_text(encoding="utf-8")
        )
    report, certificate = ppo_solver_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        reduction,
        execute_solver=not args.encoding_only,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if args.certificate is not None:
        args.certificate.parent.mkdir(parents=True, exist_ok=True)
        args.certificate.write_text(
            certificate.model_dump_json(indent=2),
            encoding="utf-8",
        )
    print(report.model_dump_json(indent=2))
    return 0


def _ppo_solver_replay(args: argparse.Namespace) -> int:
    reduction = TracePpoReductionCertificate.model_validate_json(
        args.reduction_certificate.read_text(encoding="utf-8")
    )
    solver = TraceReducedSolverRunCertificate.model_validate_json(
        args.certificate.read_text(encoding="utf-8")
    )
    report = ppo_solver_replay_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        reduction,
        solver,
        execute_solver=not args.encoding_only,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0 if all(item.accepted for item in report.windows) else 2


def _worker_rusage() -> tuple[float, float, float | None]:
    if resource is None:
        return 0.0, 0.0, None
    usage = resource.getrusage(resource.RUSAGE_SELF)
    rss = float(usage.ru_maxrss)
    if sys.platform != "darwin":
        rss /= 1024.0
    else:
        rss /= 1024.0 * 1024.0
    return usage.ru_utime, usage.ru_stime, rss


def _ppo_solver_worker(args: argparse.Namespace) -> int:
    reduction = None
    if args.reduction_certificate is not None:
        reduction = TracePpoReductionCertificate.model_validate_json(
            args.reduction_certificate.read_text(encoding="utf-8")
        )
    started = time.perf_counter()
    before_user, before_system, _ = _worker_rusage()
    report = ppo_solver_side_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        BenchmarkSide(args.side),
        reduction,
        execute_solver=args.phase == ShadowSolverPhase.SOLVER.value,
        repetition=args.repetition,
        budget_ms=args.budget_ms,
        profile=SolverDiagnosticProfile(args.profile),
    )
    after_user, after_system, peak_rss = _worker_rusage()
    wall_time_ms = max(0, int((time.perf_counter() - started) * 1000))
    replay_time_ms = sum(window.ppo_replay_time_ms for window in report.windows)
    build_time_ms = sum(window.build_time_ms for window in report.windows)
    solver_time_ms = sum(
        window.solver_time_ms
        for window in report.windows
        if window.solver_time_ms is not None
    )
    analysis_overhead_ms = max(
        0,
        wall_time_ms - replay_time_ms - build_time_ms - solver_time_ms,
    )
    child = SolverBenchmarkChildReport(
        trace_id=report.trace_id,
        side=report.side,
        phase=report.phase,
        profile=SolverDiagnosticProfile(args.profile),
        repetition=args.repetition,
        budget_ms=args.budget_ms,
        trace_complete=report.trace_complete,
        analysis_reached_windows=report.analysis_reached_windows,
        windows=report.windows,
        wall_time_ms=wall_time_ms,
        user_cpu_ms=max(0, int((after_user - before_user) * 1000)),
        system_cpu_ms=max(0, int((after_system - before_system) * 1000)),
        analysis_overhead_ms=analysis_overhead_ms,
        peak_rss_mb=peak_rss,
        reasons=report.reasons,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(child.model_dump_json(indent=2), encoding="utf-8")
    return 0


def _parse_budgets(value: str) -> tuple[int, ...]:
    budgets = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    if not budgets or any(item <= 0 for item in budgets):
        raise argparse.ArgumentTypeError("--budgets must contain positive milliseconds")
    return budgets


def _ppo_solver_benchmark(args: argparse.Namespace) -> int:
    certificates = tuple(args.reduction_certificate or ())
    if certificates and len(certificates) not in {1, len(args.trace)}:
        raise ValueError("--reduction-certificate may be given once or once per trace")
    if certificates:
        cert_paths = certificates
    else:
        cert_paths = ()
    sides = tuple(
        BenchmarkSide(item)
        for item in (args.side or [item.value for item in BenchmarkSide])
    )
    phase = ShadowSolverPhase(args.phase)
    report = run_isolated_solver_benchmark(
        tuple(args.trace),
        dbt_contract=args.dbt_contract,
        reduction_certificates=cert_paths,
        phase=phase,
        sides=sides,
        repetitions=args.repetitions,
        budgets_ms=args.budgets,
        config=_analysis_config(args),
        process_grace_ms=args.process_grace_ms,
        worker_output_dir=args.worker_output_dir,
        profile=SolverDiagnosticProfile(args.profile),
        python_executable=args.python_executable,
        keep_worker_outputs=args.keep_worker_outputs,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _run(args: argparse.Namespace) -> int:
    manifest = capture_request(
        CaptureRequest(
            command=_command(args.command),
            output_dir=args.trace,
            dynamorio_home=args.dynamorio_home,
            client_path=args.client,
            environment=tuple(sorted(_environment(args.env).items())),
            working_directory=args.cwd,
            max_thread_events=args.max_thread_events,
        )
    )
    if not manifest.complete:
        print("Trace is incomplete; analysis will return UNKNOWN.", file=sys.stderr)
    certificate = analyze_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(certificate.model_dump_json(indent=2), encoding="utf-8")
    print(explain_certificate(certificate))
    return EXIT_CODES[certificate.verdict]


def _campaign(args: argparse.Namespace) -> int:
    document = yaml.safe_load(args.manifest.read_text(encoding="utf-8")) or {}
    runs = _validate_campaign_document(document)
    args.output.mkdir(parents=True, exist_ok=True)
    if (args.output / "campaign.json").exists():
        raise ValueError("campaign output already contains campaign.json")

    members: list[CampaignMember] = []
    first_by_key: dict[str, str] = {}
    unique_bytes = 0
    total_events = 0
    total_pcs = 0
    total_bytes = 0
    resource_limited_count = 0
    for item in runs:
        name = item["name"]
        repeat = item["repeat"]
        for iteration in range(repeat):
            trace_dir = args.output / f"{name}-{iteration:03d}"
            if trace_dir.exists():
                raise ValueError(f"campaign trace directory already exists: {trace_dir}")
            capture_started = time.perf_counter()
            manifest = None
            certificate: DynamicCertificate | None = None
            error: str | None = None
            try:
                manifest = capture_request(
                    CaptureRequest(
                        command=tuple(str(value) for value in item["command"]),
                        output_dir=trace_dir,
                        dynamorio_home=args.dynamorio_home,
                        client_path=args.client,
                        environment=tuple(
                            sorted(
                                (str(k), str(v))
                                for k, v in item.get("environment", {}).items()
                            )
                        ),
                        working_directory=(
                            Path(item["working_directory"])
                            if item.get("working_directory")
                            else None
                        ),
                        max_thread_events=args.max_thread_events,
                    )
                )
            except (CaptureError, OSError, ValueError) as caught:
                error = f"capture failed: {caught}"
            capture_seconds = time.perf_counter() - capture_started
            analysis_started = time.perf_counter()
            if error is None:
                try:
                    certificate = analyze_request(
                        AnalyzeRequest(
                            trace_dir=trace_dir,
                            dbt_contract=args.dbt_contract,
                            config=_analysis_config(args),
                        )
                    )
                except (OSError, ValueError, TraceStoreError) as caught:
                    error = f"analysis failed: {caught}"
            analysis_seconds = time.perf_counter() - analysis_started
            replay_seconds = 0.0
            if certificate is not None and certificate.verdict in {
                TraceVerdict.TRACE_SAFE,
                TraceVerdict.COUNTEREXAMPLE,
            }:
                replay_started = time.perf_counter()
                try:
                    replay_dynamic_certificate(
                        certificate,
                        trace_dir,
                        args.dbt_contract,
                        config=_analysis_config(args),
                    )
                except (DynamicTraceBindingError, OSError, ValueError) as caught:
                    error = f"certificate replay failed: {caught}"
                    certificate = certificate.model_copy(
                        update={
                            "verdict": TraceVerdict.UNKNOWN,
                            "unknown_reasons": tuple(
                                dict.fromkeys(
                                    (*certificate.unknown_reasons, str(caught))
                                )
                            ),
                        }
                    )
                replay_seconds = time.perf_counter() - replay_started

            certificate_path: Path | None = None
            if certificate is not None:
                certificate_path = trace_dir / "certificate.json"
                certificate_path.write_text(
                    certificate.model_dump_json(indent=2), encoding="utf-8"
                )
            trace_bytes = _directory_bytes(trace_dir)
            verdict = certificate.verdict if certificate is not None else TraceVerdict.UNKNOWN
            trace_id = (
                certificate.scope.trace_ids[0]
                if certificate is not None and certificate.scope.trace_ids
                else None
            )
            trace_sha256 = (
                certificate.scope.trace_sha256[0]
                if certificate is not None and certificate.scope.trace_sha256
                else None
            )
            dedup_key = _certificate_dedup_key(certificate)
            duplicate_of = first_by_key.get(dedup_key) if dedup_key else None
            if dedup_key and duplicate_of is None:
                first_by_key[dedup_key] = f"{name}-{iteration:03d}"
                unique_bytes += trace_bytes
            elif dedup_key is None:
                # 没有稳定 digest 的失败成员不能和其他成员合并，仍计入
                # 唯一存储，避免资源报告把失败输入的占用记成零。
                unique_bytes += trace_bytes
            resource_limited = _certificate_resource_limited(certificate)
            if resource_limited:
                resource_limited_count += 1
            event_count = certificate.event_count if certificate is not None else 0
            unique_pc_count = certificate.unique_pc_count if certificate is not None else 0
            total_events += event_count
            total_pcs += unique_pc_count
            total_bytes += trace_bytes
            members.append(
                CampaignMember(
                    name=name,
                    iteration=iteration,
                    trace_directory=str(trace_dir.relative_to(args.output)),
                    certificate_path=(
                        str(certificate_path.relative_to(args.output))
                        if certificate_path is not None
                        else None
                    ),
                    verdict=verdict,
                    trace_id=trace_id,
                    trace_sha256=trace_sha256,
                    event_count=event_count,
                    unique_pc_count=unique_pc_count,
                    trace_bytes=trace_bytes,
                    capture_seconds=capture_seconds,
                    analysis_seconds=analysis_seconds,
                    replay_seconds=replay_seconds,
                    max_rss_kb=_max_rss_kb(),
                    resource_limited=resource_limited,
                    dedup_key=dedup_key,
                    duplicate_of=duplicate_of,
                    error=error,
                )
            )

    if not members:
        raise ValueError("campaign produced no trace members")
    verdict = _campaign_verdict(member.verdict for member in members)
    summary = CampaignSummary(
        verdict=verdict,
        trace_count=len(members),
        member_count=len(members),
        verdict_counts={
            candidate.value: sum(item.verdict == candidate for item in members)
            for candidate in TraceVerdict
        },
        unique_trace_count=len(first_by_key) + sum(
            item.dedup_key is None for item in members
        ),
        duplicate_trace_count=sum(item.duplicate_of is not None for item in members),
        total_events=total_events,
        total_unique_pcs_per_trace=total_pcs,
        total_trace_bytes=total_bytes,
        unique_trace_bytes=unique_bytes,
        resource_limited_count=resource_limited_count,
        certificates=tuple(members),
    )
    (args.output / "campaign.json").write_text(
        summary.model_dump_json(indent=2), encoding="utf-8"
    )
    print(f"Campaign verdict: {verdict.value} ({len(members)} traces)")
    return EXIT_CODES[verdict]


def _validate_campaign_document(document: object) -> list[dict[str, object]]:
    if not isinstance(document, dict):
        raise ValueError("campaign manifest must be a mapping")
    raw_runs = document.get("runs")
    if not isinstance(raw_runs, list) or not raw_runs:
        raise ValueError("campaign manifest requires a non-empty runs list")
    runs: list[dict[str, object]] = []
    names: set[str] = set()
    for item in raw_runs:
        if not isinstance(item, dict) or not isinstance(item.get("command"), list):
            raise ValueError("each campaign run requires command: [..]")
        command = item["command"]
        if not command or any(not isinstance(value, str) or not value for value in command):
            raise ValueError("campaign command must contain non-empty strings")
        name = str(item.get("name", "run"))
        if not name or name in {".", ".."} or Path(name).name != name:
            raise ValueError("campaign run name must be a unique directory name")
        if name in names:
            raise ValueError(f"duplicate campaign run name: {name}")
        names.add(name)
        try:
            repeat = int(item.get("repeat", 1))
        except (TypeError, ValueError) as error:
            raise ValueError("campaign repeat must be a positive integer") from error
        if repeat < 1:
            raise ValueError("campaign repeat must be a positive integer")
        environment = item.get("environment", {})
        if not isinstance(environment, dict):
            raise ValueError("campaign environment must be a mapping")
        runs.append({**item, "name": name, "repeat": repeat})
    return runs


def _campaign_verdict(verdicts: object) -> TraceVerdict:
    values = tuple(verdicts)
    if not values:
        raise ValueError("campaign cannot aggregate an empty member set")
    if TraceVerdict.COUNTEREXAMPLE in values:
        return TraceVerdict.COUNTEREXAMPLE
    if TraceVerdict.UNKNOWN in values:
        return TraceVerdict.UNKNOWN
    return TraceVerdict.TRACE_SAFE


def _certificate_dedup_key(certificate: DynamicCertificate | None) -> str | None:
    if certificate is None or not certificate.scope.trace_sha256:
        return None
    config_sha = certificate.binding.config_sha256 if certificate.binding else (
        certificate.coverage.config_sha256 if certificate.coverage else None
    )
    material = {
        "trace_sha256": certificate.scope.trace_sha256[0],
        "contract_sha256": certificate.dbt_contract_sha256,
        "config_sha256": config_sha,
        "schema_version": certificate.schema_version,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _certificate_resource_limited(certificate: DynamicCertificate | None) -> bool:
    if certificate is None:
        return True
    return any(
        marker in reason.lower()
        for reason in certificate.unknown_reasons
        for marker in ("limit", "budget", "resource", "memory")
    )


def _directory_bytes(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(
        item.stat().st_size
        for item in path.rglob("*")
        if item.is_file()
    )


def _max_rss_kb() -> int | None:
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # Linux reports KiB; macOS reports bytes. This process is Linux in the
        # supported deployment, but normalizing keeps the field interpretable.
        return value if value < 10_000_000 else value // 1024
    except (ImportError, AttributeError, OSError):
        return None


def _explain(args: argparse.Namespace) -> int:
    certificate = DynamicCertificate.model_validate_json(
        args.certificate.read_text(encoding="utf-8")
    )
    print(explain_certificate(certificate))
    return EXIT_CODES[certificate.verdict]


def _locate(args: argparse.Namespace) -> int:
    evidence = locate_instruction_site(args.trace, args.module, args.offset)
    print(evidence.model_dump_json(indent=2))
    return 0


def _verify(args: argparse.Namespace) -> int:
    certificate = DynamicCertificate.model_validate_json(
        args.certificate.read_text(encoding="utf-8")
    )
    replay_dynamic_certificate(
        certificate,
        args.trace,
        args.dbt_contract,
        config=_analysis_config(args),
    )
    print(f"Certificate replay verified: {certificate.verdict.value}")
    return EXIT_CODES[certificate.verdict]


def _diagnose(args: argparse.Namespace) -> int:
    """把诊断命令交给 CLI 组合层，避免 dynamic route 读取 diagnostics 内部。"""

    from bmo_check_cli.diagnose import run_diagnose

    return run_diagnose(args)


def _hybrid(args: argparse.Namespace) -> int:
    """单 workload 编排交给 CLI package，dynamic route 不反向依赖 workflow。"""

    from bmo_check_cli.hybrid import run_hybrid

    return run_hybrid(args)


def _add_capture_options(parser: argparse.ArgumentParser) -> None:
    default_home = Path(os.environ.get("DYNAMORIO_HOME", "/opt/dynamorio"))
    parser.add_argument("--dynamorio-home", type=Path, default=default_home)
    parser.add_argument(
        "--client",
        type=Path,
        default=Path(__file__).parent / "native" / "build" / "libbmo_trace.so",
    )
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--cwd", type=Path)
    parser.add_argument(
        "--max-thread-events",
        type=int,
        help="stop recording a thread after this many events and return UNKNOWN",
    )


def _add_analysis_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dbt-contract", type=Path, default=_default_contract())
    parser.add_argument("--database", type=Path)
    parser.add_argument("--max-window-events", type=int, default=64)
    parser.add_argument("--max-executions", type=int, default=20_000)
    parser.add_argument("--max-communication-edges", type=int, default=100_000)
    parser.add_argument("--max-communication-active-events", type=int, default=600_000)
    parser.add_argument("--max-object-events", type=int, default=5_000_000)
    parser.add_argument("--max-pages-per-access", type=int, default=16)
    parser.add_argument("--batch-size", type=int, default=50_000)
    parser.add_argument("--solver-timeout-ms", type=int, default=10_000)
    parser.add_argument("--max-symbolic-terms", type=int, default=100_000)
    parser.add_argument("--database-memory-limit-mb", type=int, default=512)
    parser.add_argument(
        "--application-only",
        action="store_true",
        help=(
            "prove main-ELF-touching communication after scanning all candidate pages; "
            "runtime-only edges are counted and excluded from the application window "
            "only after the complete scan"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bmo-check",
        description="Dynamic trace-scoped verifier for DBT6 mo-off",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    capture = subparsers.add_parser("capture", help="capture a native x86-64 trace")
    capture.add_argument("--output", type=Path, required=True)
    _add_capture_options(capture)
    capture.add_argument("command", nargs=argparse.REMAINDER)
    capture.set_defaults(handler=_capture)

    analyze = subparsers.add_parser("analyze", help="analyze one trace directory")
    analyze.add_argument("trace", type=Path)
    analyze.add_argument("--output", type=Path, required=True)
    _add_analysis_options(analyze)
    analyze.set_defaults(handler=_analyze)

    characterize = subparsers.add_parser(
        "characterize",
        help="scan communication and windows without running the proof checker",
    )
    characterize.add_argument("trace", type=Path)
    characterize.add_argument("--output", type=Path, required=True)
    _add_analysis_options(characterize)
    characterize.set_defaults(handler=_characterize)

    slice_candidates = subparsers.add_parser(
        "slice-candidates",
        help="report obligation-aware slice candidates without running proof",
    )
    slice_candidates.add_argument("trace", type=Path)
    slice_candidates.add_argument("--output", type=Path, required=True)
    _add_analysis_options(slice_candidates)
    slice_candidates.set_defaults(handler=_slice_candidates)

    slice_plan = subparsers.add_parser(
        "slice-plan",
        help="plan only obligation-preserving partitions without running proof",
    )
    slice_plan.add_argument("trace", type=Path)
    slice_plan.add_argument("--output", type=Path, required=True)
    _add_analysis_options(slice_plan)
    slice_plan.set_defaults(handler=_slice_plan)

    obligation_bottleneck = subparsers.add_parser(
        "obligation-bottleneck",
        help="characterize obligation bottlenecks without running proof",
    )
    obligation_bottleneck.add_argument("trace", type=Path)
    obligation_bottleneck.add_argument("--output", type=Path, required=True)
    _add_analysis_options(obligation_bottleneck)
    obligation_bottleneck.set_defaults(handler=_obligation_bottleneck)

    cycle_relevance = subparsers.add_parser(
        "cycle-relevance",
        help="characterize cycle-relevant relations without running proof",
    )
    cycle_relevance.add_argument("trace", type=Path)
    cycle_relevance.add_argument("--output", type=Path, required=True)
    _add_analysis_options(cycle_relevance)
    cycle_relevance.set_defaults(handler=_cycle_relevance)

    ppo_reduction = subparsers.add_parser(
        "ppo-reduction",
        help="build and independently replay a PPO reachability shadow certificate",
    )
    ppo_reduction.add_argument("trace", type=Path)
    ppo_reduction.add_argument("--output", type=Path, required=True)
    ppo_reduction.add_argument("--certificate", type=Path)
    _add_analysis_options(ppo_reduction)
    ppo_reduction.set_defaults(handler=_ppo_reduction)

    ppo_certificate_profile = subparsers.add_parser(
        "ppo-certificate-profile",
        help="profile PPO certificate generation and independent replay stages",
    )
    ppo_certificate_profile.add_argument("trace", type=Path)
    ppo_certificate_profile.add_argument("--output", type=Path, required=True)
    ppo_certificate_profile.add_argument(
        "--cache-dir",
        type=Path,
        help="optional per-window certificate cache directory; every load still replays independently",
    )
    _add_analysis_options(ppo_certificate_profile)
    ppo_certificate_profile.set_defaults(handler=_ppo_certificate_profile)

    graph_first = subparsers.add_parser(
        "cycle-prototype",
        help="bounded graph-first candidate-cycle shadow diagnosis",
    )
    graph_first.add_argument("trace", type=Path)
    graph_first.add_argument("--reduction-certificate", type=Path)
    graph_first.add_argument("--output", type=Path, required=True)
    graph_first.add_argument(
        "--max-cycle-length", type=int, default=12,
        help="maximum simple-cycle length explored by the diagnostic graph",
    )
    graph_first.add_argument(
        "--max-cycles", type=int, default=32,
        help="maximum candidate cycles sent to local shadow SMT",
    )
    graph_first.add_argument(
        "--max-search-states", type=int, default=100_000,
        help="maximum bounded DFS edge visits",
    )
    graph_first.add_argument(
        "--local-timeout-ms", type=int, default=1_000,
        help="timeout for each candidate-local shadow SMT query",
    )
    graph_first.add_argument(
        "--local-max-symbolic-terms", type=int, default=100_000,
        help="symbolic-term budget for each candidate-local shadow query",
    )
    graph_first.add_argument(
        "--encoding-only", action="store_true",
        help="build local diagnostic formulas without calling Z3",
    )
    _add_analysis_options(graph_first)
    graph_first.set_defaults(handler=_graph_first)

    cegar = subparsers.add_parser(
        "cegar-prototype",
        help="bounded graph-first CEGAR candidate refinement (diagnostic only)",
    )
    cegar.add_argument("trace", type=Path)
    cegar.add_argument("--reduction-certificate", type=Path)
    cegar.add_argument("--output", type=Path, required=True)
    cegar.add_argument(
        "--max-cycle-length", type=int, default=12,
        help="maximum critical-edge cycle length explored",
    )
    cegar.add_argument(
        "--max-search-states", type=int, default=10_000,
        help="maximum bounded candidate-search states",
    )
    cegar.add_argument(
        "--max-local-queries", type=int, default=1_000,
        help="maximum local SMT feasibility queries",
    )
    cegar.add_argument(
        "--max-generated-candidates", type=int, default=100_000,
        help="maximum raw candidates retained for CEGAR profiling",
    )
    cegar.add_argument(
        "--local-timeout-ms", type=int, default=1_000,
        help="timeout for each candidate-local shadow SMT query",
    )
    cegar.add_argument(
        "--local-max-symbolic-terms", type=int, default=100_000,
        help="symbolic-term budget for each candidate-local shadow query",
    )
    cegar.add_argument(
        "--encoding-only", action="store_true",
        help="build local diagnostic formulas without calling Z3",
    )
    _add_analysis_options(cegar)
    cegar.set_defaults(handler=_cegar_prototype)

    cegar_ab = subparsers.add_parser(
        "cegar-ab",
        help="compare P11/P12 candidate search modes (diagnostic only)",
    )
    cegar_ab.add_argument("trace", type=Path)
    cegar_ab.add_argument("--reduction-certificate", type=Path)
    cegar_ab.add_argument("--output", type=Path, required=True)
    cegar_ab.add_argument("--fixture", default=None)
    cegar_ab.add_argument("--max-cycle-length", type=int, default=12)
    cegar_ab.add_argument("--max-search-states", type=int, default=10_000)
    cegar_ab.add_argument("--max-local-queries", type=int, default=1_000)
    cegar_ab.add_argument("--local-timeout-ms", type=int, default=1_000)
    cegar_ab.add_argument("--local-max-symbolic-terms", type=int, default=100_000)
    cegar_ab.add_argument(
        "--include-candidate-records",
        action="store_true",
        help="persist full candidate skeleton, local witness, and replay details",
    )
    cegar_ab.add_argument(
        "--capture-model",
        action="store_true",
        help="persist every local SMT decision variable/value for shadow replay",
    )
    cegar_ab.add_argument(
        "--close-feasible-candidates",
        action="store_true",
        help="re-solve local FEASIBLE candidates with the complete window constraints",
    )
    cegar_ab.add_argument("--closure-timeout-ms", type=int, default=5_000)
    cegar_ab.add_argument("--closure-max-symbolic-terms", type=int, default=100_000)
    cegar_ab.add_argument("--encoding-only", action="store_true")
    cegar_ab.add_argument(
        "--include-structured",
        action="store_true",
        help="include the fair P14 structured candidate-discovery shadow mode",
    )
    cegar_ab.add_argument(
        "--include-bounded",
        action="store_true",
        help="include the P15 bounded-memory lazy discovery shadow mode",
    )
    cegar_ab.add_argument(
        "--only-mode",
        choices=[mode.value for mode in CegarExperimentMode],
        help="run one shadow mode in an isolated worker",
    )
    cegar_ab.add_argument(
        "--discovery-only",
        action="store_true",
        help="record candidate discovery without constructing local SMT queries",
    )
    cegar_ab.add_argument("--max-in-memory-frontier", type=int, default=None)
    cegar_ab.add_argument("--max-rss-mb", type=float, default=None)
    cegar_ab.add_argument("--max-wall-time-ms", type=int, default=None)
    cegar_ab.add_argument("--memory-sample-every", type=int, default=100)
    cegar_ab.add_argument("--checkpoint", type=Path, default=None)
    cegar_ab.add_argument("--resume-checkpoint", type=Path, default=None)
    cegar_ab.add_argument("--progress", type=Path, default=None)
    _add_analysis_options(cegar_ab)
    cegar_ab.set_defaults(handler=_cegar_ab)

    p17 = subparsers.add_parser(
        "p17-global-validation",
        help="run bounded, shadow-only P17 candidate closure and shared-solver study",
    )
    p17.add_argument("trace", type=Path)
    p17.add_argument("--fixed-candidate-report", type=Path, required=True)
    p17.add_argument("--reduction-certificate", type=Path, required=True)
    p17.add_argument("--output", type=Path, required=True)
    p17.add_argument("--progress", type=Path)
    p17.add_argument("--partial-timeout-ms", type=int, default=1_000)
    p17.add_argument("--full-timeout-ms", type=int, default=30_000)
    p17.add_argument("--p17-max-symbolic-terms", type=int, default=100_000)
    p17.add_argument("--max-queries-per-solver-session", type=int, default=2)
    p17.add_argument("--process-wall-limit-seconds", type=int, default=1_800)
    p17.add_argument("--process-memory-limit-mb", type=int, default=8_192)
    p17.add_argument("--expected-candidate-count", type=int, default=10)
    _add_analysis_options(p17)
    p17.set_defaults(
        handler=_p17_global_validation,
        max_window_events=10_000,
    )

    p17_worker = subparsers.add_parser(
        "_p17-global-validation-worker",
        help=argparse.SUPPRESS,
    )
    p17_worker.add_argument("trace", type=Path)
    p17_worker.add_argument("--fixed-candidate-report", type=Path, required=True)
    p17_worker.add_argument("--reduction-certificate", type=Path, required=True)
    p17_worker.add_argument("--output", type=Path, required=True)
    p17_worker.add_argument("--progress", type=Path, required=True)
    p17_worker.add_argument("--partial-timeout-ms", type=int, required=True)
    p17_worker.add_argument("--full-timeout-ms", type=int, required=True)
    p17_worker.add_argument("--p17-max-symbolic-terms", type=int, required=True)
    p17_worker.add_argument("--max-queries-per-solver-session", type=int, required=True)
    p17_worker.add_argument("--process-wall-limit-seconds", type=int, required=True)
    p17_worker.add_argument("--process-memory-limit-mb", type=int, required=True)
    p17_worker.add_argument("--expected-candidate-count", type=int, required=True)
    _add_analysis_options(p17_worker)
    p17_worker.set_defaults(handler=_p17_global_validation_worker)

    ppo_replay = subparsers.add_parser(
        "ppo-replay",
        help="independently replay a PPO reduction certificate",
    )
    ppo_replay.add_argument("trace", type=Path)
    ppo_replay.add_argument("--certificate", type=Path, required=True)
    ppo_replay.add_argument("--output", type=Path, required=True)
    _add_analysis_options(ppo_replay)
    ppo_replay.set_defaults(handler=_ppo_replay)

    ppo_solver = subparsers.add_parser(
        "ppo-solver-compare",
        help="compare full and certified-reduced PPO shadow solver runs",
    )
    ppo_solver.add_argument("trace", type=Path)
    ppo_solver.add_argument("--reduction-certificate", type=Path)
    ppo_solver.add_argument("--output", type=Path, required=True)
    ppo_solver.add_argument("--certificate", type=Path)
    ppo_solver.add_argument(
        "--encoding-only",
        action="store_true",
        help="build full/reduced Z3 assertions without calling the solver",
    )
    _add_analysis_options(ppo_solver)
    ppo_solver.set_defaults(handler=_ppo_solver)

    ppo_solver_replay = subparsers.add_parser(
        "ppo-solver-replay",
        help="replay a solver-level full/reduced binding certificate",
    )
    ppo_solver_replay.add_argument("trace", type=Path)
    ppo_solver_replay.add_argument("--reduction-certificate", type=Path, required=True)
    ppo_solver_replay.add_argument("--certificate", type=Path, required=True)
    ppo_solver_replay.add_argument("--output", type=Path, required=True)
    ppo_solver_replay.add_argument("--encoding-only", action="store_true")
    _add_analysis_options(ppo_solver_replay)
    ppo_solver_replay.set_defaults(handler=_ppo_solver_replay)

    ppo_solver_worker = subparsers.add_parser(
        "ppo-solver-worker",
        help=argparse.SUPPRESS,
    )
    ppo_solver_worker.add_argument("trace", type=Path)
    ppo_solver_worker.add_argument("--side", choices=[item.value for item in BenchmarkSide], required=True)
    ppo_solver_worker.add_argument("--phase", choices=[item.value for item in ShadowSolverPhase], required=True)
    ppo_solver_worker.add_argument("--repetition", type=int, required=True)
    ppo_solver_worker.add_argument("--budget-ms", type=int, required=True)
    ppo_solver_worker.add_argument(
        "--profile",
        choices=[item.value for item in SolverDiagnosticProfile],
        default=SolverDiagnosticProfile.FULL.value,
    )
    ppo_solver_worker.add_argument("--reduction-certificate", type=Path)
    ppo_solver_worker.add_argument("--output", type=Path, required=True)
    ppo_solver_worker.add_argument("--encoding-only", action="store_true")
    _add_analysis_options(ppo_solver_worker)
    ppo_solver_worker.set_defaults(handler=_ppo_solver_worker)

    ppo_solver_benchmark = subparsers.add_parser(
        "ppo-solver-benchmark",
        help="measure full/reduced shadow solver runs in isolated child processes",
    )
    ppo_solver_benchmark.add_argument("trace", type=Path, nargs="+")
    ppo_solver_benchmark.add_argument("--reduction-certificate", type=Path, action="append")
    ppo_solver_benchmark.add_argument("--output", type=Path, required=True)
    ppo_solver_benchmark.add_argument(
        "--phase",
        choices=[item.value for item in ShadowSolverPhase],
        default=ShadowSolverPhase.ENCODING.value,
    )
    ppo_solver_benchmark.add_argument(
        "--side",
        choices=[item.value for item in BenchmarkSide],
        action="append",
        default=None,
        help="repeat for each side; defaults to full and reduced",
    )
    ppo_solver_benchmark.add_argument("--repetitions", type=int, default=3)
    ppo_solver_benchmark.add_argument(
        "--profile",
        choices=[item.value for item in SolverDiagnosticProfile],
        default=SolverDiagnosticProfile.FULL.value,
        help="diagnostic-only constraint ablation profile",
    )
    ppo_solver_benchmark.add_argument(
        "--budgets",
        type=_parse_budgets,
        default=(60_000,),
        help="comma-separated per-child solver/construction budgets in milliseconds",
    )
    ppo_solver_benchmark.add_argument(
        "--process-grace-ms",
        type=int,
        default=120_000,
        help="extra external grace after the in-process budget",
    )
    ppo_solver_benchmark.add_argument(
        "--worker-output-dir",
        type=Path,
        default=Path(".experiments") / "solver-benchmark-workers",
    )
    ppo_solver_benchmark.add_argument("--keep-worker-outputs", action="store_true")
    ppo_solver_benchmark.add_argument(
        "--python-executable",
        default=sys.executable,
        help="Python executable used for isolated workers",
    )
    _add_analysis_options(ppo_solver_benchmark)
    ppo_solver_benchmark.set_defaults(handler=_ppo_solver_benchmark)

    run = subparsers.add_parser("run", help="capture and immediately analyze")
    run.add_argument("--trace", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    _add_capture_options(run)
    _add_analysis_options(run)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(handler=_run)

    campaign = subparsers.add_parser("campaign", help="run a trace corpus")
    campaign.add_argument("manifest", type=Path)
    campaign.add_argument("--output", type=Path, required=True)
    _add_capture_options(campaign)
    _add_analysis_options(campaign)
    campaign.set_defaults(handler=_campaign)

    explain = subparsers.add_parser("explain", help="explain a certificate")
    explain.add_argument("certificate", type=Path)
    explain.set_defaults(handler=_explain)

    verify = subparsers.add_parser(
        "verify", help="independently replay a determinate dynamic certificate"
    )
    verify.add_argument("certificate", type=Path)
    verify.add_argument("--trace", type=Path, required=True)
    _add_analysis_options(verify)
    verify.set_defaults(handler=_verify)

    locate = subparsers.add_parser(
        "locate", help="locate one module-relative instruction in a trace"
    )
    locate.add_argument("trace", type=Path)
    locate.add_argument("--module", required=True)
    locate.add_argument("--offset", type=lambda value: int(value, 0), required=True)
    locate.set_defaults(handler=_locate)

    diagnose = subparsers.add_parser(
        "diagnose",
        help="correlate static Unknowns with a dynamic diagnostic snapshot",
    )
    # 位置参数是最短调用形式；选项别名方便脚本明确标注输入角色。
    diagnose.add_argument("static_snapshot", nargs="?", type=Path)
    diagnose.add_argument("dynamic_snapshot", nargs="?", type=Path)
    diagnose.add_argument("--static-snapshot", dest="static_snapshot_option", type=Path)
    diagnose.add_argument("--dynamic-snapshot", dest="dynamic_snapshot_option", type=Path)
    diagnose.add_argument(
        "--trace",
        dest="trace_dir",
        type=Path,
        help="build the dynamic snapshot by streaming a trace directory",
    )
    diagnose.add_argument(
        "--max-snapshot-sites",
        type=int,
        default=100_000,
        help="bound distinct thread/site observations when --trace is used",
    )
    diagnose.add_argument("--output", type=Path, required=True)
    diagnose.add_argument(
        "--affine-output",
        type=Path,
        help="also write the trace-bound UnknownAffineBounds coverage report",
    )
    diagnose.add_argument("--static-certificate", type=Path)
    diagnose.add_argument("--trace-certificate", type=Path)
    diagnose.add_argument("--static-certificate-id")
    diagnose.add_argument("--trace-certificate-id")
    diagnose.add_argument(
        "--unknown-id",
        action="append",
        default=[],
        help="limit the report to this static EvidenceId (repeatable)",
    )
    diagnose.set_defaults(handler=_diagnose)

    hybrid = subparsers.add_parser(
        "hybrid",
        help="run static and dynamic analysis for one workload and write one report",
    )
    hybrid.add_argument("--workload", type=Path, required=True, help="versioned YAML workload manifest")
    hybrid.add_argument("--output-dir", type=Path, required=True)
    hybrid.add_argument(
        "--dynamorio-home",
        type=Path,
        help="override the manifest's DynamoRIO root (or DYNAMORIO_HOME default)",
    )
    hybrid.add_argument(
        "--client",
        type=Path,
        help="override the manifest's native client path",
    )
    hybrid.set_defaults(handler=_hybrid)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return int(args.handler(args))
    except (CaptureError, OSError, ValueError) as error:
        print(f"bmo-check: error: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
