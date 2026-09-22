from __future__ import annotations

import statistics
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import (
    BenchmarkSide,
    ShadowSolverPhase,
    SolverBenchmarkAggregate,
    SolverBenchmarkChildReport,
    SolverBenchmarkProcessRun,
    SolverBenchmarkReport,
    SolverDiagnosticProfile,
)


def _config_args(config: DynamicConfig) -> list[str]:
    args = [
        "--max-window-events", str(config.max_window_events),
        "--max-executions", str(config.max_executions),
        "--max-communication-edges", str(config.max_communication_edges),
        "--max-communication-active-events", str(config.max_communication_active_events),
        "--max-object-events", str(config.max_object_events),
        "--max-pages-per-access", str(config.max_pages_per_access),
        "--batch-size", str(config.batch_size),
        "--solver-timeout-ms", str(config.solver_timeout_ms),
        "--max-symbolic-terms", str(config.max_symbolic_terms),
        "--database-memory-limit-mb", str(config.database_memory_limit_mb),
    ]
    if config.database_path is not None:
        args.extend(("--database", str(config.database_path)))
    if config.application_only:
        args.append("--application-only")
    return args


def _child_command(
    *,
    trace: Path,
    dbt_contract: Path,
    side: BenchmarkSide,
    phase: ShadowSolverPhase,
    profile: SolverDiagnosticProfile,
    repetition: int,
    budget_ms: int,
    config: DynamicConfig,
    child_output: Path,
    reduction_certificate: Path | None,
    python_executable: str,
) -> list[str]:
    command = [
        python_executable,
        "-m",
        "bmo_check_dynamic.cli",
        "ppo-solver-worker",
        str(trace),
        "--side",
        side.value,
        "--phase",
        phase.value,
        "--repetition",
        str(repetition),
        "--budget-ms",
        str(budget_ms),
        "--profile",
        profile.value,
        "--dbt-contract",
        str(dbt_contract),
        "--output",
        str(child_output),
    ]
    if reduction_certificate is not None:
        command.extend(("--reduction-certificate", str(reduction_certificate)))
    command.extend(_config_args(replace(config, solver_timeout_ms=budget_ms)))
    if phase is ShadowSolverPhase.ENCODING:
        command.append("--encoding-only")
    return command


def _tail(value: str, limit: int = 2_000) -> str:
    return value[-limit:]


def _window_total(child: SolverBenchmarkChildReport, field: str) -> int:
    return sum(
        int(value)
        for window in child.windows
        if (value := getattr(window, field)) is not None
    )


def _median_counts(children: list[SolverBenchmarkChildReport], field: str) -> dict[str, int]:
    per_child: list[dict[str, int]] = []
    for child in children:
        counts: dict[str, int] = {}
        for window in child.windows:
            for key, value in getattr(window, field).items():
                counts[key] = counts.get(key, 0) + int(value)
        per_child.append(counts)
    keys = set().union(*(counts.keys() for counts in per_child))
    return {
        key: int(statistics.median([counts.get(key, 0) for counts in per_child]))
        for key in sorted(keys)
    }


def _median(values: list[float | int]) -> float | None:
    return float(statistics.median(values)) if values else None


def _aggregate(
    key: tuple[str, BenchmarkSide, ShadowSolverPhase, int],
    runs: list[SolverBenchmarkProcessRun],
    repetitions: int,
) -> SolverBenchmarkAggregate:
    trace, side, phase, budget_ms = key
    children = [run.child for run in runs if run.child is not None]
    completed = len(children)
    wall = [child.wall_time_ms for child in children]
    user = [child.user_cpu_ms for child in children]
    system = [child.system_cpu_ms for child in children]
    rss = [child.peak_rss_mb for child in children if child.peak_rss_mb is not None]
    result_counts: dict[str, int] = {}
    for child in children:
        for window in child.windows:
            result_counts[window.result] = result_counts.get(window.result, 0) + 1
    return SolverBenchmarkAggregate(
        trace=trace,
        side=side,
        phase=phase,
        profile=(children[0].profile if children else SolverDiagnosticProfile.FULL),
        budget_ms=budget_ms,
        repetitions=repetitions,
        completed=completed,
        result_counts=result_counts,
        median_wall_time_ms=_median(wall),
        min_wall_time_ms=min(wall) if wall else None,
        max_wall_time_ms=max(wall) if wall else None,
        median_user_cpu_ms=_median(user),
        median_system_cpu_ms=_median(system),
        median_peak_rss_mb=_median(rss),
        min_peak_rss_mb=min(rss) if rss else None,
        max_peak_rss_mb=max(rss) if rss else None,
        median_formula_terms=_median([_window_total(child, "symbolic_terms") for child in children]),
        median_z3_ast_count=_median([_window_total(child, "z3_ast_count") for child in children]),
        median_assertion_count=_median([_window_total(child, "assertion_count") for child in children]),
        median_ppo_replay_time_ms=_median(
            [_window_total(child, "ppo_replay_time_ms") for child in children]
        ),
        median_build_time_ms=_median([_window_total(child, "build_time_ms") for child in children]),
        median_solver_time_ms=_median(
            [
                _window_total(child, "solver_time_ms")
                for child in children
                if child.windows and all(
                    window.solver_time_ms is not None for window in child.windows
                )
            ]
        ),
        median_analysis_overhead_ms=_median(
            [child.analysis_overhead_ms for child in children]
        ),
        formula_breakdown=_median_counts(children, "formula_breakdown"),
        constraint_breakdown=_median_counts(children, "constraint_breakdown"),
        variable_counts=_median_counts(children, "variable_counts"),
    )


def run_isolated_solver_benchmark(
    traces: tuple[Path, ...],
    *,
    dbt_contract: Path,
    reduction_certificates: tuple[Path | None, ...],
    phase: ShadowSolverPhase,
    sides: tuple[BenchmarkSide, ...],
    repetitions: int,
    budgets_ms: tuple[int, ...],
    config: DynamicConfig,
    process_grace_ms: int,
    worker_output_dir: Path,
    profile: SolverDiagnosticProfile = SolverDiagnosticProfile.FULL,
    python_executable: str | None = None,
    keep_worker_outputs: bool = False,
) -> SolverBenchmarkReport:
    """以独立 Python 子进程运行每个 A/B 点，避免 RSS 高水位互相污染。"""

    if not traces:
        raise ValueError("at least one trace is required")
    if not sides:
        raise ValueError("at least one benchmark side is required")
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")
    if any(budget <= 0 for budget in budgets_ms):
        raise ValueError("benchmark budgets must be positive")
    if len(reduction_certificates) not in {0, 1, len(traces)}:
        raise ValueError("reduction certificates must be omitted, singular, or match traces")
    certs = (
        tuple(reduction_certificates)
        if len(reduction_certificates) == len(traces)
        else tuple(reduction_certificates * len(traces))
        if len(reduction_certificates) == 1
        else (None,) * len(traces)
    )
    worker_output_dir.mkdir(parents=True, exist_ok=True)
    executable = python_executable or sys.executable
    runs: list[SolverBenchmarkProcessRun] = []
    reasons: list[str] = []
    counter = 0
    for trace, certificate in zip(traces, certs):
        for side in sides:
            for budget_ms in budgets_ms:
                for repetition in range(repetitions):
                    child_output = worker_output_dir / f"worker-{counter:06d}.json"
                    counter += 1
                    command = _child_command(
                        trace=trace,
                        dbt_contract=dbt_contract,
                        side=side,
                        phase=phase,
                        profile=profile,
                        repetition=repetition,
                        budget_ms=budget_ms,
                        config=config,
                        child_output=child_output,
                        reduction_certificate=certificate,
                        python_executable=executable,
                    )
                    status = "completed"
                    return_code: int | None = None
                    child: SolverBenchmarkChildReport | None = None
                    error: str | None = None
                    stdout_tail = ""
                    stderr_tail = ""
                    timeout_s = (budget_ms + process_grace_ms) / 1000
                    try:
                        completed = subprocess.run(
                            command,
                            capture_output=True,
                            text=True,
                            timeout=timeout_s,
                            check=False,
                        )
                        return_code = completed.returncode
                        stdout_tail = _tail(completed.stdout)
                        stderr_tail = _tail(completed.stderr)
                        if child_output.is_file():
                            child = SolverBenchmarkChildReport.model_validate_json(
                                child_output.read_text(encoding="utf-8")
                            )
                        if return_code != 0 or child is None:
                            status = "failed"
                            error = "worker exited without a valid report"
                    except subprocess.TimeoutExpired as exc:
                        status = "process_timeout"
                        error = f"worker exceeded external timeout {timeout_s:.1f}s"
                        stdout_tail = _tail((exc.stdout or "") if isinstance(exc.stdout, str) else "")
                        stderr_tail = _tail((exc.stderr or "") if isinstance(exc.stderr, str) else "")
                    except (OSError, ValueError) as exc:
                        status = "failed"
                        error = str(exc)
                    runs.append(
                        SolverBenchmarkProcessRun(
                            trace=str(trace),
                            side=side,
                            phase=phase,
                            repetition=repetition,
                            budget_ms=budget_ms,
                            status=status,
                            return_code=return_code,
                            child=child,
                            stdout_tail=stdout_tail,
                            stderr_tail=stderr_tail,
                            error=error,
                        )
                    )
                    if error:
                        reasons.append(f"{trace}:{side.value}:{budget_ms}:{error}")
                    if not keep_worker_outputs:
                        child_output.unlink(missing_ok=True)

    grouped: dict[tuple[str, BenchmarkSide, ShadowSolverPhase, int], list[SolverBenchmarkProcessRun]] = {}
    for run in runs:
        grouped.setdefault((run.trace, run.side, run.phase, run.budget_ms), []).append(run)
    aggregates = tuple(
        _aggregate(key, group, repetitions)
        for key, group in sorted(grouped.items(), key=lambda item: item[0])
    )
    return SolverBenchmarkReport(
        phase=phase,
        profile=profile,
        traces=tuple(str(trace) for trace in traces),
        runs=tuple(runs),
        aggregates=aggregates,
        process_grace_ms=process_grace_ms,
        reasons=tuple(reasons),
    )


__all__ = ["run_isolated_solver_benchmark"]
