from __future__ import annotations

from enum import StrEnum

from .manifest import StrictModel
from .shadow_solver import ShadowSolverPhase, ShadowSolverRun
from .solver_diagnostics import SolverDiagnosticProfile


class BenchmarkSide(StrEnum):
    FULL = "full"
    REDUCED = "reduced"


class SolverBenchmarkChildReport(StrictModel):
    """一个隔离子进程的一侧运行结果和进程级资源计量。"""

    schema_version: str = "solver-benchmark-child-v1"
    trace_id: str
    side: BenchmarkSide
    phase: ShadowSolverPhase
    profile: SolverDiagnosticProfile = SolverDiagnosticProfile.FULL
    repetition: int
    budget_ms: int
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[ShadowSolverRun, ...] = ()
    wall_time_ms: int
    user_cpu_ms: int
    system_cpu_ms: int
    # 这里包含 trace 导入、窗口分析、进程启动和未单独计时的准备工作。
    # PPO replay、SMT build、solver 分别由窗口计量字段拆出。
    analysis_overhead_ms: int = 0
    peak_rss_mb: float | None = None
    reasons: tuple[str, ...] = ()


class TraceShadowSolverSideReport(StrictModel):
    """单个 worker 只构造一侧 PPO 的窗口结果。"""

    schema_version: str = "trace-shadow-solver-side-v1"
    trace_id: str
    side: BenchmarkSide
    phase: ShadowSolverPhase
    profile: SolverDiagnosticProfile = SolverDiagnosticProfile.FULL
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[ShadowSolverRun, ...] = ()
    reasons: tuple[str, ...] = ()


class SolverBenchmarkProcessRun(StrictModel):
    """父进程对一次 worker 生命周期的记录。"""

    schema_version: str = "solver-benchmark-process-v1"
    trace: str
    side: BenchmarkSide
    phase: ShadowSolverPhase
    repetition: int
    budget_ms: int
    status: str
    return_code: int | None = None
    child: SolverBenchmarkChildReport | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    error: str | None = None


class SolverBenchmarkAggregate(StrictModel):
    """同一 trace/side/phase/budget 多次独立运行的稳健摘要。"""

    schema_version: str = "solver-benchmark-aggregate-v1"
    trace: str
    side: BenchmarkSide
    phase: ShadowSolverPhase
    profile: SolverDiagnosticProfile = SolverDiagnosticProfile.FULL
    budget_ms: int
    repetitions: int
    completed: int
    result_counts: dict[str, int] = {}
    median_wall_time_ms: float | None = None
    min_wall_time_ms: int | None = None
    max_wall_time_ms: int | None = None
    median_user_cpu_ms: float | None = None
    median_system_cpu_ms: float | None = None
    median_peak_rss_mb: float | None = None
    min_peak_rss_mb: float | None = None
    max_peak_rss_mb: float | None = None
    median_formula_terms: float | None = None
    median_z3_ast_count: float | None = None
    median_assertion_count: float | None = None
    median_ppo_replay_time_ms: float | None = None
    median_build_time_ms: float | None = None
    median_solver_time_ms: float | None = None
    median_analysis_overhead_ms: float | None = None
    formula_breakdown: dict[str, int] = {}
    constraint_breakdown: dict[str, int] = {}
    variable_counts: dict[str, int] = {}


class SolverBenchmarkReport(StrictModel):
    """P9.5 独立进程实验报告；不表示任何 verifier verdict。"""

    schema_version: str = "solver-benchmark-v1"
    phase: ShadowSolverPhase
    profile: SolverDiagnosticProfile = SolverDiagnosticProfile.FULL
    traces: tuple[str, ...]
    runs: tuple[SolverBenchmarkProcessRun, ...] = ()
    aggregates: tuple[SolverBenchmarkAggregate, ...] = ()
    process_grace_ms: int
    diagnostic_only: bool = True
    reasons: tuple[str, ...] = ()


__all__ = [
    "BenchmarkSide",
    "SolverBenchmarkChildReport",
    "TraceShadowSolverSideReport",
    "SolverBenchmarkProcessRun",
    "SolverBenchmarkAggregate",
    "SolverBenchmarkReport",
]
