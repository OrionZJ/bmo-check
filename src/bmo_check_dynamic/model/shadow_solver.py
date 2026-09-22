from __future__ import annotations

from enum import StrEnum

from .manifest import StrictModel


class ShadowSolverPhase(StrEnum):
    ENCODING = "encoding"
    SOLVER = "solver"


class ShadowSolverRun(StrictModel):
    """单侧 full/reduced shadow encoder 的实际运行计量。"""

    schema_version: str = "shadow-solver-run-v1"
    window_id: str
    phase: ShadowSolverPhase
    result: str
    reason: str = ""
    source_ppo_edges: int
    target_ppo_edges: int
    symbolic_terms: int
    z3_ast_count: int
    assertion_count: int
    build_time_ms: int
    solver_time_ms: int | None = None
    peak_rss_mb: float | None = None


class ShadowSolverComparison(StrictModel):
    """full/reduced A/B 结果；不参与正式 verdict。"""

    schema_version: str = "shadow-solver-comparison-v1"
    window_id: str
    replay_accepted: bool
    full: ShadowSolverRun
    reduced: ShadowSolverRun
    edge_reduction_ratio: float
    term_reduction_ratio: float
    build_speedup: float | None = None
    solver_speedup: float | None = None
    rss_reduction_mb: float | None = None
    result_match: bool | None
    result_match_reason: str
    used_for_verdict: bool = False


class ReducedSolverRunCertificate(StrictModel):
    """把 solver A/B 绑定到同一 trace、窗口和模型输入。"""

    schema_version: str = "reduced-solver-run-certificate-v1"
    window_id: str
    phase: ShadowSolverPhase
    trace_sha256: str
    window_digest: str
    full_ppo_digest: str
    reduced_ppo_digest: str
    reduction_certificate_digest: str
    memory_model_contract_digest: str
    rf_fr_co_candidate_digest: str
    solver_config_digest: str
    full_result: str
    reduced_result: str
    result_match: bool | None
    comparison_digest: str
    diagnostic_only: bool = True


class SolverRunReplay(StrictModel):
    """独立重放 solver-level binding 的结果。"""

    schema_version: str = "solver-run-replay-v1"
    window_id: str
    binding_matches: bool
    candidate_domain_matches: bool
    solver_config_matches: bool
    result_matches: bool
    accepted: bool
    reasons: tuple[str, ...] = ()


class TraceShadowSolverReport(StrictModel):
    schema_version: str = "trace-shadow-solver-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[ShadowSolverComparison, ...] = ()
    reasons: tuple[str, ...] = ()


class TraceReducedSolverRunCertificate(StrictModel):
    schema_version: str = "trace-reduced-solver-certificate-v1"
    trace_id: str
    windows: tuple[ReducedSolverRunCertificate, ...] = ()


class TraceSolverReplayReport(StrictModel):
    schema_version: str = "trace-solver-replay-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[SolverRunReplay, ...] = ()
    reasons: tuple[str, ...] = ()


__all__ = [
    "ShadowSolverPhase",
    "ShadowSolverRun",
    "ShadowSolverComparison",
    "ReducedSolverRunCertificate",
    "SolverRunReplay",
    "TraceShadowSolverReport",
    "TraceReducedSolverRunCertificate",
    "TraceSolverReplayReport",
]
