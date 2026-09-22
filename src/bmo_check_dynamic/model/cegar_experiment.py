from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .manifest import StrictModel
from .graph_first import CandidateDiscoveryProfile


class CegarExperimentMode(StrEnum):
    """P13/P14 只读对比的搜索路径。"""

    RAW_P11 = "P11_RAW"
    CANONICAL = "P12_CANONICAL"
    CANONICAL_BLOCKING = "P12_CANONICAL_BLOCKING"
    STRUCTURED_P14 = "P14_STRUCTURED"
    STRUCTURED_P15 = "P15_BOUNDED_STRUCTURED"


class BlockingReplayReport(StrictModel):
    """一条 blocking constraint 的独立字段检查结果。"""

    block_id: str
    accepted: bool
    query_binding_valid: bool
    assumption_scope_valid: bool
    semantic_context_valid: bool
    solver_status_valid: bool
    reasons: tuple[str, ...] = ()
    diagnostic_only: bool = True


class CandidateCoverageReport(StrictModel):
    """有界实例上独立穷举与规范化候选集合的比较。"""

    schema_version: str = "candidate-coverage-report-v1"
    bound_cycle_length: int
    independent_candidate_count: int
    observed_candidate_count: int
    missing_candidate_ids: tuple[str, ...] = ()
    unexpected_candidate_ids: tuple[str, ...] = ()
    unresolved_query_count: int = 0
    invalid_block_count: int = 0
    exhaustive_search_truncated: bool = False
    complete: bool = False
    reasons: tuple[str, ...] = ()
    diagnostic_only: bool = True


class CegarModeMetrics(StrictModel):
    """一次模式运行的可比较指标；不表示正式 verdict。"""

    mode: CegarExperimentMode
    same_budget: bool = True
    certificate_prepare_ms: int = 0
    certificate_replay_ms: int = 0
    search_ms: int = 0
    total_ms: int = 0
    peak_rss_mb: float | None = None
    raw_search_states: int = 0
    generated_candidates: int = 0
    unique_candidates: int = 0
    duplicate_candidates: int = 0
    # 用稳定 canonical skeleton identity 比较模式，不依赖候选遍历编号。
    candidate_skeleton_ids: tuple[str, ...] = ()
    discovery_profile: CandidateDiscoveryProfile | None = None
    same_rf_variants: int = 0
    ppo_witness_variants: int = 0
    local_queries: int = 0
    feasible: int = 0
    infeasible: int = 0
    unknown: int = 0
    not_run: int = 0
    replay_accepted: int = 0
    replay_rejected: int = 0
    replay_reasons: tuple[str, ...] = ()
    blocked: int = 0
    invalid_blocks: int = 0
    search_truncated: bool = False
    query_truncated: bool = False
    status: str = "INCOMPLETE"
    reasons: tuple[str, ...] = ()
    diagnostic_only: bool = True


class CegarModeComparisonReport(StrictModel):
    """P13 三模式 A/B 报告。"""

    schema_version: str = "cegar-mode-comparison-v1"
    fixture: str
    window_id: str
    event_count: int
    max_cycle_length: int
    max_search_states: int
    max_local_queries: int
    local_timeout_ms: int
    local_max_symbolic_terms: int = 100_000
    certificate_digest: str | None = None
    certificate_prepare_ms: int = 0
    certificate_replay_ms: int = 0
    modes: tuple[CegarModeMetrics, ...] = ()
    candidate_sets_match: bool = True
    candidate_set_differences: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    coverage: CandidateCoverageReport | None = None
    isolated_process: bool = False
    diagnostic_only: bool = True
    reasons: tuple[str, ...] = ()


class CegarExperimentReport(StrictModel):
    """多个 fixture 的 P13 汇总；不会产生 SAFE/COUNTEREXAMPLE。"""

    schema_version: str = "cegar-experiment-v1"
    generated_at: str
    trace_id: str | None = None
    trace_complete: bool | None = None
    analysis_reached_windows: bool = False
    reports: tuple[CegarModeComparisonReport, ...] = ()
    diagnostic_only: bool = True
    reasons: tuple[str, ...] = Field(default_factory=tuple)


__all__ = [
    "CegarExperimentMode",
    "BlockingReplayReport",
    "CandidateCoverageReport",
    "CegarModeMetrics",
    "CegarModeComparisonReport",
    "CegarExperimentReport",
]
