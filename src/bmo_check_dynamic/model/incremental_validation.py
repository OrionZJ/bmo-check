from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .manifest import StrictModel
from .graph_first import CandidateCycleReplay, CandidateViolationCycle, GraphFirstLocalQuery


class DependencyCoverageStatus(StrEnum):
    COVERED = "covered"
    NOT_COVERED = "not_covered"
    PROVEN_IRRELEVANT = "proven_irrelevant"
    UNKNOWN = "unknown"


class DependencyFamily(StrEnum):
    CANDIDATE_CORE = "candidate_core"
    RF_SOURCE_DOMAIN = "rf_source_domain"
    FR_LATER_WRITE = "fr_later_write"
    COHERENCE_COMPONENT = "coherence_component"
    SOURCE_PPO_PATH = "source_ppo_path"
    TARGET_PPO = "target_ppo"
    BOUNDARY = "fence_rmw_sync_boundary"
    FULL_WINDOW = "full_window_target_acyclicity"


class CandidateReadPartDomain(StrictModel):
    """一个 read 字节片段在完整窗口中的可选写入来源。"""

    address: int
    size: int
    initial_write_allowed: bool = True
    candidate_write_event_ids: tuple[str, ...] = ()
    relation_ids: tuple[str, ...] = ()


class CandidateReadSourceDomain(StrictModel):
    """候选 read 的完整切片 RF 域；初始写作为每片的独立来源保留。"""

    read_event_id: str
    parts: tuple[CandidateReadPartDomain, ...]


class FixedCandidateBaseline(StrictModel):
    """本轮重新执行的固定候选输入和 P16 局部查询基线。"""

    candidate_id: str
    candidate_skeleton_id: str
    candidate: CandidateViolationCycle
    local_query: GraphFirstLocalQuery
    local_replay: CandidateCycleReplay | None = None
    read_source_domains: tuple[CandidateReadSourceDomain, ...] = ()
    diagnostic_only: bool = True


class DependencyCoverage(StrictModel):
    dependency_id: str
    family: DependencyFamily
    event_ids: tuple[str, ...] = ()
    relation_ids: tuple[str, ...] = ()
    status: DependencyCoverageStatus
    explanation: str


class ProgressiveValidationRound(StrictModel):
    round_index: int
    stage: str
    scope: str
    full_window: bool
    event_count_before: int
    event_count_after: int
    added_event_ids: tuple[str, ...] = ()
    source_ppo_edge_count: int = 0
    target_ppo_edge_count: int = 0
    relation_counts: dict[str, int] = Field(default_factory=dict)
    formula_terms: int = 0
    assertion_count: int = 0
    ast_node_count: int = 0
    encode_ms: int = 0
    solver_ms: int | None = None
    solver_result: str = "not_run"
    unresolved_dependency_count: int = 0
    unresolved_event_count: int = 0
    termination_reason: str = ""
    diagnostic_only: bool = True


class ProgressiveCandidateValidation(StrictModel):
    candidate_id: str
    candidate_skeleton_id: str
    window_id: str
    full_window_event_count: int
    rounds: tuple[ProgressiveValidationRound, ...] = ()
    dependency_coverage: tuple[DependencyCoverage, ...] = ()
    final_full_query_result: str = "not_reached"
    final_full_query_replay_status: str = "not_run"
    final_full_query_replay_reasons: tuple[str, ...] = ()
    has_full_window_model_validated: bool = False
    diagnostic_only: bool = True


class IncrementalCandidateCheck(StrictModel):
    candidate_id: str
    candidate_skeleton_id: str
    session_index: int
    query_index_in_session: int
    base_formula_terms: int
    base_assertion_count: int
    base_ast_node_count: int
    base_encode_ms: int
    candidate_added_assertions: int
    candidate_added_ast_nodes: int
    candidate_constraint_build_ms: int
    candidate_push_pop_ms: int = 0
    solver_ms: int | None
    peak_rss_mb: float | None = None
    solver_result: str
    reason: str = ""
    independent_full_query_result: str = "not_run"
    result_matches_independent_full: bool | None = None
    independent_full_replay_status: str = "not_run"
    independent_recheck_result: str = "not_run"
    independent_replay_status: str = "not_run"
    independent_replay_reasons: tuple[str, ...] = ()
    diagnostic_only: bool = True


class IndependentFullWindowQuery(StrictModel):
    candidate_id: str
    candidate_skeleton_id: str
    formula_terms: int = 0
    assertion_count: int = 0
    ast_node_count: int = 0
    encode_ms: int = 0
    solver_ms: int | None = None
    solver_result: str
    replay_status: str = "not_run"
    replay_reasons: tuple[str, ...] = ()
    diagnostic_only: bool = True


class IncrementalSessionBuild(StrictModel):
    session_index: int
    candidate_query_count: int = 0
    base_formula_terms: int = 0
    base_assertion_count: int = 0
    base_ast_node_count: int = 0
    base_encode_ms: int = 0
    peak_rss_mb: float | None = None
    status: str = "ready"
    reason: str = ""
    diagnostic_only: bool = True


class GlobalConstraintValidationReport(StrictModel):
    schema_version: str = "p17-global-constraint-validation-v1"
    trace_id: str
    trace_sha256: str
    contract_sha256: str
    window_id: str
    event_count: int
    ppo_certificate_digest: str
    fixed_candidate_report_sha256: str = ""
    candidate_skeleton_ids: tuple[str, ...]
    fixed_candidate_baseline: tuple[FixedCandidateBaseline, ...] = ()
    progressive_runs: tuple[ProgressiveCandidateValidation, ...] = ()
    independent_full_queries: tuple[IndependentFullWindowQuery, ...] = ()
    shared_incremental_queries: tuple[IncrementalCandidateCheck, ...] = ()
    incremental_session_builds: tuple[IncrementalSessionBuild, ...] = ()
    max_partial_timeout_ms: int
    max_full_timeout_ms: int
    max_symbolic_terms: int
    max_queries_per_solver_session: int
    process_wall_limit_seconds: int
    process_memory_limit_mb: int | None = None
    resource_enforcement: str = "external_launcher_required"
    process_peak_rss_mb: float | None = None
    worker_wall_time_ms: int | None = None
    worker_exit_code: int | None = None
    termination_reason: str = "completed"
    limitations: tuple[str, ...] = ()
    diagnostic_only: bool = True
