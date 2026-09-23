from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from .manifest import StrictModel
from .graph_first import (
    CandidateCycleReplay,
    CandidateCycleReplayStatus,
    CandidateDiscoveryProfile,
    GraphFirstCandidateCycle,
    GraphFirstLocalQuery,
    LocalCycleWitness,
)


class CegarExperimentMode(StrEnum):
    """P13/P14 只读对比的搜索路径。"""

    RAW_P11 = "P11_RAW"
    CANONICAL = "P12_CANONICAL"
    CANONICAL_BLOCKING = "P12_CANONICAL_BLOCKING"
    STRUCTURED_P14 = "P14_STRUCTURED"
    STRUCTURED_P15 = "P15_BOUNDED_STRUCTURED"


class BlockingReplayReport(StrictModel):
    """一条 blocking constraint 的 query/范围字段检查结果。"""

    block_id: str
    accepted: bool
    query_binding_valid: bool
    assumption_scope_valid: bool
    semantic_context_valid: bool
    # 检查记录是否声称 solver 返回 UNSAT；不表示独立重跑或校验了 Z3 proof。
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


class LocalWitnessClosureKind(StrEnum):
    """全窗口闭包查询对局部 FEASIBLE 的诊断分类。"""

    FULL_WINDOW_MODEL_VALIDATED = "FULL_WINDOW_MODEL_VALIDATED"
    EXECUTION_WITNESS_VALIDATED = "EXECUTION_WITNESS_VALIDATED"
    LEGACY_UNVERIFIED = "LEGACY_UNVERIFIED"
    SPURIOUS_LOCAL_SAT = "SPURIOUS_LOCAL_SAT"
    CLOSURE_QUERY_UNKNOWN = "CLOSURE_QUERY_UNKNOWN"
    WITNESS_REPLAY_REJECTED = "WITNESS_REPLAY_REJECTED"
    NOT_RUN = "NOT_RUN"


class LocalWitnessClosureRecord(StrictModel):
    """把局部候选扩展到完整窗口后得到的可独立审核结果。"""

    schema_version: str = "local-witness-closure-v2"
    candidate_id: str
    # 当前闭包会在全窗中重求同一候选 relation set，不会固定局部 RF assignment。
    closure_mode: str = "full_window_candidate_relation_set_recheck"
    local_assignment_preserved: bool = False
    local_event_count: int
    full_window_event_count: int
    classification: LocalWitnessClosureKind
    closure_query: GraphFirstLocalQuery
    closure_witness: LocalCycleWitness | None = None
    replay: CandidateCycleReplay | None = None
    encoding_ms: int = 0
    solver_ms: int | None = None
    witness_build_ms: int = 0
    obligations_build_ms: int = 0
    replay_ms: int = 0
    reasons: tuple[str, ...] = ()
    diagnostic_only: bool = True

    @model_validator(mode="before")
    @classmethod
    def _downgrade_legacy_witness_label(cls, value: object) -> object:
        """旧 VALID_COMPLETE_WITNESS 没区分符号模型和真实执行。"""

        if isinstance(value, dict) and value.get("classification") == "VALID_COMPLETE_WITNESS":
            migrated = dict(value)
            migrated["classification"] = LocalWitnessClosureKind.LEGACY_UNVERIFIED.value
            migrated.setdefault("schema_version", "local-witness-closure-legacy")
            return migrated
        return value

    @model_validator(mode="after")
    def _check_closure_evidence(self) -> "LocalWitnessClosureRecord":
        """闭包标签必须与查询、模型快照和独立 replay 的等级相符。"""

        if self.classification in {
            LocalWitnessClosureKind.FULL_WINDOW_MODEL_VALIDATED,
            LocalWitnessClosureKind.EXECUTION_WITNESS_VALIDATED,
        }:
            snapshot = (
                self.closure_witness.model_snapshot
                if self.closure_witness is not None
                else None
            )
            if not (
                self.closure_mode == "full_window_candidate_relation_set_recheck"
                and self.local_assignment_preserved is False
                and self.closure_query.solver_result == "sat"
                and self.closure_query.feasibility_status.value == "FEASIBLE"
                and snapshot is not None
                and snapshot.complete
                and self.replay is not None
                and self.replay.model_snapshot_valid is True
                and self.replay.full_window_closed is True
            ):
                raise ValueError("positive closure classification lacks complete full-window model evidence")
            if self.classification is LocalWitnessClosureKind.FULL_WINDOW_MODEL_VALIDATED and (
                self.replay.status is not CandidateCycleReplayStatus.FULL_WINDOW_MODEL_VALIDATED
                or self.replay.execution_counterexample_validated
            ):
                raise ValueError("model-validated closure cannot claim or imply execution validation")
            if self.classification is LocalWitnessClosureKind.EXECUTION_WITNESS_VALIDATED and (
                self.replay.status is not CandidateCycleReplayStatus.EXECUTION_WITNESS_VALIDATED
                or not self.replay.execution_counterexample_validated
            ):
                raise ValueError("execution closure requires an execution-witness replay")
        return self


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
    # 仅在固定候选复现时保存逐候选骨架、模型、witness 与 replay。
    candidate_records: tuple[GraphFirstCandidateCycle, ...] = ()
    # 对局部 FEASIBLE 重新加入完整窗口约束后的 shadow-only replay。
    witness_closures: tuple[LocalWitnessClosureRecord, ...] = ()
    discovery_profile: CandidateDiscoveryProfile | None = None
    same_rf_variants: int = 0
    ppo_witness_variants: int = 0
    local_queries: int = 0
    feasible: int = 0
    infeasible: int = 0
    unknown: int = 0
    not_run: int = 0
    replay_structure_validated: int = 0
    replay_local_model_validated: int = 0
    replay_full_window_model_validated: int = 0
    replay_execution_witness_validated: int = 0
    # 只为读取旧报告保留；新生产者永远不会填这个字段。
    legacy_replay_accepted_unverified: int = 0
    replay_rejected: int = 0
    replay_reasons: tuple[str, ...] = ()
    blocked: int = 0
    invalid_blocks: int = 0
    search_truncated: bool = False
    query_truncated: bool = False
    status: str = "INCOMPLETE"
    reasons: tuple[str, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_replay_count(cls, value: object) -> object:
        """旧汇总里的 replay_accepted 没记录其证据等级，降级保存。"""

        if isinstance(value, dict) and "replay_accepted" in value:
            migrated = dict(value)
            legacy_count = migrated.pop("replay_accepted")
            migrated.setdefault("legacy_replay_accepted_unverified", legacy_count)
            return migrated
        return value
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
    # 固定查询 artifact 绑定原始轨迹和 DBT contract，避免只凭 fixture 名称复用。
    trace_sha256: str | None = None
    contract_sha256: str | None = None
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
