from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .manifest import StrictModel
from .certificate import SymbolicModelSnapshot


class GraphFirstQueryStatus(StrEnum):
    """graph-first 局部查询的状态；这些值不是正式 verifier verdict。"""

    # 没有调用局部求解器，例如 encoding-only 诊断。
    NOT_RUN = "not_run"
    # 局部约束找到候选，但仍需完整窗口和 witness 复核。
    SAT_CANDIDATE = "sat_candidate"
    # 当前候选环的局部约束不可满足，不代表整窗 SAFE。
    UNSAT_LOCAL = "unsat_local"
    # 局部查询超时、资源不足或信息不完整。
    UNKNOWN_LOCAL = "unknown_local"
    # PPO replay 或候选边绑定失败，不能建立局部查询。
    REJECTED = "rejected"


class LocalCycleStatus(StrEnum):
    """局部环可满足性状态；不等价于任何全窗口 verdict。"""

    FEASIBLE = "FEASIBLE"
    INFEASIBLE = "INFEASIBLE"
    UNKNOWN = "UNKNOWN"


class CandidateCycleReplayStatus(StrEnum):
    """独立 replay 对候选环的接受状态。"""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    NOT_RUN = "not_run"


class CandidateReplayFailureKind(StrEnum):
    """局部 witness replay 的失败分类；这些类别不改变正式 verdict。"""

    RF_ASSIGNMENT_INCOMPLETE = "rf_assignment_incomplete"
    FR_CO_INCONSISTENT = "fr_co_inconsistent"
    PPO_WITNESS_INVALID = "ppo_witness_invalid"
    SOURCE_TARGET_SEMANTIC_CONFLICT = "source_target_semantic_conflict"
    FENCE_RMW_FUTEX_CONSTRAINT_MISSING = "fence_rmw_futex_constraint_missing"
    BINDING_MISMATCH = "binding_mismatch"
    WITNESS_SERIALIZATION_ERROR = "witness_serialization_error"
    LOCAL_MODEL_INCOMPLETE = "local_model_incomplete"


class CandidateReplayFailure(StrictModel):
    """指出被违反的具体 obligation 和 replay predicate。"""

    kind: CandidateReplayFailureKind
    obligation_id: str
    predicate: str
    detail: str


class GraphFirstEdge(StrictModel):
    """候选坏环中的一条带关系族标签的边。"""

    # 关系的起点事件，使用 trace 内稳定 event_id。
    source_event: str
    # 关系的终点事件，使用 trace 内稳定 event_id。
    target_event: str
    # source_ppo、rf、fr、coherence 等关系族。
    relation_kind: str
    # 用于回到候选域的稳定关系标识。
    relation_id: str
    # 同端点同关系族的所有候选标签；不能因图搜索去重而丢失候选域。
    relation_ids: tuple[str, ...] = ()
    # source/target 侧；PPO_REACHABILITY 表示两侧均需 replay。
    side: str = "source"
    # RF/FR/CO 是条件边，PPO_REACHABILITY 是已证明的 reachability。
    conditional: bool = False
    # PPO 摘要边的原始 reduced-graph witness path。
    witness_path: tuple[str, ...] = ()


class CandidateViolationEdge(StrictModel):
    """CandidateViolationCycle 中一条已经分类的语义边。"""

    source_event: str
    target_event: str
    relation_type: str
    side: str
    conditional: bool
    relation_ids: tuple[str, ...] = ()
    rf_candidate_ids: tuple[str, ...] = ()
    fr_consequence_ids: tuple[str, ...] = ()
    co_dependency_ids: tuple[str, ...] = ()
    ppo_reachability_path: tuple[str, ...] = ()
    boundary_dependency_ids: tuple[str, ...] = ()
    unresolved_dependency_reasons: tuple[str, ...] = ()


class CandidateViolationCycle(StrictModel):
    """符合当前 source-cycle/target-acyclic 查询语义的候选，而非任意图环。"""

    schema_version: str = "candidate-violation-cycle-v1"
    cycle_id: str
    cycle_nodes: tuple[str, ...]
    ordered_edges: tuple[CandidateViolationEdge, ...]
    source_side: str = "source"
    target_side_condition: str = "target_acyclic"
    rf_dependencies: tuple[str, ...] = ()
    fr_dependencies: tuple[str, ...] = ()
    co_dependencies: tuple[str, ...] = ()
    ppo_reachability_dependencies: tuple[tuple[str, ...], ...] = ()
    fence_rmw_futex_dependencies: tuple[str, ...] = ()
    unresolved_dependencies: tuple[str, ...] = ()
    # 该对象描述的是 over-approximate candidate space，不能单独证明结论。
    diagnostic_only: bool = True


class MayViolationGraphContract(StrictModel):
    """may-edge graph 的保守边界。"""

    schema_version: str = "may-violation-graph-contract-v1"
    must_edge_families: tuple[str, ...] = ("source_ppo",)
    conditional_edge_families: tuple[str, ...] = ("rf", "fr", "coherence")
    reachability_is_summarized: bool = True
    parallel_relation_labels_preserved: bool = True
    over_approximate: bool = True
    missing_edge_is_unknown: bool = True
    diagnostic_only: bool = True


class MayViolationGraphSummary(StrictModel):
    """一个窗口 may graph 的结构和完整性摘要。"""

    contract: MayViolationGraphContract = MayViolationGraphContract()
    node_count: int
    edge_count: int
    relation_counts: dict[str, int] = Field(default_factory=dict)
    conditional_edge_count: int
    scc_count: int
    cyclic_scc_count: int
    largest_scc_node_count: int
    largest_scc_edge_count: int
    graph_complete_for_observed_candidates: bool
    reasons: tuple[str, ...] = ()


class LocalCycleObligationSet(StrictModel):
    """判断一个候选环所需的局部关系和 global RF context。"""

    cycle_id: str
    # query_event_ids 固定局部 SMT 的事件 universe，replay 可独立重建变量域。
    query_event_ids: tuple[str, ...] = ()
    # window_event_ids 固定候选所属的完整窗口；局部 UNSAT 不能排除全窗候选。
    window_event_ids: tuple[str, ...] = ()
    # 绑定实际编码的事件、PPO 输入、contract 和 solver 配置。
    query_context_digest: str = ""
    selected_rf_relation_ids: tuple[str, ...] = ()
    rf_candidate_domain_ids: tuple[str, ...] = ()
    required_fr_relation_ids: tuple[str, ...] = ()
    required_co_relation_ids: tuple[str, ...] = ()
    ppo_witness_paths: tuple[tuple[str, ...], ...] = ()
    boundary_event_ids: tuple[str, ...] = ()
    unresolved_dependencies: tuple[str, ...] = ()
    # 即使当前环只选一个 RF，也必须保留该 read 的 exactly-one 候选域。
    rf_exclusivity_preserved: bool = True
    diagnostic_only: bool = True


class LocalCycleWitness(StrictModel):
    """局部 solver 的可 replay witness，不是最终 counterexample。"""

    cycle_id: str
    rf_assignments: tuple[tuple[str, str | None, int, int], ...] = ()
    co_assignments: tuple[tuple[str, str], ...] = ()
    fr_consequences: tuple[tuple[str, str], ...] = ()
    ppo_reachability_witnesses: tuple[tuple[str, ...], ...] = ()
    ordering_assignment: tuple[tuple[str, str], ...] = ()
    cycle_edges: tuple[tuple[str, str], ...] = ()
    # source_cycle 是 solver 实际选出的 source relation cycle，不等同于候选骨架。
    source_cycle: tuple[str, ...] = ()
    # 完整决策变量只在 P16 复现实验中按需保存。
    model_snapshot: SymbolicModelSnapshot | None = None
    diagnostic_only: bool = True


class CandidateBlockingClause(StrictModel):
    """对一个已证实不可行的精确候选进行可追踪阻塞。"""

    cycle_id: str
    literals: tuple[str, ...] = ()
    solver_result: str
    exact_candidate_key: str
    verified_unsat: bool
    replayable: bool
    diagnostic_only: bool = True


class CegarSearchStatus(StrEnum):
    """CEGAR 候选搜索的覆盖状态；这些值不能映射为正式 verdict。"""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN_REMAINS = "UNKNOWN_REMAINS"
    TRUNCATED = "TRUNCATED"


class CanonicalCycleSkeleton(StrictModel):
    """忽略 PPO witness 走法、保留语义端点和条件关系的候选身份。"""

    schema_version: str = "canonical-cycle-skeleton-v1"
    canonical_id: str
    # 每项为 source,target,relation,side,conditional,relation-labels。
    # PPO 的内部 witness 不写入这里，避免同一可达性被重复计数。
    edge_signatures: tuple[tuple[str, ...], ...]
    critical_endpoints: tuple[str, ...]
    rf_candidate_ids: tuple[str, ...] = ()
    fr_dependency_ids: tuple[str, ...] = ()
    co_dependency_ids: tuple[str, ...] = ()
    ppo_reachability_pairs: tuple[tuple[str, str], ...] = ()
    source_side: str = "source"
    target_side_condition: str = "target_acyclic"
    diagnostic_only: bool = True


class CandidateSpaceProfile(StrictModel):
    """CEGAR 搜索空间的诊断剖面，不表示候选空间已经穷尽。"""

    schema_version: str = "candidate-space-profile-v1"
    raw_search_states: int = 0
    generated_skeletons: int = 0
    unique_skeletons: int = 0
    duplicate_skeletons: int = 0
    same_rf_assignment_variants: int = 0
    same_structural_cycle_different_ppo_witness: int = 0
    local_smt_submitted: int = 0
    exact_blocked_candidates: int = 0
    repeated_infeasible_cores: int = 0
    branching_factor: float = 0.0
    depth_histogram: dict[str, int] = Field(default_factory=dict)
    search_truncated: bool = False
    query_truncated: bool = False
    diagnostic_only: bool = True


class CandidateDiscoveryProfile(StrictModel):
    """结构化候选发现的阶段计数；不表示候选空间已经穷尽。"""

    schema_version: str = "candidate-discovery-profile-v1"
    scheduler: str = "depth_first"
    fair_seed_scheduling: bool = False
    conditional_seed_count: int = 0
    seeds_visited: int = 0
    ppo_reachability_queries: int = 0
    ppo_reachability_cache_hits: int = 0
    path_expansions: int = 0
    rejected_cycles: int = 0
    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    generated_skeletons: int = 0
    unique_skeletons: int = 0
    remaining_frontier: int | None = None
    search_truncated: bool = False
    max_cycle_length: int = 0
    max_search_states: int = 0
    # P15 只读画像：这些数字用于解释资源消耗，不能改变候选语义。
    successors_generated: int = 0
    frontier_peak: int = 0
    estimated_frontier_bytes: int | None = None
    estimated_state_bytes: int | None = None
    estimated_path_bytes: int | None = None
    estimated_reachability_cache_bytes: int | None = None
    # 这些是浅层估计，用来区分 frontier、缓存和索引各自的增长，
    # 不能被当作精确的进程内存账本或资源安全证明。
    memory_components: dict[str, int] = Field(default_factory=dict)
    memory_samples: tuple[dict[str, object], ...] = ()
    resource_limit_reached: bool = False
    termination_reason: str | None = None
    resumable: bool = False
    checkpoint_path: str | None = None
    checkpoint_binding_digest: str | None = None
    spill_size_bytes: int = 0
    diagnostic_only: bool = True


class CandidateDiscoveryResourcePolicy(StrictModel):
    """候选发现的资源边界；达到边界只能保留未探索状态并报告截断。

    这些限制只作用于 shadow discovery。它们不能把未探索空间解释成空集，
    也不能改变正式 checker 的 SAFE/UNKNOWN/COUNTEREXAMPLE 结论。
    """

    schema_version: str = "candidate-discovery-resource-policy-v1"
    max_in_memory_frontier: int | None = None
    max_rss_mb: float | None = None
    max_search_states: int | None = None
    max_wall_time_ms: int | None = None
    sample_every: int = 100
    checkpoint_path: str | None = None
    resume_checkpoint: str | None = None
    progress_path: str | None = None
    diagnostic_only: bool = True


class CandidateBlockingConstraint(StrictModel):
    """记录一次 UNSAT 查询；当前只允许按完全相同的全窗查询复用。"""

    schema_version: str = "candidate-blocking-constraint-v2"
    block_id: str
    kind: str
    # 规范化后的 RF/CO/FR/edge assumptions；不能由 timeout 生成。
    assumptions: tuple[str, ...] = ()
    rf_relation_ids: tuple[str, ...] = ()
    co_relation_ids: tuple[str, ...] = ()
    fr_relation_ids: tuple[str, ...] = ()
    canonical_structure_id: str | None = None
    source_candidate_id: str
    source_query_digest: str
    # 以下字段把记录绑定到候选、查询输入和 obligation。
    # replayable 只表示这些边界可重放，不是 Z3 UNSAT 证明证书。
    candidate_digest: str | None = None
    obligation_digest: str | None = None
    semantic_context_digest: str | None = None
    proof_scope: str = "full-window-exact-query-v2"
    solver_result: str
    # 这是求解器调用方记录的返回值；当前格式不携带可独立检查的 Z3 proof。
    verified_unsat: bool
    replayable: bool
    pruned_candidate_count: int = 0
    diagnostic_only: bool = True


class CegarCandidateRecord(StrictModel):
    """CEGAR 一次候选的生成、局部查询和 replay 结果。"""

    candidate_id: str
    canonical_skeleton: CanonicalCycleSkeleton
    candidate_violation_cycle: CandidateViolationCycle
    local_query: GraphFirstLocalQuery | None = None
    local_obligations: LocalCycleObligationSet | None = None
    local_witness: LocalCycleWitness | None = None
    replay: CandidateCycleReplay | None = None
    blocking_constraint: CandidateBlockingConstraint | None = None
    pruned: bool = False
    prune_reason: str | None = None
    diagnostic_only: bool = True


class CegarSearchLedger(StrictModel):
    """CEGAR 状态机账本，显式区分未探索、UNKNOWN 和穷尽。"""

    schema_version: str = "cegar-search-ledger-v1"
    candidate_space: str
    may_graph_complete: bool
    status: CegarSearchStatus
    raw_search_states: int
    generated_count: int
    canonical_count: int
    duplicate_count: int
    feasible_count: int
    infeasible_count: int
    unknown_count: int
    not_run_count: int
    blocked_count: int
    pruned_by_block_count: int
    local_query_count: int
    not_explored_count: int | None
    search_truncated: bool
    query_truncated: bool
    # 截断时无法估计剩余 frontier，使用 None 而不是伪造为 0。
    frontier_count: int | None
    blocking_constraints: tuple[CandidateBlockingConstraint, ...] = ()
    diagnostic_only: bool = True


class CegarWindowReport(StrictModel):
    """单窗口 CEGAR shadow 报告；永远不产生正式 SAFE/反例。"""

    schema_version: str = "cegar-window-v1"
    window_id: str
    event_count: int
    # P11/P12 搜索路径标签，仅用于实验比较。
    mode: str = "P12_CANONICAL_BLOCKING"
    diagnostic_only: bool = True
    reduction_replay_accepted: bool = False
    reduction_certificate_digest: str | None = None
    source_original_ppo_edges: int = 0
    source_reduced_ppo_edges: int = 0
    target_original_ppo_edges: int = 0
    target_reduced_ppo_edges: int = 0
    candidate_edge_count: int = 0
    relation_counts: dict[str, int] = Field(default_factory=dict)
    scc_count: int = 0
    cyclic_scc_count: int = 0
    largest_scc_node_count: int = 0
    largest_scc_edge_count: int = 0
    candidates: tuple[CegarCandidateRecord, ...] = ()
    profile: CandidateSpaceProfile | None = None
    ledger: CegarSearchLedger | None = None
    reasons: tuple[str, ...] = ()


class TraceCegarReport(StrictModel):
    """整条 trace 的 CEGAR 诊断报告，不能改变 trace verdict。"""

    schema_version: str = "trace-cegar-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    diagnostic_only: bool = True
    windows: tuple[CegarWindowReport, ...] = ()
    reasons: tuple[str, ...] = ()


class CandidateCycleReplay(StrictModel):
    """不信任 local solver producer 的候选环独立 replay 结果。"""

    cycle_id: str
    status: CandidateCycleReplayStatus
    cycle_closed: bool
    ppo_reachability_valid: bool
    rf_candidates_valid: bool
    rf_exclusivity_valid: bool
    fr_consequences_valid: bool
    co_valid: bool
    boundary_ordering_valid: bool
    source_violation_valid: bool
    target_condition_valid: bool
    # None 表示旧实验没有保存模型，不能声称完成了模型闭包检查。
    model_snapshot_valid: bool | None = None
    full_window_closed: bool | None = None
    # failures 将聚合原因落到单项 obligation/predicate，便于回归审计。
    failures: tuple[CandidateReplayFailure, ...] = ()
    reasons: tuple[str, ...] = ()
    diagnostic_only: bool = True


class CandidateSearchLedger(StrictModel):
    """记录候选空间覆盖，禁止把有限搜索误报成 SAFE。"""

    candidate_space: str
    may_graph_complete: bool
    generated_count: int
    feasible_count: int
    infeasible_count: int
    unknown_count: int
    blocked_count: int
    # 搜索截断时无法知道剩余候选数量，因此显式使用 None。
    not_explored_count: int | None
    search_truncated: bool
    # encoding-only 或局部查询未启动时单独记账，不能伪装成 UNSAT。
    not_run_count: int = 0
    blocking_clauses: tuple[CandidateBlockingClause, ...] = ()
    diagnostic_only: bool = True


class GraphFirstLocalQuery(StrictModel):
    """一次候选环局部 SMT 查询的资源和结果摘要。

    局部查询只回答“这个候选环的必要条件在小范围内是否可满足”。
    它没有全窗口覆盖证明，不能写入 SAFE、TRACE_SAFE 或 COUNTEREXAMPLE。
    """

    # 诊断状态，不得映射为正式 verdict。
    status: GraphFirstQueryStatus
    # Z3/encoder 层原始状态，例如 sat、unsat、timeout。
    solver_result: str
    # 解释局部查询为何得到该状态。
    reason: str
    # 候选环诱导的局部事件数。
    event_count: int
    # 局部 shadow 使用的 source PPO 边数。
    source_ppo_edge_count: int
    # 局部 shadow 使用的 target PPO 边数。
    target_ppo_edge_count: int
    # encoder 估计的 symbolic term 数。
    formula_terms: int = 0
    # 实际加入 Z3 的 assertion 数。
    assertion_count: int = 0
    # 实际构造的 Z3 AST 节点数。
    z3_ast_count: int = 0
    # 构造局部公式的耗时。
    build_time_ms: int = 0
    # 求解器耗时；未运行时为空。
    solver_time_ms: int | None = None
    # 防止下游把局部结果当作证明事实。
    diagnostic_only: bool = True
    # P11 统一使用 FEASIBLE/INFEASIBLE/UNKNOWN 三值标签。
    feasibility_status: LocalCycleStatus = LocalCycleStatus.UNKNOWN


class GraphFirstCandidateCycle(StrictModel):
    """有界图搜索找到的候选坏环及其局部查询。"""

    # 本次有界搜索内的稳定候选编号。
    cycle_id: str
    # 环上的事件序列，末尾重复起点便于报告阅读。
    event_ids: tuple[str, ...]
    # 环上每条边及其关系族。
    edges: tuple[GraphFirstEdge, ...]
    # 环必须至少含一条非 PPO 边才进入局部查询。
    includes_non_ppo: bool
    # 对该环诱导范围的局部 shadow 结果。
    local_query: GraphFirstLocalQuery | None = None
    # 候选搜索不是完整证明，不能越过这个边界。
    diagnostic_only: bool = True
    # P11 的语义候选；旧字段仍保留以兼容 P10 报告。
    candidate_violation_cycle: CandidateViolationCycle | None = None
    # 该环需要的局部 obligation，包含完整 RF candidate domain。
    local_obligations: LocalCycleObligationSet | None = None
    # local SMT 产出的可 replay witness。
    local_witness: LocalCycleWitness | None = None
    # 不信任 producer 的独立 replay 结果。
    replay: CandidateCycleReplay | None = None
    # 分别记录 witness / obligation materialization / independent replay 耗时。
    witness_build_ms: int = 0
    obligations_build_ms: int = 0
    replay_ms: int = 0
    # local UNSAT 时的精确候选阻塞信息。
    blocking_clause: CandidateBlockingClause | None = None


class GraphFirstWindowReport(StrictModel):
    """单个窗口的 graph-first shadow 报告。"""

    # 报告结构版本，便于未来改变诊断字段时拒绝误读。
    schema_version: str = "graph-first-window-v2"
    # 来源分析窗口身份。
    window_id: str
    # 窗口保留的全部事件数量。
    event_count: int
    # 明确标识本报告不能产生正式结论。
    diagnostic_only: bool = True
    # PPO reduction 是否通过独立 replay。
    reduction_replay_accepted: bool = False
    # replay 绑定的 reduction certificate 摘要。
    reduction_certificate_digest: str | None = None
    # reduction 前 source PPO 边数。
    source_original_ppo_edges: int = 0
    # reduction 后 source PPO 边数。
    source_reduced_ppo_edges: int = 0
    # reduction 前 target PPO 边数。
    target_original_ppo_edges: int = 0
    # reduction 后 target PPO 边数。
    target_reduced_ppo_edges: int = 0
    # 有界图搜索使用的去重关系边数。
    candidate_edge_count: int = 0
    # 各关系族在去重前的候选数量。
    relation_counts: dict[str, int] = Field(default_factory=dict)
    # 图中的强连通分量数量。
    scc_count: int = 0
    # 可能包含有向环的强连通分量数量。
    cyclic_scc_count: int = 0
    # DFS 实际展开的边访问次数。
    explored_states: int = 0
    # 有界搜索发现的候选环数量。
    cycles_considered: int = 0
    # 实际送入局部 shadow 的候选环数量。
    cycles_returned: int = 0
    # 是否因搜索/候选上限截断。
    truncated: bool = False
    # 单个候选环允许的最大节点数。
    max_cycle_length: int = 12
    # 最多执行多少个局部候选查询。
    max_cycles: int = 32
    # 最多展开多少个 DFS 边状态。
    max_search_states: int = 100_000
    # 有界候选环和局部查询明细。
    candidates: tuple[GraphFirstCandidateCycle, ...] = ()
    # 不能当作成功的原因和边界说明。
    reasons: tuple[str, ...] = ()
    # P11 may-edge graph 的 over-approximation 摘要。
    may_graph: MayViolationGraphSummary | None = None
    # 候选生成与检查是否覆盖完整空间的账本。
    search_ledger: CandidateSearchLedger | None = None
    # P14 结构化发现计数；仅用于比较搜索前沿，不进入 verdict。
    discovery_profile: CandidateDiscoveryProfile | None = None
    # skeleton 图只显式保留条件边，PPO 通过 reachability oracle 懒查询。
    skeleton_edge_count: int = 0
    skeleton_scc_count: int = 0
    skeleton_cyclic_scc_count: int = 0


class TraceGraphFirstReport(StrictModel):
    """整条 trace 的 graph-first shadow 报告，永远不产生正式 verdict。"""

    # 报告结构版本。
    schema_version: str = "trace-graph-first-v2"
    # 来源 trace 身份。
    trace_id: str
    # 采集结构是否完整；不等于局部查询完整。
    trace_complete: bool
    # 是否真正构造过分析窗口。
    analysis_reached_windows: bool
    # 顶层诊断边界，阻止误用为 trace verdict。
    diagnostic_only: bool = True
    # 每个窗口的 graph-first 诊断。
    windows: tuple[GraphFirstWindowReport, ...] = ()
    # trace/import/window 层的保守原因。
    reasons: tuple[str, ...] = ()


# These classes are declared before some of the legacy graph-first classes so
# the shared model file keeps the historical schema order.  Resolve the
# forward references once every model is available.
CegarCandidateRecord.model_rebuild()
CegarWindowReport.model_rebuild()


__all__ = [
    "GraphFirstQueryStatus",
    "LocalCycleStatus",
    "CandidateCycleReplayStatus",
    "GraphFirstEdge",
    "CandidateViolationEdge",
    "CandidateViolationCycle",
    "MayViolationGraphContract",
    "MayViolationGraphSummary",
    "LocalCycleObligationSet",
    "LocalCycleWitness",
    "CandidateBlockingClause",
    "CegarSearchStatus",
    "CanonicalCycleSkeleton",
    "CandidateSpaceProfile",
    "CandidateDiscoveryProfile",
    "CandidateDiscoveryResourcePolicy",
    "CandidateBlockingConstraint",
    "CegarCandidateRecord",
    "CegarSearchLedger",
    "CegarWindowReport",
    "TraceCegarReport",
    "CandidateCycleReplay",
    "CandidateSearchLedger",
    "GraphFirstLocalQuery",
    "GraphFirstCandidateCycle",
    "GraphFirstWindowReport",
    "TraceGraphFirstReport",
]
