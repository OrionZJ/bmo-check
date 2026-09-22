from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .manifest import StrictModel


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


class GraphFirstWindowReport(StrictModel):
    """单个窗口的 graph-first shadow 报告。"""

    # 报告结构版本，便于未来改变诊断字段时拒绝误读。
    schema_version: str = "graph-first-window-v1"
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


class TraceGraphFirstReport(StrictModel):
    """整条 trace 的 graph-first shadow 报告，永远不产生正式 verdict。"""

    # 报告结构版本。
    schema_version: str = "trace-graph-first-v1"
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


__all__ = [
    "GraphFirstQueryStatus",
    "GraphFirstEdge",
    "GraphFirstLocalQuery",
    "GraphFirstCandidateCycle",
    "GraphFirstWindowReport",
    "TraceGraphFirstReport",
]
