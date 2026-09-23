from __future__ import annotations

from pydantic import Field

from .graph_first import (
    CandidateCycleReplay,
    CandidateCycleReplayStatus,
    LocalCycleWitness,
)
from .manifest import StrictModel


class FixedCycleRelationRequirement(StrictModel):
    """P18 固定环上一组需要按 OR 激活的精确条件关系。"""

    source_event: str = Field(description="关系的起点事件")
    target_event: str = Field(description="关系的终点事件")
    relation_type: str = Field(description="RF、FR 或 CO 关系族")
    relation_ids: tuple[str, ...] = Field(description="同组可任选其一的稳定关系 ID")


class P17CandidateComparison(StrictModel):
    """P17 完整独立查询与共享增量查询的冻结对照计量。"""

    independent_result: str = Field(description="P17 独立全窗查询结果")
    independent_formula_terms: int = Field(description="独立查询公式项数")
    independent_assertion_count: int = Field(description="独立查询断言数")
    independent_ast_node_count: int = Field(description="独立查询 AST 节点数")
    independent_build_time_ms: int = Field(description="独立查询构造时间")
    independent_solver_time_ms: int | None = Field(description="独立查询求解时间")
    independent_replay_status: str = Field(description="独立查询原有 replay 状态")
    shared_result: str = Field(description="P17 共享增量查询结果")
    shared_base_formula_terms: int = Field(description="共享 solver 基础公式项数")
    shared_base_assertion_count: int = Field(description="共享基础公式断言数")
    shared_base_ast_node_count: int = Field(description="共享基础公式 AST 节点数")
    shared_base_build_time_ms: int = Field(description="共享基础公式构造时间")
    shared_candidate_build_time_ms: int = Field(description="该候选额外关系构造时间")
    shared_push_pop_time_ms: int = Field(description="该候选 solver 栈操作时间")
    shared_solver_time_ms: int | None = Field(description="共享查询求解时间")
    shared_peak_rss_mb: float | None = Field(description="共享 worker 峰值 RSS")
    p17_results_match: bool | None = Field(
        default=None, description="P17 本身独立与共享查询结果是否相同"
    )


class FixedCycleShadowQuery(StrictModel):
    """完整窗口中固定一个既有 source cycle 的 shadow 查询结果。"""

    candidate_id: str = Field(description="冻结候选的稳定 ID")
    candidate_skeleton_id: str = Field(description="固定候选骨架的摘要 ID")
    fixed_cycle_edges: tuple[tuple[str, str], ...] = Field(
        description="求解器固定选择的闭环有向边"
    )
    relation_requirements: tuple[FixedCycleRelationRequirement, ...] = Field(
        description="每条条件边的精确 relation-ID OR 组"
    )
    full_window_event_count: int = Field(description="公式覆盖的完整窗口事件数")
    candidate_preparation_time_ms: int = Field(
        description="组装固定环边集和 PPO 输入的预处理时间"
    )
    full_window_constraints: bool = Field(
        default=True, description="RF/FR/CO/PPO/Fence/RMW 均来自完整窗口公式"
    )
    rf_choices_remain_symbolic: bool = Field(
        default=True, description="没有固定任何 read 的 RF 来源选择"
    )
    relation_groups_use_or: bool = Field(
        default=True, description="同组多个 relation ID 保持任选其一"
    )
    target_acyclicity_retained: bool = Field(
        default=True, description="完整 target rank/无环条件仍参与查询"
    )
    rmw_constraints_retained: bool = Field(
        default=True, description="完整 RMW coherence 前驱约束仍参与查询"
    )
    official_verdict_changed: bool = Field(
        default=False, description="该实验不会写回正式 verifier verdict"
    )
    rf_choice_count: int = Field(description="保持符号化的完整 RF 选择变量数")
    p17_independent_result: str = Field(description="P17 独立全窗查询的对照状态")
    p17_shared_result: str = Field(description="P17 共享增量查询的对照状态")
    p17_baseline: P17CandidateComparison | None = Field(
        default=None, description="P17 同一候选的完整 A/B 资源计量"
    )
    p17_formula_profile_result: str = Field(
        description="本轮无求解器重建旧完整公式的编码状态"
    )
    p17_formula_profile_reason: str = Field(
        default="", description="旧完整公式 profiling 未完成时的原因"
    )
    p17_formula_profile_terms: int = Field(
        description="旧完整公式 profiling 的公式项数"
    )
    p17_formula_profile_assertions: int = Field(
        description="旧完整公式 profiling 的断言数"
    )
    p17_formula_profile_ast_nodes: int = Field(
        description="旧完整公式 profiling 的 AST 节点数"
    )
    p17_formula_profile_build_ms: int = Field(
        description="旧完整公式 profiling 的构造时间"
    )
    p17_formula_breakdown: dict[str, int] = Field(
        default_factory=dict, description="旧完整公式各类别估算项数"
    )
    p17_constraint_breakdown: dict[str, int] = Field(
        default_factory=dict, description="旧完整公式各类别断言数"
    )
    p17_variable_counts: dict[str, int] = Field(
        default_factory=dict, description="旧完整公式各类别变量数"
    )
    definitive_result_matches_p17: bool | None = Field(
        default=None,
        description="双方均为 SAT/UNSAT 时是否一致，遇 UNKNOWN 时留空",
    )
    solver_result: str = Field(description="本次 Z3 SAT、UNSAT 或 UNKNOWN 状态")
    reason: str = Field(default="", description="求解器给出的原因或资源终止说明")
    formula_terms: int = Field(description="本次公式的估算项数")
    assertion_count: int = Field(description="加入 Z3 的断言数量")
    ast_node_count: int = Field(description="公式 AST 节点数")
    build_time_ms: int = Field(description="公式构造耗时")
    solver_time_ms: int | None = Field(default=None, description="Z3 实际求解耗时")
    peak_rss_mb: float | None = Field(default=None, description="进程峰值常驻内存")
    formula_breakdown: dict[str, int] = Field(
        default_factory=dict, description="按公式类别统计的估算项数"
    )
    constraint_breakdown: dict[str, int] = Field(
        default_factory=dict, description="按约束类别统计的断言数"
    )
    variable_counts: dict[str, int] = Field(
        default_factory=dict, description="各类符号变量数"
    )
    replay_status: CandidateCycleReplayStatus = Field(
        description="独立 replay 实际验证到的证据等级"
    )
    replay_reasons: tuple[str, ...] = Field(
        default=(), description="独立 replay 拒绝或限制结论的原因"
    )
    independent_replay: CandidateCycleReplay | None = Field(
        default=None,
        description="独立重放的完整检查项；符号模型不等于真实执行反例",
    )
    witness: LocalCycleWitness | None = Field(
        default=None, description="SAT 时保存的完整模型和可独立重放 witness"
    )
    diagnostic_only: bool = Field(default=True, description="该结果不参与正式 verdict")


class P18FixedCycleReport(StrictModel):
    """P18 固定十候选研究结果及其全部输入绑定。"""

    schema_version: str = Field(
        default="p18-fixed-cycle-shadow-v1", description="报告格式版本"
    )
    trace_id: str = Field(description="动态执行的 trace identity")
    trace_sha256: str = Field(description="被冻结 trace 数据摘要")
    contract_sha256: str = Field(description="DBT6 mo-off contract 摘要")
    window_id: str = Field(description="被冻结分析窗口 ID")
    event_count: int = Field(description="完整窗口中的事件数")
    ppo_certificate_digest: str = Field(description="PPO reduction 证书摘要")
    fixed_candidate_report_sha256: str = Field(
        description="P16/P17 固定候选输入报告摘要"
    )
    p17_report_sha256: str = Field(description="P17 对照报告摘要")
    candidate_ids: tuple[str, ...] = Field(description="本轮固定候选 ID 清单")
    queries: tuple[FixedCycleShadowQuery, ...] = Field(
        default=(), description="逐候选固定 source cycle 查询和 replay 结果"
    )
    timeout_ms: int = Field(description="每条查询使用的 Z3 超时设置")
    max_symbolic_terms: int = Field(description="公式构造的项数上限")
    process_wall_limit_seconds: int = Field(description="worker 的硬墙钟限制")
    process_memory_limit_mb: int = Field(description="worker 的虚拟地址空间上限")
    process_peak_rss_mb: float | None = Field(
        default=None, description="独立 worker 的实测峰值 RSS"
    )
    worker_wall_time_ms: int | None = Field(
        default=None, description="包含输入准备的 worker 墙钟时间"
    )
    worker_exit_code: int | None = Field(
        default=None, description="受限 worker 的退出码"
    )
    termination_reason: str = Field(
        default="completed", description="报告或 worker 的终止原因"
    )
    limitations: tuple[str, ...] = Field(
        default=(), description="不能从本报告推出的结论和已知限制"
    )
    diagnostic_only: bool = Field(default=True, description="P18 结果不进入正式分析 verdict")
