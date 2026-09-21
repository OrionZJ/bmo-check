from __future__ import annotations

from enum import StrEnum

from .manifest import StrictModel


class SymbolicEncodingStats(StrictModel):
    """不创建 Z3 AST 的编码规模估计；只用于定位模型膨胀来源。"""

    schema_version: str = "symbolic-encoding-v1"
    window_id: str
    event_count: int
    memory_event_count: int
    read_count: int
    write_count: int
    node_count: int
    source_ppo_edge_count: int
    target_ppo_edge_count: int
    initial_formula_terms: int
    coherence_component_count: int
    coherence_write_count: int
    coherence_pair_count: int
    rf_part_count: int
    rf_candidate_count: int
    cross_thread_rf_edge_count: int
    from_read_candidate_count: int
    conditional_edge_additions: int
    conditional_edge_count: int
    conditional_term_weight: int
    cycle_edge_count: int
    cycle_node_count: int
    estimated_formula_terms: int


class WindowGraphNode(StrictModel):
    """窗口图中度数最高的节点；只用于解释图膨胀来源。"""

    event_id: str
    thread_id: int
    sequence: int
    kind: str
    degree: int
    communication_degree: int
    program_order_degree: int
    boundary_degree: int


class WindowGraphAddress(StrictModel):
    """通信图中最热地址类的有界摘要。"""

    address: int
    size: int
    event_count: int
    communication_edge_count: int
    load_count: int
    store_count: int


class WindowGraphDiagnostics(StrictModel):
    """窗口构造图的只读表征，不表示任何可证明的删除。"""

    schema_version: str = "window-graph-diagnostics-v1"
    node_count: int
    communication_edge_count: int
    program_order_edge_count: int
    boundary_edge_count: int
    graph_edge_count: int
    connected_component_count: int
    biconnected_component_count: int
    articulation_node_count: int
    max_degree: int
    p95_degree: int
    max_biconnected_component_nodes: int
    max_biconnected_component_edges: int
    top_degree_nodes: tuple[WindowGraphNode, ...] = ()
    top_address_classes: tuple[WindowGraphAddress, ...] = ()


class BottleneckRelationKind(StrEnum):
    """P6 把 inventory obligation 和派生 FR 关系放进同一张诊断表。"""

    EVENT_PRESENCE = "event_presence"
    COMMUNICATION = "communication"
    SOURCE_PPO = "source_ppo"
    TARGET_PPO = "target_ppo"
    READ_FROM_DOMAIN = "read_from_domain"
    COHERENCE_DOMAIN = "coherence_domain"
    FROM_READ = "from_read"
    FENCE = "fence"
    ATOMIC_RMW = "atomic_rmw"
    SYNC_BOUNDARY = "sync_boundary"


class ObligationTypeStats(StrictModel):
    """一种关系在全窗口及最大组件中的数量。"""

    kind: BottleneckRelationKind
    inventory_count: int
    derived_count: int
    total_count: int
    event_incidence_count: int
    component_count: int
    largest_component_count: int


class ObligationComponentStats(StrictModel):
    """obligation 超图一个连通组件的有界摘要。"""

    component_id: str
    event_count: int
    relation_count: int
    inventory_obligation_count: int
    derived_relation_count: int
    graph_edge_count: int
    density: float
    articulation_node_count: int
    relation_types: tuple[ObligationTypeStats, ...] = ()


class BottleneckEvent(StrictModel):
    """热点 Load 的关系度数；不表示可以删除该事件。"""

    event_id: str
    thread_id: int
    sequence: int
    address: int
    size: int
    kind: str
    component_id: str
    obligation_degree: int
    source_ppo_degree: int
    target_ppo_degree: int
    rf_candidate_count: int
    from_read_exposure_count: int
    communication_degree: int
    cross_thread_communication_degree: int


class ObligationHotspot(StrictModel):
    """重复 Load 组与其周围关系的诊断摘要。"""

    hotspot_id: str
    thread_id: int
    address: int
    size: int
    kind: str
    event_count: int
    communication_endpoint_count: int
    component_id: str
    source_ppo_internal_count: int
    source_ppo_external_count: int
    target_ppo_internal_count: int
    target_ppo_external_count: int
    rf_candidate_total: int
    rf_candidate_max: int
    from_read_exposure_total: int
    from_read_exposure_max: int
    cross_thread_communication_count: int
    relation_incidence_count: int
    relation_types: tuple[ObligationTypeStats, ...] = ()
    top_events: tuple[BottleneckEvent, ...] = ()


class ThreadObligationContribution(StrictModel):
    """每个线程对关系网络的贡献。"""

    thread_id: int
    event_count: int
    relation_incidence_count: int
    source_ppo_count: int
    target_ppo_count: int
    communication_count: int
    read_from_domain_count: int
    from_read_exposure_count: int


class AddressObligationContribution(StrictModel):
    """每个地址/宽度类的关系网络贡献。"""

    address: int
    size: int
    event_count: int
    load_count: int
    store_count: int
    relation_incidence_count: int
    communication_count: int
    source_ppo_count: int
    target_ppo_count: int
    read_from_domain_count: int
    from_read_exposure_count: int


class ObligationBottleneckReport(StrictModel):
    """单窗口 P6 表征；只读诊断，不改变 proof/verdict。"""

    schema_version: str = "obligation-bottleneck-v1"
    window_id: str
    event_count: int
    memory_event_count: int
    inventory_obligation_count: int
    derived_from_read_count: int
    relation_count: int
    rf_candidate_count: int
    max_rf_candidates: int
    from_read_candidate_count: int
    component_count: int
    largest_component_id: str | None = None
    largest_component_event_count: int
    largest_component_relation_count: int
    largest_component_density: float
    articulation_node_count: int
    articulation_event_ids: tuple[str, ...] = ()
    articulation_nodes_truncated: bool = False
    relation_types: tuple[ObligationTypeStats, ...] = ()
    components: tuple[ObligationComponentStats, ...] = ()
    components_truncated: bool = False
    hotspots: tuple[ObligationHotspot, ...] = ()
    hotspots_truncated: bool = False
    thread_contributions: tuple[ThreadObligationContribution, ...] = ()
    address_contributions: tuple[AddressObligationContribution, ...] = ()


class TraceObligationBottleneckReport(StrictModel):
    """整条 trace 的 P6 表征报告。"""

    schema_version: str = "trace-obligation-bottleneck-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[ObligationBottleneckReport, ...] = ()
    reasons: tuple[str, ...] = ()


class CycleRelevanceClass(StrEnum):
    """P7 对关系在当前 cycle 查询中的主要作用分类。"""

    DIRECT_CYCLE_EDGE = "direct_cycle_edge"
    REACHABILITY_SUPPORT = "reachability_support"
    CANDIDATE_DOMAIN_ONLY = "candidate_domain_only"
    ORDERING_SUPPORT = "ordering_support"
    UNRESOLVED = "unresolved"


class ViolationCycleSemantics(StrictModel):
    """从当前 finite/symbolic checker 恢复出的坏环契约。"""

    schema_version: str = "violation-cycle-semantics-v1"
    source_cycle_query: str
    target_cycle_query: str
    source_direct_relation_families: tuple[str, ...]
    target_ordering_relation_families: tuple[str, ...]
    conditional_relation_families: tuple[str, ...]
    source_cycle_required: bool = True
    target_cycle_forbidden: bool = True
    requires_control_flow_closed: bool = True
    requires_value_match: bool = True
    finite_relation_builder: str
    symbolic_relation_builder: str


class CycleRelevanceCount(StrictModel):
    """主要分类的数量；分类不会删除关系。"""

    classification: CycleRelevanceClass
    count: int


class PPOCycleSummary(StrictModel):
    """一侧 PPO 图的可达性和冗余候选统计。"""

    side: str
    direct_edge_count: int
    reachability_pair_count: int
    transitive_reduction_candidate_count: int
    nonredundant_edge_count: int
    cycle_relevant_direct_edge_count: int
    communication_relevant_edge_count: int
    internal_chain_edge_count: int
    hotspot_incident_edge_count: int
    hotspot_redundant_edge_count: int
    hotspot_communication_relevant_edge_count: int
    invalid_edge_count: int = 0


class CandidateCycleSummary(StrictModel):
    """RF/FR/CO 候选在 source/target 候选环中的有界统计。"""

    kind: str
    total_candidate_count: int
    source_cycle_relevant_count: int
    target_cycle_relevant_count: int
    either_cycle_relevant_count: int
    neither_cycle_relevant_count: int
    max_candidates_per_event: int
    cycle_relevance_is_overapproximation: bool = True


class CycleHotspotSummary(StrictModel):
    """重复 Load 热点对 PPO 与候选关系的贡献。"""

    thread_id: int
    address: int
    size: int
    kind: str
    event_count: int
    source_ppo_edge_count: int
    source_ppo_redundant_count: int
    source_ppo_communication_relevant_count: int
    target_ppo_edge_count: int
    target_ppo_redundant_count: int
    target_ppo_communication_relevant_count: int
    rf_candidate_count: int
    rf_source_cycle_relevant_count: int
    rf_target_cycle_relevant_count: int
    fr_candidate_count: int
    fr_source_cycle_relevant_count: int
    fr_target_cycle_relevant_count: int


class ObligationCycleClassification(StrictModel):
    """单条 obligation 的诊断分类；只保留报告中的有界样本。"""

    relation_id: str
    relation_kind: str
    event_ids: tuple[str, ...]
    classification: CycleRelevanceClass
    source_direct: bool = False
    target_direct: bool = False
    potentially_transitive_redundant: bool = False
    reason: str


class CycleRelevanceReport(StrictModel):
    """单窗口 P7 cycle relevance 表征，不改变 checker 输入。"""

    schema_version: str = "cycle-relevance-v1"
    window_id: str
    event_count: int
    full_relation_count: int
    cycle_direct_relation_count: int
    reachability_support_count: int
    candidate_domain_only_count: int
    ordering_support_count: int
    unresolved_count: int
    semantics: ViolationCycleSemantics
    classification_counts: tuple[CycleRelevanceCount, ...] = ()
    source_ppo: PPOCycleSummary
    target_ppo: PPOCycleSummary
    source_only_ppo_edge_count: int
    target_only_ppo_edge_count: int
    shared_ppo_edge_count: int
    rf: CandidateCycleSummary
    fr: CandidateCycleSummary
    coherence: CandidateCycleSummary
    hotspots: tuple[CycleHotspotSummary, ...] = ()
    hotspots_truncated: bool = False
    obligation_classifications: tuple[ObligationCycleClassification, ...] = ()
    obligation_classifications_truncated: bool = False
    estimated_explicit_relation_reduction: int
    estimated_explicit_relation_count_after_summary: int
    estimate_is_diagnostic_only: bool = True


class TraceCycleRelevanceReport(StrictModel):
    """整条 trace 的 P7 cycle relevance 表征。"""

    schema_version: str = "trace-cycle-relevance-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[CycleRelevanceReport, ...] = ()
    reasons: tuple[str, ...] = ()
