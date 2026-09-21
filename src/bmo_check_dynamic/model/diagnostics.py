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
