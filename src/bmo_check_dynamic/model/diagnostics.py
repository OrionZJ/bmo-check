from __future__ import annotations

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

