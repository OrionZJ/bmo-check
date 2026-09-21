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
