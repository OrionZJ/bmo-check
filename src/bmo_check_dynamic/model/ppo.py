from __future__ import annotations

from enum import StrEnum

from pydantic import model_validator

from .diagnostics import SymbolicEncodingStats
from .manifest import StrictModel


class PpoSide(StrEnum):
    SOURCE = "source"
    TARGET = "target"


class SourcePpoSemantics(StrictModel):
    """source 查询如何消费 PPO。"""

    side: PpoSide = PpoSide.SOURCE
    consumers: tuple[str, ...] = (
        "source_conditions",
        "selected_source_cycle",
    )
    direct_edges_are_unconditional: bool = True
    cycle_depends_on_reachability: bool = True
    direct_edge_identity_is_semantic: bool = False
    replacement_requires_witness_path: bool = True


class TargetPpoSemantics(StrictModel):
    """target 查询如何消费 PPO。"""

    side: PpoSide = PpoSide.TARGET
    consumers: tuple[str, ...] = ("target_rank_constraints",)
    direct_edges_are_unconditional: bool = True
    acyclicity_depends_on_reachability: bool = True
    direct_edge_identity_is_semantic: bool = False
    replacement_requires_witness_path: bool = True


class ViolationCycleDependency(StrictModel):
    """把坏环查询依赖的关系族固定成可重放的契约。"""

    source_relation_families: tuple[str, ...] = (
        "source_ppo",
        "cross_thread_rf",
        "coherence",
        "from_read",
    )
    target_relation_families: tuple[str, ...] = (
        "target_ppo",
        "cross_thread_rf",
        "coherence",
        "from_read",
    )
    required_endpoint_families: tuple[str, ...] = (
        "communication",
        "cross_thread_rf",
        "coherence",
        "from_read",
        "fence",
        "atomic_rmw",
    )
    source_requires_nonempty_cycle: bool = True
    target_requires_acyclic_graph: bool = True
    control_flow_closed_required: bool = True
    value_match_required_for_counterexample: bool = True


class PpoSemanticContract(StrictModel):
    """P8 reduction 能力使用的 checker 语义边界。"""

    schema_version: str = "ppo-semantic-contract-v1"
    source: SourcePpoSemantics = SourcePpoSemantics()
    target: TargetPpoSemantics = TargetPpoSemantics()
    violation: ViolationCycleDependency = ViolationCycleDependency()
    protected_edge_families: tuple[str, ...] = (
        "fence_boundary",
        "atomic_rmw_boundary",
        "futex_boundary",
    )
    reachability_equivalence_is_sufficient: bool = True
    contract_digest: str


class PpoGraphBinding(StrictModel):
    """原始 PPO 图的身份；replay 不信任 producer 的边数。"""

    side: PpoSide
    node_count: int
    edge_count: int
    node_digest: str
    edge_digest: str
    protected_edge_digest: str
    relevant_endpoint_digest: str


class RelevantReachabilityPair(StrictModel):
    source_event: str
    target_event: str
    reasons: tuple[str, ...] = ()


class ReachabilityPairInventory(StrictModel):
    """完整集合用 digest/count 绑定，JSON 只保存有界样本。"""

    pair_count: int
    pair_digest: str
    sample: tuple[RelevantReachabilityPair, ...] = ()
    sample_limit: int = 64

    @model_validator(mode="after")
    def _valid_counts(self) -> "ReachabilityPairInventory":
        if self.pair_count < 0 or self.sample_limit < 0:
            raise ValueError("reachability pair counts cannot be negative")
        if len(self.sample) > self.sample_limit:
            raise ValueError("reachability sample exceeds sample_limit")
        return self


class RemovedPpoEdge(StrictModel):
    """一条被移除边在最终 reduced graph 中的可重放 witness。"""

    source_event: str
    target_event: str
    witness_path: tuple[str, ...] = ()
    witness_path_digest: str = ""
    witness_path_length: int = 0
    reason: str = "alternate PPO path preserves reachability"

    @model_validator(mode="after")
    def _valid_path(self) -> "RemovedPpoEdge":
        if self.witness_path:
            if len(self.witness_path) < 2:
                raise ValueError("removed PPO edge needs a witness path")
            if self.witness_path[0] != self.source_event:
                raise ValueError("witness path must start at removed edge source")
            if self.witness_path[-1] != self.target_event:
                raise ValueError("witness path must end at removed edge target")
            if self.witness_path_length not in {0, len(self.witness_path)}:
                raise ValueError("witness path length does not match path")
        elif self.witness_path_length < 2 or not self.witness_path_digest:
            raise ValueError("removed PPO edge needs an inline or digest witness")
        return self


class PpoSideReduction(StrictModel):
    """一个 source/target PPO 图的完整 reduction 证明材料。"""

    side: PpoSide
    original_edge_count: int
    reduced_edge_count: int
    protected_edge_count: int
    removed_edges: tuple[RemovedPpoEdge, ...] = ()
    required_reachability_pairs: ReachabilityPairInventory
    preserved_pairs: ReachabilityPairInventory
    missing_pairs: ReachabilityPairInventory
    extra_pairs: ReachabilityPairInventory
    unresolved_pairs: ReachabilityPairInventory
    reduced_edge_digest: str
    replayable: bool
    eligible: bool
    reasons: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _valid_counts(self) -> "PpoSideReduction":
        if min(
            self.original_edge_count,
            self.reduced_edge_count,
            self.protected_edge_count,
        ) < 0:
            raise ValueError("PPO edge counts cannot be negative")
        if self.reduced_edge_count > self.original_edge_count:
            raise ValueError("reduced graph cannot contain more edges")
        if len(self.removed_edges) != (
            self.original_edge_count - self.reduced_edge_count
        ):
            raise ValueError("removed edge inventory does not match edge counts")
        if self.eligible and not self.replayable:
            raise ValueError("eligible reduction must be replayable")
        return self


class PpoReductionCertificate(StrictModel):
    """source/target PPO reduction 的 producer 输出。"""

    schema_version: str = "ppo-reduction-certificate-v1"
    window_id: str
    contract: PpoSemanticContract
    source_binding: PpoGraphBinding
    target_binding: PpoGraphBinding
    source: PpoSideReduction
    target: PpoSideReduction
    proof_digest: str
    reduction_eligible: bool
    diagnostic_only: bool = True

    @model_validator(mode="after")
    def _sides_match(self) -> "PpoReductionCertificate":
        if self.source.side is not PpoSide.SOURCE:
            raise ValueError("source reduction has the wrong side")
        if self.target.side is not PpoSide.TARGET:
            raise ValueError("target reduction has the wrong side")
        if self.source_binding.side is not PpoSide.SOURCE:
            raise ValueError("source binding has the wrong side")
        if self.target_binding.side is not PpoSide.TARGET:
            raise ValueError("target binding has the wrong side")
        if self.reduction_eligible and not (
            self.source.eligible and self.target.eligible
        ):
            raise ValueError("eligible certificate requires eligible source/target")
        return self


class PpoReductionReplay(StrictModel):
    """不依赖 producer 中间状态的独立 replay 结果。"""

    schema_version: str = "ppo-reduction-replay-v1"
    window_id: str
    certificate_digest_matches: bool
    source_replayable: bool
    target_replayable: bool
    source_equivalent: bool
    target_equivalent: bool
    accepted: bool
    reasons: tuple[str, ...] = ()


class PpoShadowComparison(StrictModel):
    """full/reduced encoding 的只读估计；不送入 checker。"""

    full: SymbolicEncodingStats
    reduced: SymbolicEncodingStats
    source_ppo_edge_delta: int
    target_ppo_edge_delta: int
    estimated_formula_term_delta: int
    used_for_verdict: bool = False


class PpoReductionWindowReport(StrictModel):
    schema_version: str = "ppo-reduction-window-v1"
    window_id: str
    event_count: int
    contract: PpoSemanticContract
    certificate: PpoReductionCertificate
    replay: PpoReductionReplay
    shadow: PpoShadowComparison


class TracePpoReductionReport(StrictModel):
    schema_version: str = "trace-ppo-reduction-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[PpoReductionWindowReport, ...] = ()
    reasons: tuple[str, ...] = ()


class TracePpoReductionCertificate(StrictModel):
    schema_version: str = "trace-ppo-reduction-certificate-v1"
    trace_id: str
    windows: tuple[PpoReductionCertificate, ...] = ()


class TracePpoReductionReplayReport(StrictModel):
    schema_version: str = "trace-ppo-reduction-replay-v1"
    trace_id: str
    trace_complete: bool
    analysis_reached_windows: bool
    windows: tuple[PpoReductionReplay, ...] = ()
    reasons: tuple[str, ...] = ()


__all__ = [
    "PpoSide",
    "SourcePpoSemantics",
    "TargetPpoSemantics",
    "ViolationCycleDependency",
    "PpoSemanticContract",
    "PpoGraphBinding",
    "RelevantReachabilityPair",
    "ReachabilityPairInventory",
    "RemovedPpoEdge",
    "PpoSideReduction",
    "PpoReductionCertificate",
    "PpoReductionReplay",
    "PpoShadowComparison",
    "PpoReductionWindowReport",
    "TracePpoReductionReport",
    "TracePpoReductionCertificate",
    "TracePpoReductionReplayReport",
]
