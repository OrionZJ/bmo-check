from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

import networkx as nx

from bmo_check_dynamic.model import (
    PpoGraphBinding,
    PpoReductionCertificate,
    PpoReductionReplay,
    PpoReductionWindowReport,
    PpoSemanticContract,
    PpoShadowComparison,
    PpoSide,
    PpoSideReduction,
    ReachabilityPairInventory,
    RelevantReachabilityPair,
    RemovedPpoEdge,
    SymbolicEncodingStats,
    TraceEvent,
    ViolationCycleDependency,
)

from .cycle_relevance import _candidate_relations
from .windows import AnalysisWindow
from bmo_check_dynamic.proof.relations import (
    Edge,
    source_preserved_order,
    target_preserved_order,
)


_SAMPLE_LIMIT = 64


@dataclass(frozen=True, slots=True)
class PpoGraphInput:
    """replay 所需的原始图和独立相关端点。"""

    window_id: str
    events: tuple[TraceEvent, ...]
    source_edges: frozenset[Edge]
    target_edges: frozenset[Edge]
    source_protected_edges: frozenset[Edge]
    target_protected_edges: frozenset[Edge]
    relevant_endpoints: frozenset[str]
    endpoint_reasons: tuple[tuple[str, tuple[str, ...]], ...]

    @property
    def endpoint_reason_map(self) -> dict[str, tuple[str, ...]]:
        return dict(self.endpoint_reasons)


@dataclass(frozen=True, slots=True)
class _Reachability:
    masks: dict[str, int]
    ordered_by_thread: dict[int, tuple[str, ...]]
    endpoint_masks: dict[int, int]
    invalid_edges: tuple[Edge, ...]


@dataclass(frozen=True, slots=True)
class _SideBuild:
    side: PpoSide
    original_edges: frozenset[Edge]
    reduced_edges: frozenset[Edge]
    protected_edges: frozenset[Edge]
    removed: tuple[RemovedPpoEdge, ...]
    reduction: PpoSideReduction


def ppo_semantic_contract() -> PpoSemanticContract:
    """返回当前 checker 使用的固定 PPO 语义契约。"""

    dependency = ViolationCycleDependency()
    payload = {
        "schema_version": "ppo-semantic-contract-v1",
        "source": {
            "consumers": ["source_conditions", "selected_source_cycle"],
            "direct_edges_are_unconditional": True,
            "cycle_depends_on_reachability": True,
            "direct_edge_identity_is_semantic": False,
        },
        "target": {
            "consumers": ["target_rank_constraints"],
            "direct_edges_are_unconditional": True,
            "acyclicity_depends_on_reachability": True,
            "direct_edge_identity_is_semantic": False,
        },
        "violation": dependency.model_dump(mode="json"),
        "protected_edge_families": [
            "fence_boundary",
            "atomic_rmw_boundary",
            "futex_boundary",
        ],
        "reachability_equivalence_is_sufficient": True,
    }
    digest = _digest_json(payload)
    return PpoSemanticContract(contract_digest=digest)


def build_ppo_graph_input(window: AnalysisWindow) -> PpoGraphInput:
    """从同一窗口构造 source/target 图，未修改窗口事件。"""

    events = tuple(
        sorted(window.events, key=lambda event: (event.thread_id, event.sequence, event.event_id))
    )
    source = frozenset(source_preserved_order(events))
    target = frozenset(target_preserved_order(events))
    event_by_id = {event.event_id: event for event in events}
    reasons: dict[str, set[str]] = defaultdict(set)

    for edge in window.communication_edges:
        reasons[edge.first_event].add("communication")
        reasons[edge.second_event].add("communication")
    for candidate in _candidate_relations(events):
        reasons[candidate.event_ids[0]].add(candidate.kind)
        reasons[candidate.event_ids[1]].add(candidate.kind)
    for event in events:
        if event.kind.is_boundary:
            reasons[event.event_id].add(
                "atomic_rmw" if event.kind.name == "ATOMIC_RMW" else "fence"
            )

    relevant_endpoints = frozenset(reasons)
    # Fence/RMW/FUTEX 节点本身进入 relevant endpoint 集合；不把所有邻接边
    # 粗暴标成不可删。真正需要保留的是这些端点之间的可达关系，replay 会
    # 重新计算它们。否则一个 RMW 周围的全量 PPO 边会直接掩盖 P8 的问题。
    source_protected = frozenset()
    target_protected = frozenset()
    return PpoGraphInput(
        window_id=window.window_id,
        events=events,
        source_edges=source,
        target_edges=target,
        source_protected_edges=source_protected,
        target_protected_edges=target_protected,
        relevant_endpoints=relevant_endpoints,
        endpoint_reasons=tuple(
            sorted((event_id, tuple(sorted(values))) for event_id, values in reasons.items())
        ),
    )


def build_ppo_reduction(
    window: AnalysisWindow,
) -> PpoReductionWindowReport:
    """生成 reduction certificate，并立即用独立 replay 验证它。"""

    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    source = _side_from_certificate(certificate.source, graph.source_edges)
    target = _side_from_certificate(certificate.target, graph.target_edges)
    contract = certificate.contract
    from bmo_check_dynamic.proof.checker import characterize_symbolic_encoding

    full_stats = characterize_symbolic_encoding(window)
    reduced_stats = characterize_symbolic_encoding(
        window,
        source_ppo=set(source.reduced_edges),
        target_ppo=set(target.reduced_edges),
    )
    shadow = PpoShadowComparison(
        full=full_stats,
        reduced=reduced_stats,
        source_ppo_edge_delta=(
            full_stats.source_ppo_edge_count - reduced_stats.source_ppo_edge_count
        ),
        target_ppo_edge_delta=(
            full_stats.target_ppo_edge_count - reduced_stats.target_ppo_edge_count
        ),
        estimated_formula_term_delta=(
            full_stats.estimated_formula_terms - reduced_stats.estimated_formula_terms
        ),
    )
    return PpoReductionWindowReport(
        window_id=window.window_id,
        event_count=len(graph.events),
        contract=contract,
        certificate=certificate,
        replay=replay,
        shadow=shadow,
    )


def build_ppo_reduction_certificate(
    graph: PpoGraphInput,
) -> tuple[PpoReductionCertificate, PpoReductionReplay]:
    """为给定原始 source/target 图生成并独立重放 certificate。"""

    contract = ppo_semantic_contract()
    source = _build_side(
        PpoSide.SOURCE,
        graph.source_edges,
        graph.source_protected_edges,
        graph,
    )
    target = _build_side(
        PpoSide.TARGET,
        graph.target_edges,
        graph.target_protected_edges,
        graph,
    )
    certificate = PpoReductionCertificate(
        window_id=graph.window_id,
        contract=contract,
        source_binding=_binding(
            PpoSide.SOURCE,
            graph,
            graph.source_edges,
            graph.source_protected_edges,
        ),
        target_binding=_binding(
            PpoSide.TARGET,
            graph,
            graph.target_edges,
            graph.target_protected_edges,
        ),
        source=source.reduction,
        target=target.reduction,
        proof_digest="",
        reduction_eligible=source.reduction.eligible and target.reduction.eligible,
    )
    certificate = certificate.model_copy(
        update={"proof_digest": _certificate_digest(certificate)}
    )
    replay = replay_ppo_reduction(graph, certificate)
    if replay.accepted != certificate.reduction_eligible:
        certificate = certificate.model_copy(
            update={"reduction_eligible": replay.accepted}
        )
        certificate = certificate.model_copy(
            update={"proof_digest": _certificate_digest(certificate)}
        )
        replay = replay_ppo_reduction(graph, certificate)
    return certificate, replay


def _side_from_certificate(
    reduction: PpoSideReduction,
    original: frozenset[Edge],
) -> _SideBuild:
    removed = tuple(reduction.removed_edges)
    reduced = frozenset(original - {(item.source_event, item.target_event) for item in removed})
    return _SideBuild(
        reduction.side,
        original,
        reduced,
        frozenset(),
        removed,
        reduction,
    )


def replay_ppo_reduction(
    graph: PpoGraphInput,
    certificate: PpoReductionCertificate,
) -> PpoReductionReplay:
    """独立重建图、digest、路径和相关 reachability 集合。"""

    reasons: list[str] = []
    certificate_digest_matches = _certificate_digest(certificate) == certificate.proof_digest
    if not certificate_digest_matches:
        reasons.append("certificate proof_digest does not match its contents")
    expected_contract = ppo_semantic_contract()
    if certificate.contract.contract_digest != expected_contract.contract_digest:
        reasons.append("PPO semantic contract digest is not current")
    if certificate.window_id != graph.window_id:
        reasons.append("certificate window_id does not match original graph")

    source_ok, source_equivalent, source_reasons = _replay_side(
        PpoSide.SOURCE,
        graph.source_edges,
        graph.source_protected_edges,
        graph,
        certificate.source_binding,
        certificate.source,
    )
    target_ok, target_equivalent, target_reasons = _replay_side(
        PpoSide.TARGET,
        graph.target_edges,
        graph.target_protected_edges,
        graph,
        certificate.target_binding,
        certificate.target,
    )
    reasons.extend(source_reasons)
    reasons.extend(target_reasons)
    computed_accept = (
        certificate_digest_matches
        and not reasons
        and source_ok
        and target_ok
        and source_equivalent
        and target_equivalent
    )
    if certificate.reduction_eligible != computed_accept:
        reasons.append("certificate reduction_eligible flag does not match replay")
    return PpoReductionReplay(
        window_id=graph.window_id,
        certificate_digest_matches=certificate_digest_matches,
        source_replayable=source_ok,
        target_replayable=target_ok,
        source_equivalent=source_equivalent,
        target_equivalent=target_equivalent,
        accepted=computed_accept and not reasons,
        reasons=tuple(reasons),
    )


def _build_side(
    side: PpoSide,
    original: frozenset[Edge],
    protected: frozenset[Edge],
    graph: PpoGraphInput,
) -> _SideBuild:
    reasons: list[str] = []
    invalid = tuple(
        sorted(
            edge
            for edge in original
            if edge[0] not in {event.event_id for event in graph.events}
            or edge[1] not in {event.event_id for event in graph.events}
        )
    )
    if invalid:
        reasons.append("original PPO graph contains unknown event ids")
    try:
        network = nx.DiGraph()
        network.add_nodes_from(event.event_id for event in graph.events)
        network.add_edges_from(original)
        reduced_base = nx.transitive_reduction(network)
        reduced = set(reduced_base.edges) | set(protected)
    except (nx.NetworkXUnfeasible, nx.NetworkXError) as error:
        reasons.append(f"PPO graph is not a finite DAG: {error}")
        reduced = set(original)

    reduced &= set(original)
    removed_candidates = set(original) - reduced
    removed, reduced, witness_reasons = _finalize_witnesses(
        original,
        reduced,
        removed_candidates,
        graph,
    )
    reasons.extend(witness_reasons)
    required, preserved, missing, extra, unresolved = _reachability_inventories(
        original,
        reduced,
        graph,
    )
    eligible = not reasons and not unresolved.pair_count and not missing.pair_count and not extra.pair_count
    reduction = PpoSideReduction(
        side=side,
        original_edge_count=len(original),
        reduced_edge_count=len(reduced),
        protected_edge_count=len(protected),
        removed_edges=removed,
        required_reachability_pairs=required,
        preserved_pairs=preserved,
        missing_pairs=missing,
        extra_pairs=extra,
        unresolved_pairs=unresolved,
        reduced_edge_digest=_digest_edges(reduced),
        replayable=eligible,
        eligible=eligible,
        reasons=tuple(reasons),
    )
    return _SideBuild(side, original, frozenset(reduced), protected, removed, reduction)


def _finalize_witnesses(
    original: frozenset[Edge],
    reduced: set[Edge],
    removed_candidates: set[Edge],
    graph: PpoGraphInput,
) -> tuple[tuple[RemovedPpoEdge, ...], set[Edge], list[str]]:
    reasons: list[str] = []
    removed = set(removed_candidates)
    event_by_id = {event.event_id: event for event in graph.events}
    # A witness must survive after all removals, not only at the moment an edge
    # was considered. Restore any edge whose final graph lost its path.
    changed = True
    while changed:
        changed = False
        reach = _reachability(frozenset(reduced), graph)
        adjacency = _adjacency(reduced)
        for edge in sorted(tuple(removed)):
            path = _path_from_reach(
                edge[0], edge[1], reach, adjacency, event_by_id
            )
            if path is None:
                reduced.add(edge)
                removed.remove(edge)
                changed = True
    witnesses: list[RemovedPpoEdge] = []
    reach = _reachability(frozenset(reduced), graph)
    adjacency = _adjacency(reduced)
    for left, right in sorted(removed):
        path = _path_from_reach(left, right, reach, adjacency, event_by_id)
        if path is None:
            reduced.add((left, right))
            removed.remove((left, right))
            reasons.append(f"could not construct final witness for {left}->{right}")
            continue
        # 大窗口不把十万条长路径同时复制进模型；每条 edge 仍绑定完整
        # path 的 digest/长度，replay 会按同一确定策略重新构造并核对。
        inline = len(removed_candidates) <= 1024
        witnesses.append(
            RemovedPpoEdge(
                source_event=left,
                target_event=right,
                witness_path=path if inline else (),
                witness_path_digest=_digest_path(path),
                witness_path_length=len(path),
            )
        )
    if len(witnesses) != len(original) - len(reduced):
        reasons.append("removed edge and witness inventories disagree")
    return tuple(witnesses), reduced, reasons


def _replay_side(
    side: PpoSide,
    original: frozenset[Edge],
    protected: frozenset[Edge],
    graph: PpoGraphInput,
    binding: PpoGraphBinding,
    reduction: PpoSideReduction,
) -> tuple[bool, bool, list[str]]:
    reasons: list[str] = []
    expected_binding = _binding(side, graph, original, protected)
    if binding != expected_binding:
        reasons.append(f"{side.value} original graph binding mismatch")
    if reduction.side is not side:
        reasons.append(f"{side.value} reduction side mismatch")
    if reduction.original_edge_count != len(original):
        reasons.append(f"{side.value} original edge count mismatch")
    if reduction.protected_edge_count != len(protected):
        reasons.append(f"{side.value} protected edge count mismatch")
    if not set(protected) <= set(original):
        reasons.append(f"{side.value} protected edge inventory is not a subset")
    removed = {(item.source_event, item.target_event): item for item in reduction.removed_edges}
    if len(removed) != len(reduction.removed_edges):
        reasons.append(f"{side.value} removed edge inventory has duplicates")
    if not set(removed) <= set(original):
        reasons.append(f"{side.value} certificate removes a non-original edge")
    if set(removed) & set(protected):
        reasons.append(f"{side.value} certificate removes a protected boundary edge")
    reduced = set(original) - set(removed)
    if len(reduced) != reduction.reduced_edge_count:
        reasons.append(f"{side.value} reduced edge count mismatch")
    if _digest_edges(reduced) != reduction.reduced_edge_digest:
        reasons.append(f"{side.value} reduced edge digest mismatch")
    reduced_reach = _reachability(frozenset(reduced), graph)
    reduced_adjacency = _adjacency(reduced)
    event_by_id = {event.event_id: event for event in graph.events}
    for item in reduction.removed_edges:
        path = item.witness_path or _replay_witness_path(
            item.source_event,
            item.target_event,
            reduced_reach,
            reduced_adjacency,
            event_by_id,
        )
        if path is None or not _path_is_in_graph(path, reduced):
            reasons.append(
                f"{side.value} witness path is not present for "
                f"{item.source_event}->{item.target_event}"
            )
        elif item.witness_path_length not in {0, len(path)}:
            reasons.append(
                f"{side.value} witness path length mismatch for "
                f"{item.source_event}->{item.target_event}"
            )
        elif item.witness_path_digest and item.witness_path_digest != _digest_path(path):
            reasons.append(
                f"{side.value} witness path digest mismatch for "
                f"{item.source_event}->{item.target_event}"
            )
    required, preserved, missing, extra, unresolved = _reachability_inventories(
        original,
        frozenset(reduced),
        graph,
    )
    if required != reduction.required_reachability_pairs:
        reasons.append(f"{side.value} required reachability inventory mismatch")
    if preserved != reduction.preserved_pairs:
        reasons.append(f"{side.value} preserved reachability inventory mismatch")
    if missing != reduction.missing_pairs:
        reasons.append(f"{side.value} missing reachability inventory mismatch")
    if extra != reduction.extra_pairs:
        reasons.append(f"{side.value} extra reachability inventory mismatch")
    if unresolved != reduction.unresolved_pairs:
        reasons.append(f"{side.value} unresolved reachability inventory mismatch")
    replayable = not reasons and not unresolved.pair_count
    equivalent = replayable and not missing.pair_count and not extra.pair_count
    if reduction.replayable != replayable:
        reasons.append(f"{side.value} replayable flag mismatch")
    if reduction.eligible != equivalent:
        reasons.append(f"{side.value} eligible flag mismatch")
    replayable = not reasons and not unresolved.pair_count
    equivalent = replayable and not missing.pair_count and not extra.pair_count
    return replayable, equivalent, reasons


def _reachability_inventories(
    original: frozenset[Edge],
    reduced: frozenset[Edge],
    graph: PpoGraphInput,
) -> tuple[
    ReachabilityPairInventory,
    ReachabilityPairInventory,
    ReachabilityPairInventory,
    ReachabilityPairInventory,
    ReachabilityPairInventory,
]:
    full = _reachability(original, graph)
    reduced_reach = _reachability(reduced, graph)
    endpoint_reasons = graph.endpoint_reason_map
    required = _inventory(full, full, graph, endpoint_reasons, "required")
    preserved = _inventory(full, reduced_reach, graph, endpoint_reasons, "preserved")
    missing = _inventory(full, reduced_reach, graph, endpoint_reasons, "missing")
    extra = _inventory(reduced_reach, full, graph, endpoint_reasons, "extra")
    unresolved_pairs = _empty_inventory()
    invalid = full.invalid_edges + reduced_reach.invalid_edges
    if invalid:
        unresolved_pairs = ReachabilityPairInventory(
            pair_count=len(invalid),
            pair_digest=_digest_edges(invalid),
            sample=tuple(
                RelevantReachabilityPair(
                    source_event=left,
                    target_event=right,
                    reasons=("invalid_ppo_edge",),
                )
                for left, right in sorted(invalid)[:_SAMPLE_LIMIT]
            ),
            sample_limit=_SAMPLE_LIMIT,
        )
    return required, preserved, missing, extra, unresolved_pairs


def _reachability(edges: frozenset[Edge], graph: PpoGraphInput) -> _Reachability:
    event_by_id = {event.event_id: event for event in graph.events}
    by_thread: dict[int, list[str]] = defaultdict(list)
    for event in graph.events:
        by_thread[event.thread_id].append(event.event_id)
    ordered_by_thread = {
        thread_id: tuple(
            sorted(
                values,
                key=lambda event_id: (
                    event_by_id[event_id].sequence,
                    event_id,
                ),
            )
        )
        for thread_id, values in by_thread.items()
    }
    local_index = {
        event_id: index
        for values in ordered_by_thread.values()
        for index, event_id in enumerate(values)
    }
    adjacency: dict[str, set[str]] = {event.event_id: set() for event in graph.events}
    invalid: list[Edge] = []
    for left, right in edges:
        first, second = event_by_id.get(left), event_by_id.get(right)
        if first is None or second is None or first.thread_id != second.thread_id:
            invalid.append((left, right))
            continue
        if (first.sequence, first.event_id) >= (second.sequence, second.event_id):
            invalid.append((left, right))
            continue
        adjacency[left].add(right)
    masks: dict[str, int] = {}
    for thread_id, values in ordered_by_thread.items():
        for event_id in reversed(values):
            mask = 0
            for neighbor in adjacency[event_id]:
                mask |= 1 << local_index[neighbor]
                mask |= masks.get(neighbor, 0)
            masks[event_id] = mask
    endpoint_ids = graph.relevant_endpoints
    endpoint_masks = {
        thread_id: sum(
            1 << index
            for index, event_id in enumerate(values)
            if event_id in endpoint_ids
        )
        for thread_id, values in ordered_by_thread.items()
    }
    return _Reachability(
        masks=masks,
        ordered_by_thread=ordered_by_thread,
        endpoint_masks=endpoint_masks,
        invalid_edges=tuple(sorted(set(invalid))),
    )


def _inventory(
    left: _Reachability,
    right: _Reachability,
    graph: PpoGraphInput,
    endpoint_reasons: dict[str, tuple[str, ...]],
    mode: str,
) -> ReachabilityPairInventory:
    digest = hashlib.sha256()
    count = 0
    sample: list[RelevantReachabilityPair] = []
    for thread_id in sorted(left.ordered_by_thread):
        values = left.ordered_by_thread[thread_id]
        right_values = right.ordered_by_thread.get(thread_id, ())
        if values != right_values:
            continue
        endpoint_mask = left.endpoint_masks.get(thread_id, 0)
        for index, source in enumerate(values):
            if not (endpoint_mask & (1 << index)):
                continue
            left_mask = left.masks.get(source, 0)
            right_mask = right.masks.get(source, 0)
            if mode == "required":
                mask = left_mask & endpoint_mask
            elif mode == "preserved":
                mask = left_mask & right_mask & endpoint_mask
            elif mode == "missing":
                mask = left_mask & ~right_mask & endpoint_mask
            elif mode == "extra":
                mask = right_mask & ~left_mask & endpoint_mask
            else:
                raise ValueError(f"unknown reachability inventory mode: {mode}")
            while mask:
                bit = mask & -mask
                target_index = bit.bit_length() - 1
                target = values[target_index]
                digest.update(f"{source}\0{target}\n".encode("utf-8"))
                count += 1
                if len(sample) < _SAMPLE_LIMIT:
                    sample.append(
                        RelevantReachabilityPair(
                            source_event=source,
                            target_event=target,
                            reasons=tuple(
                                sorted(
                                    set(endpoint_reasons.get(source, ()))
                                    | set(endpoint_reasons.get(target, ()))
                                )
                            ),
                        )
                    )
                mask ^= bit
    return ReachabilityPairInventory(
        pair_count=count,
        pair_digest=digest.hexdigest(),
        sample=tuple(sample),
        sample_limit=_SAMPLE_LIMIT,
    )


def _binding(
    side: PpoSide,
    graph: PpoGraphInput,
    edges: frozenset[Edge],
    protected: frozenset[Edge],
) -> PpoGraphBinding:
    return PpoGraphBinding(
        side=side,
        node_count=len(graph.events),
        edge_count=len(edges),
        node_digest=_digest_strings(event.event_id for event in graph.events),
        edge_digest=_digest_edges(edges),
        protected_edge_digest=_digest_edges(protected),
        relevant_endpoint_digest=_digest_endpoint_facts(graph),
    )


def _digest_endpoint_facts(graph: PpoGraphInput) -> str:
    return _digest_strings(
        f"{event_id}|{','.join(reasons)}"
        for event_id, reasons in graph.endpoint_reasons
    )


def _digest_strings(values: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _digest_edges(edges: Iterable[Edge]) -> str:
    return _digest_strings(f"{left}\0{right}" for left, right in sorted(edges))


def _digest_path(path: tuple[str, ...]) -> str:
    return _digest_strings(path)


def _digest_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _certificate_digest(certificate: PpoReductionCertificate) -> str:
    payload = certificate.model_dump(mode="json", exclude={"proof_digest"})
    return _digest_json(payload)


def ppo_certificate_digest(certificate: PpoReductionCertificate) -> str:
    """公开证书 digest 计算，供独立 fixture 构造篡改证书。"""

    return _certificate_digest(certificate)


def _empty_inventory() -> ReachabilityPairInventory:
    return ReachabilityPairInventory(pair_count=0, pair_digest=hashlib.sha256(b"").hexdigest())


def _path_is_in_graph(path: tuple[str, ...], edges: set[Edge]) -> bool:
    return all((left, right) in edges for left, right in zip(path, path[1:]))


def _adjacency(edges: frozenset[Edge] | set[Edge]) -> dict[str, tuple[str, ...]]:
    values: dict[str, list[str]] = defaultdict(list)
    for left, right in edges:
        values[left].append(right)
    return {left: tuple(sorted(rights)) for left, rights in values.items()}


def _path_from_reach(
    source: str,
    target: str,
    reach: _Reachability,
    adjacency: dict[str, tuple[str, ...]],
    event_by_id: dict[str, TraceEvent],
) -> tuple[str, ...] | None:
    first, last = event_by_id.get(source), event_by_id.get(target)
    if first is None or last is None or first.thread_id != last.thread_id:
        return None
    ordered = reach.ordered_by_thread.get(first.thread_id, ())
    local_index = {event_id: index for index, event_id in enumerate(ordered)}
    target_index = local_index.get(target)
    if target_index is None or not (reach.masks.get(source, 0) & (1 << target_index)):
        return None
    path = [source]
    current = source
    seen = {source}
    while current != target:
        next_node = None
        for neighbor in adjacency.get(current, ()):
            if neighbor == target:
                next_node = neighbor
                break
            neighbor_index = local_index.get(neighbor)
            if (
                neighbor_index is not None
                and reach.masks.get(neighbor, 0) & (1 << target_index)
            ):
                next_node = neighbor
                break
        if next_node is None or next_node in seen:
            return None
        path.append(next_node)
        seen.add(next_node)
        current = next_node
    return tuple(path)


def _replay_witness_path(
    source: str,
    target: str,
    reach: _Reachability,
    adjacency: dict[str, tuple[str, ...]],
    event_by_id: dict[str, TraceEvent],
) -> tuple[str, ...] | None:
    """replay 的独立路径构造；不调用 producer 的 witness 中间结果。"""

    first, last = event_by_id.get(source), event_by_id.get(target)
    if first is None or last is None or first.thread_id != last.thread_id:
        return None
    ordered = reach.ordered_by_thread.get(first.thread_id, ())
    local_index = {event_id: index for index, event_id in enumerate(ordered)}
    target_index = local_index.get(target)
    if target_index is None:
        return None
    path = [source]
    current = source
    seen = {source}
    if not (reach.masks.get(source, 0) & (1 << target_index)):
        return None
    while current != target:
        next_node = None
        for neighbor in adjacency.get(current, ()):
            if neighbor == target:
                next_node = neighbor
                break
            neighbor_index = local_index.get(neighbor)
            if (
                neighbor_index is not None
                and reach.masks.get(neighbor, 0) & (1 << target_index)
            ):
                next_node = neighbor
                break
        if next_node is None or next_node in seen:
            return None
        path.append(next_node)
        seen.add(next_node)
        current = next_node
    return tuple(path)


def _find_path(
    edges: set[Edge],
    source: str,
    target: str,
    graph: PpoGraphInput,
) -> tuple[str, ...] | None:
    if source == target:
        return (source,)
    adjacency: dict[str, list[str]] = defaultdict(list)
    for left, right in edges:
        adjacency[left].append(right)
    event_by_id = {event.event_id: event for event in graph.events}
    for values in adjacency.values():
        values.sort(key=lambda event_id: (event_by_id.get(event_id).sequence if event_id in event_by_id else 0, event_id))
    queue = [source]
    predecessor: dict[str, str | None] = {source: None}
    for node in queue:
        for neighbor in adjacency.get(node, ()):
            if neighbor in predecessor:
                continue
            predecessor[neighbor] = node
            if neighbor == target:
                path: list[str] = [target]
                while predecessor[path[-1]] is not None:
                    path.append(predecessor[path[-1]])  # type: ignore[arg-type]
                path.reverse()
                return tuple(path)
            queue.append(neighbor)
    return None


__all__ = [
    "PpoGraphInput",
    "build_ppo_graph_input",
    "build_ppo_reduction",
    "build_ppo_reduction_certificate",
    "replay_ppo_reduction",
    "ppo_certificate_digest",
    "ppo_semantic_contract",
]
