from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from bmo_check_dynamic.model import (
    CandidateCycleSummary,
    CycleHotspotSummary,
    CycleRelevanceClass,
    CycleRelevanceCount,
    CycleRelevanceReport,
    EventKind,
    ObligationCycleClassification,
    PPOCycleSummary,
    SliceObligation,
    SliceObligationKind,
    TraceEvent,
    TraceCycleRelevanceReport,
    ViolationCycleSemantics,
)
from bmo_check_dynamic.proof.relations import (
    source_preserved_order,
    target_preserved_order,
)

from .obligation_bottleneck import _from_read_relations, _load_groups, _read_parts
from .slice_contract import build_obligation_inventory
from .windows import AnalysisWindow, WindowInclusionReason


Edge = tuple[str, str]


@dataclass(frozen=True, slots=True)
class _Candidate:
    relation_id: str
    kind: str
    event_ids: tuple[str, str]
    owner_event_id: str
    # RF 的字节分段属于候选 identity；只保存事件对会把 mixed-width
    # 的不同 read-part 错当成同一个可选项。
    address: int | None = None
    size: int | None = None
    source_relevant: bool = False
    target_relevant: bool = False


@dataclass(frozen=True, slots=True)
class _PPOAnalysis:
    summary: PPOCycleSummary
    edges: frozenset[Edge]
    redundant_edges: frozenset[Edge]
    communication_relevant_edges: frozenset[Edge]
    cycle_relevant_edges: frozenset[Edge]


@dataclass(frozen=True, slots=True)
class _ClassifiedRelation:
    relation_id: str
    relation_kind: str
    event_ids: tuple[str, ...]
    classification: CycleRelevanceClass
    source_direct: bool
    target_direct: bool
    potentially_transitive_redundant: bool
    score: int
    reason: str


def characterize_cycle_relevance(
    window: AnalysisWindow,
    *,
    top_hotspots: int = 16,
    top_obligations: int = 128,
) -> CycleRelevanceReport:
    """表征当前坏环查询真正使用的关系，不改变 checker 输入。

    PPO 的冗余和候选环相关性都是诊断估计：完整 PPO、RF、FR、CO 仍然
    保留在本函数的输入关系中，也不会被传回 ``check_window``。
    """

    if top_hotspots < 1 or top_obligations < 1:
        raise ValueError("diagnostic limits must be positive")

    events = tuple(
        sorted(window.events, key=lambda event: (event.thread_id, event.sequence, event.event_id))
    )
    event_by_id = {event.event_id: event for event in events}
    event_ids = tuple(event.event_id for event in events)
    source_edges = frozenset(source_preserved_order(events))
    target_edges = frozenset(target_preserved_order(events))
    communication_ids = _communication_endpoint_ids(window)
    groups = tuple(
        sorted(
            _load_groups(events),
            key=lambda item: (-len(item[1]), item[0]),
        )[:top_hotspots]
    )
    hotspot_ids = tuple(
        (key, frozenset(event.event_id for event in values))
        for key, values in groups
    )

    # PPO 先独立分析；candidate graph 之后再决定哪些 direct edge 处在
    # 某个 source/target SCC 中。
    source_pre = _analyze_ppo(
        "source", source_edges, events, communication_ids, hotspot_ids, None
    )
    target_pre = _analyze_ppo(
        "target", target_edges, events, communication_ids, hotspot_ids, None
    )

    candidates = _candidate_relations(events)
    candidate_edges = frozenset(
        candidate.event_ids
        for candidate in candidates
        if candidate.kind != "rf" or event_by_id[candidate.event_ids[0]].thread_id
        != event_by_id[candidate.event_ids[1]].thread_id
    )
    source_components = _strongly_connected_components(
        event_ids, source_edges | candidate_edges
    )
    target_components = _strongly_connected_components(
        event_ids, target_edges | candidate_edges
    )
    candidates = tuple(
        _mark_candidate_relevance(candidate, source_components, target_components)
        for candidate in candidates
    )
    source = _analyze_ppo(
        "source",
        source_edges,
        events,
        communication_ids,
        hotspot_ids,
        source_components,
    )
    target = _analyze_ppo(
        "target",
        target_edges,
        events,
        communication_ids,
        hotspot_ids,
        target_components,
    )

    inventory = build_obligation_inventory(window)
    from_read_relations = _from_read_relations(events)
    classified = _classify_relations(
        inventory,
        from_read_relations,
        source.edges,
        target.edges,
        source.redundant_edges,
        target.redundant_edges,
    )
    counts = Counter(item.classification for item in classified)
    invalid_count = source.summary.invalid_edge_count + target.summary.invalid_edge_count
    if invalid_count:
        counts[CycleRelevanceClass.UNRESOLVED] += invalid_count

    source_only = source.edges - target.edges
    target_only = target.edges - source.edges
    shared = source.edges & target.edges
    rf = _candidate_summary("rf", candidates)
    fr = _candidate_summary("fr", candidates)
    coherence = _candidate_summary("coherence", candidates)
    hotspots = _hotspot_summaries(
        hotspot_ids,
        source,
        target,
        candidates,
    )
    full_relation_count = len(inventory) + len(from_read_relations)
    cycle_direct_count = counts[CycleRelevanceClass.DIRECT_CYCLE_EDGE]
    reachability_support_count = counts[CycleRelevanceClass.REACHABILITY_SUPPORT]
    candidate_domain_count = counts[CycleRelevanceClass.CANDIDATE_DOMAIN_ONLY]
    ordering_support_count = counts[CycleRelevanceClass.ORDERING_SUPPORT]
    unresolved_count = counts[CycleRelevanceClass.UNRESOLVED]
    classification_counts = tuple(
        CycleRelevanceCount(
            classification=classification,
            count=counts[classification],
        )
        for classification in CycleRelevanceClass
    )
    sampled = tuple(
        ObligationCycleClassification(
            relation_id=item.relation_id,
            relation_kind=item.relation_kind,
            event_ids=item.event_ids,
            classification=item.classification,
            source_direct=item.source_direct,
            target_direct=item.target_direct,
            potentially_transitive_redundant=item.potentially_transitive_redundant,
            reason=item.reason,
        )
        for item in sorted(
            classified,
            key=lambda item: (-item.score, item.relation_id),
        )[:top_obligations]
    )
    return CycleRelevanceReport(
        window_id=window.window_id,
        event_count=len(events),
        full_relation_count=full_relation_count,
        cycle_direct_relation_count=cycle_direct_count,
        reachability_support_count=reachability_support_count,
        candidate_domain_only_count=candidate_domain_count,
        ordering_support_count=ordering_support_count,
        unresolved_count=unresolved_count,
        semantics=_semantics(),
        classification_counts=classification_counts,
        source_ppo=source.summary,
        target_ppo=target.summary,
        source_only_ppo_edge_count=len(source_only),
        target_only_ppo_edge_count=len(target_only),
        shared_ppo_edge_count=len(shared),
        rf=rf,
        fr=fr,
        coherence=coherence,
        hotspots=hotspots,
        hotspots_truncated=len(_load_groups(events)) > top_hotspots,
        obligation_classifications=sampled,
        obligation_classifications_truncated=len(classified) > top_obligations,
        estimated_explicit_relation_reduction=(
            len(source.redundant_edges) + len(target.redundant_edges)
        ),
        estimated_explicit_relation_count_after_summary=max(
            0,
            full_relation_count
            - len(source.redundant_edges)
            - len(target.redundant_edges),
        ),
    )


def _semantics() -> ViolationCycleSemantics:
    return ViolationCycleSemantics(
        source_cycle_query=(
            "finite: find_cycle(source_ppo | communication_relations) != empty; "
            "symbolic: select a non-empty balanced source cycle"
        ),
        target_cycle_query=(
            "finite: find_cycle(target_ppo | communication_relations) == empty; "
            "symbolic: target_rank strictly increases over target_ppo and "
            "conditional relations"
        ),
        source_direct_relation_families=(
            "source_ppo",
            "cross_thread_rf",
            "coherence",
            "from_read",
        ),
        target_ordering_relation_families=(
            "target_ppo",
            "cross_thread_rf",
            "coherence",
            "from_read",
        ),
        conditional_relation_families=(
            "cross_thread_rf",
            "coherence",
            "from_read",
        ),
        finite_relation_builder="proof.checker._communication_relations",
        symbolic_relation_builder="proof.checker._check_symbolic.conditional_edges",
    )


def _candidate_relations(events: tuple[TraceEvent, ...]) -> tuple[_Candidate, ...]:
    memory = tuple(event for event in events if event.kind.is_memory)
    reads = tuple(event for event in memory if event.kind.is_read)
    writes = tuple(event for event in memory if event.kind.is_write)
    candidates: list[_Candidate] = []
    for read in reads:
        for part_index, (part_address, part_size) in enumerate(_read_parts(read, writes)):
            part_end = part_address + part_size
            part_candidates = tuple(
                write
                for write in writes
                if write.address <= part_address
                and write.end_address >= part_end
                and not (
                    write.thread_id == read.thread_id
                    and write.sequence >= read.sequence
                )
            )
            for candidate_index, write in enumerate(part_candidates):
                candidates.append(
                    _Candidate(
                        relation_id=(
                            f"rf:{read.event_id}:{part_index}:{candidate_index}:"
                            f"{write.event_id}:{part_address}:{part_size}"
                        ),
                        kind="rf",
                        event_ids=(write.event_id, read.event_id),
                        owner_event_id=read.event_id,
                        address=part_address,
                        size=part_size,
                    )
                )
    for relation in _from_read_relations(events):
        candidates.append(
            _Candidate(
                relation_id=relation.relation_id,
                kind="fr",
                event_ids=(relation.event_ids[0], relation.event_ids[1]),
                owner_event_id=relation.event_ids[0],
            )
        )
    for left in writes:
        for right in writes:
            if left.event_id == right.event_id or not left.overlaps(right):
                continue
            candidates.append(
                _Candidate(
                    relation_id=f"co:{left.event_id}:{right.event_id}",
                    kind="coherence",
                    event_ids=(left.event_id, right.event_id),
                    owner_event_id=left.event_id,
                )
            )
    return tuple(candidates)


def _mark_candidate_relevance(
    candidate: _Candidate,
    source_components: dict[str, int],
    target_components: dict[str, int],
) -> _Candidate:
    left, right = candidate.event_ids
    return _Candidate(
        relation_id=candidate.relation_id,
        kind=candidate.kind,
        event_ids=candidate.event_ids,
        owner_event_id=candidate.owner_event_id,
        address=candidate.address,
        size=candidate.size,
        source_relevant=(
            left != right
            and source_components.get(left) == source_components.get(right)
        ),
        target_relevant=(
            left != right
            and target_components.get(left) == target_components.get(right)
        ),
    )


def _candidate_summary(kind: str, candidates: tuple[_Candidate, ...]) -> CandidateCycleSummary:
    values = tuple(candidate for candidate in candidates if candidate.kind == kind)
    per_event = Counter(candidate.owner_event_id for candidate in values)
    source = sum(candidate.source_relevant for candidate in values)
    target = sum(candidate.target_relevant for candidate in values)
    either = sum(
        candidate.source_relevant or candidate.target_relevant for candidate in values
    )
    return CandidateCycleSummary(
        kind=kind,
        total_candidate_count=len(values),
        source_cycle_relevant_count=source,
        target_cycle_relevant_count=target,
        either_cycle_relevant_count=either,
        neither_cycle_relevant_count=len(values) - either,
        max_candidates_per_event=max(per_event.values(), default=0),
    )


def _classify_relations(
    inventory: tuple[SliceObligation, ...],
    from_read_relations: list[object],
    source_edges: frozenset[Edge],
    target_edges: frozenset[Edge],
    source_redundant: frozenset[Edge],
    target_redundant: frozenset[Edge],
) -> tuple[_ClassifiedRelation, ...]:
    values: list[_ClassifiedRelation] = []
    for obligation in inventory:
        values.append(
            _classify_inventory_relation(
                obligation,
                source_edges,
                target_edges,
                source_redundant,
                target_redundant,
            )
        )
    for relation in from_read_relations:
        event_ids = tuple(relation.event_ids)
        values.append(
            _ClassifiedRelation(
                relation_id=relation.relation_id,
                relation_kind="from_read",
                event_ids=event_ids,
                classification=CycleRelevanceClass.DIRECT_CYCLE_EDGE,
                source_direct=True,
                target_direct=True,
                potentially_transitive_redundant=False,
                score=2,
                reason="conditional from-read edge enters both cycle queries",
            )
        )
    return tuple(values)


def _classify_inventory_relation(
    obligation: SliceObligation,
    source_edges: frozenset[Edge],
    target_edges: frozenset[Edge],
    source_redundant: frozenset[Edge],
    target_redundant: frozenset[Edge],
) -> _ClassifiedRelation:
    edge = (
        obligation.event_ids[0],
        obligation.event_ids[1],
    ) if len(obligation.event_ids) == 2 else None
    source_direct = edge in source_edges if edge else False
    target_direct = edge in target_edges if edge else False
    if obligation.kind is SliceObligationKind.SOURCE_PPO:
        redundant = bool(edge and edge in source_redundant)
    elif obligation.kind is SliceObligationKind.TARGET_PPO:
        redundant = bool(edge and edge in target_redundant)
    else:
        redundant = False
    if obligation.kind in {
        SliceObligationKind.SOURCE_PPO,
        SliceObligationKind.TARGET_PPO,
    }:
        classification = (
            CycleRelevanceClass.REACHABILITY_SUPPORT
            if redundant
            else CycleRelevanceClass.DIRECT_CYCLE_EDGE
        )
        reason = (
            "PPO edge is explicit in the current cycle/ordering graph"
            + (
                "; an alternate PPO path also exists, so a reachability summary "
                "could represent this relation"
                if redundant
                else ""
            )
        )
        score = 4 if redundant else 3
    elif obligation.kind in {
        SliceObligationKind.READ_FROM_DOMAIN,
        SliceObligationKind.COHERENCE_DOMAIN,
    }:
        classification = CycleRelevanceClass.CANDIDATE_DOMAIN_ONLY
        reason = "domain constrains candidate RF/CO choices before cycle construction"
        score = len(obligation.event_ids)
    elif obligation.kind in {
        SliceObligationKind.EVENT_PRESENCE,
        SliceObligationKind.COMMUNICATION_EDGE,
        SliceObligationKind.BOUNDARY,
    }:
        classification = CycleRelevanceClass.ORDERING_SUPPORT
        reason = "retained event/window support; this record is not itself a cycle edge"
        score = 1
    else:
        classification = CycleRelevanceClass.UNRESOLVED
        reason = "relation kind is not described by the recovered cycle contract"
        score = 0
    return _ClassifiedRelation(
        relation_id=obligation.obligation_id,
        relation_kind=obligation.kind.value,
        event_ids=obligation.event_ids,
        classification=classification,
        source_direct=source_direct,
        target_direct=target_direct,
        potentially_transitive_redundant=redundant,
        score=score,
        reason=reason,
    )


def _analyze_ppo(
    side: str,
    edges: frozenset[Edge],
    events: tuple[TraceEvent, ...],
    communication_ids: set[str],
    hotspot_ids: tuple[tuple[tuple[int, int, int, EventKind], frozenset[str]], ...],
    cycle_components: dict[str, int] | None,
) -> _PPOAnalysis:
    event_by_id = {event.event_id: event for event in events}
    by_thread: dict[int, list[TraceEvent]] = defaultdict(list)
    for event in events:
        by_thread[event.thread_id].append(event)
    adjacency: dict[str, set[str]] = {event.event_id: set() for event in events}
    predecessors: dict[str, set[str]] = {event.event_id: set() for event in events}
    invalid: set[Edge] = set()
    for left, right in edges:
        first, second = event_by_id.get(left), event_by_id.get(right)
        if first is None or second is None or first.thread_id != second.thread_id:
            invalid.add((left, right))
            continue
        if (first.sequence, first.event_id) >= (second.sequence, second.event_id):
            invalid.add((left, right))
            continue
        adjacency[left].add(right)
        predecessors[right].add(left)
    reach: dict[str, int] = {}
    endpoint_index: dict[str, int] = {}
    endpoint_masks: dict[int, int] = {}
    ancestor_endpoint_masks: dict[str, int] = {}
    descendant_endpoint_masks: dict[str, int] = {}
    for thread_id, thread_events in by_thread.items():
        ordered = sorted(thread_events, key=lambda event: (event.sequence, event.event_id))
        local_index = {event.event_id: index for index, event in enumerate(ordered)}
        for index, event in enumerate(ordered):
            endpoint_index[event.event_id] = index
        bits = {
            event.event_id: 1 << index
            for index, event in enumerate(ordered)
            if event.event_id in communication_ids
        }
        endpoint_masks[thread_id] = 0
        for bit in bits.values():
            endpoint_masks[thread_id] |= bit
        for event in reversed(ordered):
            value = 0
            for neighbor in adjacency[event.event_id]:
                if event_by_id[neighbor].thread_id != thread_id:
                    continue
                value |= (1 << local_index[neighbor]) | reach.get(neighbor, 0)
            reach[event.event_id] = value
            descendant_endpoint_masks[event.event_id] = bits.get(event.event_id, 0)
            for neighbor in adjacency[event.event_id]:
                descendant_endpoint_masks[event.event_id] |= descendant_endpoint_masks.get(
                    neighbor, bits.get(neighbor, 0)
                )
        for event in ordered:
            value = bits.get(event.event_id, 0)
            for predecessor in predecessors[event.event_id]:
                if event_by_id[predecessor].thread_id == thread_id:
                    value |= ancestor_endpoint_masks.get(predecessor, 0)
            ancestor_endpoint_masks[event.event_id] = value

    redundant: set[Edge] = set()
    communication_relevant: set[Edge] = set()
    for left, right in edges - invalid:
        successors = adjacency[left]
        if any(
            next_node != right
            and (
                next_node == right
                or bool(reach.get(next_node, 0) & (1 << endpoint_index[right]))
            )
            for next_node in successors
        ):
            redundant.add((left, right))
        ancestors = ancestor_endpoint_masks.get(left, 0)
        descendants = descendant_endpoint_masks.get(right, 0)
        if _contains_distinct_bits(ancestors, descendants):
            communication_relevant.add((left, right))

    hotspot_incident = 0
    hotspot_redundant = 0
    hotspot_communication_relevant = 0
    for left, right in edges - invalid:
        if any(left in ids or right in ids for _, ids in hotspot_ids):
            hotspot_incident += 1
            if (left, right) in redundant:
                hotspot_redundant += 1
            if (left, right) in communication_relevant:
                hotspot_communication_relevant += 1
    cycle_relevant = frozenset(
        edge
        for edge in edges - invalid
        if cycle_components is not None
        and cycle_components.get(edge[0]) == cycle_components.get(edge[1])
    )
    closure_pairs = sum(value.bit_count() for value in reach.values())
    direct_count = len(edges)
    valid_count = len(edges - invalid)
    summary = PPOCycleSummary(
        side=side,
        direct_edge_count=direct_count,
        reachability_pair_count=closure_pairs,
        transitive_reduction_candidate_count=len(redundant),
        nonredundant_edge_count=valid_count - len(redundant),
        cycle_relevant_direct_edge_count=len(cycle_relevant),
        communication_relevant_edge_count=len(communication_relevant),
        internal_chain_edge_count=valid_count - len(communication_relevant),
        hotspot_incident_edge_count=hotspot_incident,
        hotspot_redundant_edge_count=hotspot_redundant,
        hotspot_communication_relevant_edge_count=hotspot_communication_relevant,
        invalid_edge_count=len(invalid),
    )
    return _PPOAnalysis(
        summary=summary,
        edges=edges,
        redundant_edges=frozenset(redundant),
        communication_relevant_edges=frozenset(communication_relevant),
        cycle_relevant_edges=cycle_relevant,
    )


def _hotspot_summaries(
    hotspot_ids: tuple[tuple[tuple[int, int, int, EventKind], frozenset[str]], ...],
    source: _PPOAnalysis,
    target: _PPOAnalysis,
    candidates: tuple[_Candidate, ...],
) -> tuple[CycleHotspotSummary, ...]:
    summaries: list[CycleHotspotSummary] = []
    for key, event_ids in hotspot_ids:
        source_edges = {
            edge for edge in source.edges if set(edge).intersection(event_ids)
        }
        target_edges = {
            edge for edge in target.edges if set(edge).intersection(event_ids)
        }
        rf = tuple(
            candidate
            for candidate in candidates
            if candidate.kind == "rf" and set(candidate.event_ids).intersection(event_ids)
        )
        fr = tuple(
            candidate
            for candidate in candidates
            if candidate.kind == "fr" and set(candidate.event_ids).intersection(event_ids)
        )
        summaries.append(
            CycleHotspotSummary(
                thread_id=key[0],
                address=key[1],
                size=key[2],
                kind=key[3].name,
                event_count=len(event_ids),
                source_ppo_edge_count=len(source_edges),
                source_ppo_redundant_count=len(source_edges & source.redundant_edges),
                source_ppo_communication_relevant_count=len(
                    source_edges & source.communication_relevant_edges
                ),
                target_ppo_edge_count=len(target_edges),
                target_ppo_redundant_count=len(target_edges & target.redundant_edges),
                target_ppo_communication_relevant_count=len(
                    target_edges & target.communication_relevant_edges
                ),
                rf_candidate_count=len(rf),
                rf_source_cycle_relevant_count=sum(item.source_relevant for item in rf),
                rf_target_cycle_relevant_count=sum(item.target_relevant for item in rf),
                fr_candidate_count=len(fr),
                fr_source_cycle_relevant_count=sum(item.source_relevant for item in fr),
                fr_target_cycle_relevant_count=sum(item.target_relevant for item in fr),
            )
        )
    return tuple(summaries)


def _strongly_connected_components(
    nodes: tuple[str, ...], edges: frozenset[Edge]
) -> dict[str, int]:
    """用显式栈计算 SCC，避免大窗口触发递归深度限制。"""

    adjacency: dict[str, tuple[str, ...]] = {node: () for node in nodes}
    reverse: dict[str, tuple[str, ...]] = {node: () for node in nodes}
    forward_sets: dict[str, set[str]] = {node: set() for node in nodes}
    reverse_sets: dict[str, set[str]] = {node: set() for node in nodes}
    for left, right in edges:
        if left not in forward_sets or right not in forward_sets:
            continue
        forward_sets[left].add(right)
        reverse_sets[right].add(left)
    adjacency = {node: tuple(sorted(values)) for node, values in forward_sets.items()}
    reverse = {node: tuple(sorted(values)) for node, values in reverse_sets.items()}
    visited: set[str] = set()
    order: list[str] = []
    for start in nodes:
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                order.append(node)
                continue
            stack.append((node, True))
            for neighbor in reversed(adjacency[node]):
                if neighbor not in visited:
                    visited.add(neighbor)
                    stack.append((neighbor, False))
    components: dict[str, int] = {}
    component_id = 0
    for start in reversed(order):
        if start in components:
            continue
        stack = [start]
        components[start] = component_id
        while stack:
            node = stack.pop()
            for neighbor in reverse[node]:
                if neighbor not in components:
                    components[neighbor] = component_id
                    stack.append(neighbor)
        component_id += 1
    return components


def _contains_distinct_bits(left: int, right: int) -> bool:
    if not left or not right:
        return False
    if left.bit_count() > 1 or right.bit_count() > 1:
        return True
    return left != right


def _communication_endpoint_ids(window: AnalysisWindow) -> set[str]:
    ids = {
        inclusion.event_id
        for inclusion in window.event_inclusions
        if WindowInclusionReason.COMMUNICATION_ENDPOINT in inclusion.reasons
    }
    return ids or {
        event_id
        for edge in window.communication_edges
        for event_id in (edge.first_event, edge.second_event)
    }


__all__ = ["characterize_cycle_relevance"]
