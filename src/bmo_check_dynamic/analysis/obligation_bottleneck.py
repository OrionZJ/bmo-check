from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256

from bmo_check_dynamic.model import (
    AddressObligationContribution,
    BottleneckEvent,
    BottleneckRelationKind,
    EventKind,
    ObligationBottleneckReport,
    ObligationComponentStats,
    ObligationHotspot,
    ObligationTypeStats,
    SliceObligation,
    SliceObligationKind,
    ThreadObligationContribution,
    TraceEvent,
)
from .slice_contract import build_obligation_inventory
from .windows import AnalysisWindow, WindowInclusionReason


@dataclass(frozen=True, slots=True)
class _Relation:
    relation_id: str
    kind: BottleneckRelationKind
    event_ids: tuple[str, ...]
    derived: bool


def characterize_obligation_bottleneck(
    window: AnalysisWindow,
    *,
    top_components: int = 32,
    top_hotspots: int = 16,
    top_events: int = 16,
    top_threads: int = 32,
    top_addresses: int = 32,
    top_articulations: int = 128,
) -> ObligationBottleneckReport:
    """统计 obligation 网络的构成和热点，不创建 solver 约束。

    inventory obligation 来自当前 checker 输入；from-read 是按现有 symbolic
    encoder 的 read-part/later-write 候选规则派生的诊断关系。两者都只进入
    报告，不会从 ``AnalysisWindow`` 删除事件，也不会影响 verdict。
    """

    if min(
        top_components,
        top_hotspots,
        top_events,
        top_threads,
        top_addresses,
        top_articulations,
    ) < 1:
        raise ValueError("diagnostic limits must be positive")

    events = tuple(
        sorted(window.events, key=lambda event: (event.thread_id, event.sequence, event.event_id))
    )
    event_by_id = {event.event_id: event for event in events}
    inventory = build_obligation_inventory(window)
    relations = [_inventory_relation(item, event_by_id) for item in inventory]
    derived_from_read = _from_read_relations(events)
    relations.extend(derived_from_read)

    parent = {event.event_id: event.event_id for event in events}

    def find(event_id: str) -> str:
        root = event_id
        while parent[root] != root:
            root = parent[root]
        while parent[event_id] != event_id:
            next_id = parent[event_id]
            parent[event_id] = root
            event_id = next_id
        return root

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    graph: dict[str, set[str]] = {event.event_id: set() for event in events}
    relation_roots: list[str] = []
    for relation in relations:
        ids = _unique_event_ids(relation.event_ids)
        if not ids:
            relation_roots.append("")
            continue
        anchor = ids[0]
        for event_id in ids[1:]:
            union(anchor, event_id)
            _add_graph_edge(graph, anchor, event_id)
        relation_roots.append(find(anchor))

    component_events: dict[str, list[str]] = defaultdict(list)
    for event in events:
        component_events[find(event.event_id)].append(event.event_id)
    component_relations: dict[str, list[_Relation]] = defaultdict(list)
    for relation, root in zip(relations, relation_roots, strict=True):
        if root:
            component_relations[find(root)].append(relation)

    root_component_ids = {
        root: _component_id(values)
        for root, values in component_events.items()
    }
    event_component_ids = {
        event_id: root_component_ids[find(event_id)]
        for event_id in event_by_id
    }
    largest_root = max(
        component_events,
        key=lambda root: (
            len(component_relations[root]),
            len(component_events[root]),
            root_component_ids[root],
        ),
        default=None,
    )
    largest_component_id = root_component_ids.get(largest_root) if largest_root else None

    rf_counts = _read_from_counts(events)
    fr_counts = _from_read_counts(derived_from_read)
    communication_endpoint_ids = _communication_endpoint_ids(window)
    communication_degree, cross_thread_communication_degree = _communication_degrees(
        relations, event_by_id
    )
    relation_degree = _relation_degrees(relations)
    source_degree = _pair_degrees(relations, BottleneckRelationKind.SOURCE_PPO)
    target_degree = _pair_degrees(relations, BottleneckRelationKind.TARGET_PPO)

    global_types = _type_stats(
        relations,
        event_component_ids=event_component_ids,
        largest_component_id=largest_component_id,
    )
    components = []
    all_articulations: set[str] = set()
    ordered_roots = sorted(
        component_events,
        key=lambda root: (
            -len(component_relations[root]),
            -len(component_events[root]),
            root_component_ids[root],
        ),
    )
    for root in ordered_roots:
        component_graph = {
            event_id: {
                neighbor
                for neighbor in graph[event_id]
                if neighbor in component_events[root]
            }
            for event_id in component_events[root]
        }
        articulation = _articulation_nodes(component_graph)
        all_articulations.update(articulation)
        component_relations_for_root = component_relations[root]
        edge_count = sum(
            1
            for left in component_graph
            for right in component_graph[left]
            if left < right
        )
        components.append(
            ObligationComponentStats(
                component_id=root_component_ids[root],
                event_count=len(component_events[root]),
                relation_count=len(component_relations_for_root),
                inventory_obligation_count=sum(
                    not relation.derived for relation in component_relations_for_root
                ),
                derived_relation_count=sum(
                    relation.derived for relation in component_relations_for_root
                ),
                graph_edge_count=edge_count,
                density=_density(len(component_events[root]), edge_count),
                articulation_node_count=len(articulation),
                relation_types=_type_stats(
                    component_relations_for_root,
                    event_component_ids=event_component_ids,
                    largest_component_id=root_component_ids[root],
                ),
            )
        )

    hotspots = _hotspots(
        window,
        event_by_id,
        event_component_ids,
        relation_degree,
        source_degree,
        target_degree,
        rf_counts,
        fr_counts,
        communication_endpoint_ids,
        communication_degree,
        cross_thread_communication_degree,
        relations,
        top_hotspots=top_hotspots,
        top_events=top_events,
    )
    thread_contributions = _thread_contributions(
        events,
        relations,
        event_by_id,
        top_threads=top_threads,
    )
    address_contributions = _address_contributions(
        events,
        relations,
        top_addresses=top_addresses,
    )

    largest_component = next(
        (component for component in components if component.component_id == largest_component_id),
        None,
    )
    articulation_ids = tuple(
        sorted(all_articulations, key=lambda event_id: (-relation_degree[event_id], event_id))
    )
    return ObligationBottleneckReport(
        window_id=window.window_id,
        event_count=len(events),
        memory_event_count=sum(event.kind.is_memory for event in events),
        inventory_obligation_count=len(inventory),
        derived_from_read_count=len(derived_from_read),
        relation_count=len(relations),
        rf_candidate_count=sum(rf_counts.values()),
        max_rf_candidates=max(rf_counts.values(), default=0),
        from_read_candidate_count=len(derived_from_read),
        component_count=len(component_events),
        largest_component_id=largest_component_id,
        largest_component_event_count=(largest_component.event_count if largest_component else 0),
        largest_component_relation_count=(largest_component.relation_count if largest_component else 0),
        largest_component_density=(largest_component.density if largest_component else 0.0),
        articulation_node_count=len(all_articulations),
        articulation_event_ids=articulation_ids[:top_articulations],
        articulation_nodes_truncated=len(articulation_ids) > top_articulations,
        relation_types=global_types,
        components=tuple(components[:top_components]),
        components_truncated=len(components) > top_components,
        hotspots=tuple(hotspots),
        hotspots_truncated=len(_load_groups(events)) > top_hotspots,
        thread_contributions=thread_contributions,
        address_contributions=address_contributions,
    )


def _inventory_relation(
    obligation: SliceObligation,
    event_by_id: dict[str, TraceEvent],
) -> _Relation:
    kind = obligation.kind
    if kind is SliceObligationKind.EVENT_PRESENCE:
        report_kind = BottleneckRelationKind.EVENT_PRESENCE
    elif kind is SliceObligationKind.COMMUNICATION_EDGE:
        report_kind = BottleneckRelationKind.COMMUNICATION
    elif kind is SliceObligationKind.SOURCE_PPO:
        report_kind = BottleneckRelationKind.SOURCE_PPO
    elif kind is SliceObligationKind.TARGET_PPO:
        report_kind = BottleneckRelationKind.TARGET_PPO
    elif kind is SliceObligationKind.READ_FROM_DOMAIN:
        report_kind = BottleneckRelationKind.READ_FROM_DOMAIN
    elif kind is SliceObligationKind.COHERENCE_DOMAIN:
        report_kind = BottleneckRelationKind.COHERENCE_DOMAIN
    else:
        event = event_by_id[obligation.event_ids[0]]
        if event.kind == EventKind.ATOMIC_RMW:
            report_kind = BottleneckRelationKind.ATOMIC_RMW
        elif event.kind == EventKind.FUTEX_WAIT:
            report_kind = BottleneckRelationKind.SYNC_BOUNDARY
        else:
            report_kind = BottleneckRelationKind.FENCE
    return _Relation(obligation.obligation_id, report_kind, obligation.event_ids, False)


def _from_read_relations(events: tuple[TraceEvent, ...]) -> list[_Relation]:
    reads = tuple(event for event in events if event.kind.is_read)
    writes = tuple(event for event in events if event.kind.is_write)
    relations: list[_Relation] = []
    for read in reads:
        for part_index, (part_address, part_size) in enumerate(
            _read_parts(read, writes)
        ):
            part_end = part_address + part_size
            for later in writes:
                if (
                    later.address >= part_end
                    or later.end_address <= part_address
                    or later.event_id == read.event_id
                ):
                    continue
                relation_id = (
                    f"fr:{read.event_id}:{part_index}:{later.event_id}:"
                    f"{part_address}:{part_size}"
                )
                relations.append(
                    _Relation(
                        relation_id,
                        BottleneckRelationKind.FROM_READ,
                        (read.event_id, later.event_id),
                        True,
                    )
                )
    return relations


def _read_parts(
    read: TraceEvent,
    writes: tuple[TraceEvent, ...],
) -> tuple[tuple[int, int], ...]:
    """与 symbolic encoder 相同的字节分段，只生成诊断数据。"""

    boundaries = {read.address, read.end_address}
    for write in writes:
        if not write.overlaps(read):
            continue
        boundaries.add(max(read.address, write.address))
        boundaries.add(min(read.end_address, write.end_address))
    ordered = sorted(boundaries)
    return tuple(
        (left, right - left)
        for left, right in zip(ordered, ordered[1:])
        if right > left
    )


def _read_from_counts(events: tuple[TraceEvent, ...]) -> dict[str, int]:
    reads = tuple(event for event in events if event.kind.is_read)
    writes = tuple(event for event in events if event.kind.is_write)
    return {
        read.event_id: sum(
            _covers(write, read)
            and not (
                write.thread_id == read.thread_id
                and write.sequence >= read.sequence
            )
            for write in writes
        )
        for read in reads
    }


def _from_read_counts(relations: list[_Relation]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for relation in relations:
        if relation.kind is BottleneckRelationKind.FROM_READ:
            counts[relation.event_ids[0]] += 1
    return dict(counts)


def _covers(write: TraceEvent, read: TraceEvent) -> bool:
    return write.address <= read.address and write.end_address >= read.end_address


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


def _communication_degrees(
    relations: list[_Relation],
    event_by_id: dict[str, TraceEvent],
) -> tuple[dict[str, int], dict[str, int]]:
    degree: Counter[str] = Counter()
    cross_thread: Counter[str] = Counter()
    for relation in relations:
        if relation.kind is not BottleneckRelationKind.COMMUNICATION:
            continue
        ids = _unique_event_ids(relation.event_ids)
        for event_id in ids:
            degree[event_id] += 1
        if len(ids) == 2 and event_by_id[ids[0]].thread_id != event_by_id[ids[1]].thread_id:
            for event_id in ids:
                cross_thread[event_id] += 1
    return dict(degree), dict(cross_thread)


def _relation_degrees(relations: list[_Relation]) -> dict[str, int]:
    degree: Counter[str] = Counter()
    for relation in relations:
        for event_id in set(relation.event_ids):
            degree[event_id] += 1
    return dict(degree)


def _pair_degrees(
    relations: list[_Relation],
    kind: BottleneckRelationKind,
) -> dict[str, int]:
    degree: Counter[str] = Counter()
    for relation in relations:
        if relation.kind is kind:
            for event_id in set(relation.event_ids):
                degree[event_id] += 1
    return dict(degree)


def _type_stats(
    relations: list[_Relation],
    *,
    event_component_ids: dict[str, str],
    largest_component_id: str | None,
) -> tuple[ObligationTypeStats, ...]:
    by_kind: dict[BottleneckRelationKind, list[_Relation]] = defaultdict(list)
    for relation in relations:
        by_kind[relation.kind].append(relation)
    result = []
    for kind in BottleneckRelationKind:
        values = by_kind.get(kind, [])
        touched_components = {
            _event_component_id(event_component_ids, relation.event_ids)
            for relation in values
            if relation.event_ids
        }
        inventory_count = sum(not relation.derived for relation in values)
        derived_count = sum(relation.derived for relation in values)
        result.append(
            ObligationTypeStats(
                kind=kind,
                inventory_count=inventory_count,
                derived_count=derived_count,
                total_count=len(values),
                event_incidence_count=sum(
                    len(set(relation.event_ids)) for relation in values
                ),
                component_count=len(touched_components),
                largest_component_count=sum(
                    1
                    for relation in values
                    if largest_component_id is not None
                    and _event_component_id(event_component_ids, relation.event_ids)
                    == largest_component_id
                ),
            )
        )
    return tuple(result)


def _event_component_id(
    event_component_ids: dict[str, str], event_ids: tuple[str, ...]
) -> str:
    values = {
        event_component_ids[event_id]
        for event_id in event_ids
        if event_id in event_component_ids
    }
    return next(iter(values), "") if len(values) == 1 else ""


def _hotspots(
    window: AnalysisWindow,
    event_by_id: dict[str, TraceEvent],
    component_ids: dict[str, str],
    relation_degree: dict[str, int],
    source_degree: dict[str, int],
    target_degree: dict[str, int],
    rf_counts: dict[str, int],
    fr_counts: dict[str, int],
    communication_endpoint_ids: set[str],
    communication_degree: dict[str, int],
    cross_thread_communication_degree: dict[str, int],
    relations: list[_Relation],
    *,
    top_hotspots: int,
    top_events: int,
) -> list[ObligationHotspot]:
    relation_by_kind = {
        kind: tuple(relation for relation in relations if relation.kind is kind)
        for kind in (
            BottleneckRelationKind.SOURCE_PPO,
            BottleneckRelationKind.TARGET_PPO,
            BottleneckRelationKind.COMMUNICATION,
        )
    }
    result: list[ObligationHotspot] = []
    for group_index, values in enumerate(
        sorted(_load_groups(tuple(event_by_id.values())), key=lambda group: (-len(group[1]), group[0]))[
            :top_hotspots
        ]
    ):
        key, group_values = values
        group_ids = {event.event_id for event in group_values}
        group_relations = [
            relation for relation in relations if group_ids.intersection(relation.event_ids)
        ]
        internal_source, external_source = _pair_group_counts(
            relation_by_kind[BottleneckRelationKind.SOURCE_PPO], group_ids
        )
        internal_target, external_target = _pair_group_counts(
            relation_by_kind[BottleneckRelationKind.TARGET_PPO], group_ids
        )
        cross_thread = sum(
            1
            for relation in relation_by_kind[BottleneckRelationKind.COMMUNICATION]
            if group_ids.intersection(relation.event_ids)
            and len({event_by_id[event_id].thread_id for event_id in relation.event_ids}) > 1
        )
        components = {component_ids[event.event_id] for event in group_values}
        component_id = next(iter(components), "") if len(components) == 1 else "multiple"
        hotspot_events = tuple(
            _bottleneck_event(
                event,
                component_ids,
                relation_degree,
                source_degree,
                target_degree,
                rf_counts,
                fr_counts,
                communication_degree,
                cross_thread_communication_degree,
            )
            for event in sorted(
                group_values,
                key=lambda event: (
                    -relation_degree.get(event.event_id, 0),
                    -fr_counts.get(event.event_id, 0),
                    -rf_counts.get(event.event_id, 0),
                    event.event_id,
                ),
            )[:top_events]
        )
        result.append(
            ObligationHotspot(
                hotspot_id=f"hotspot-{group_index:04d}-" + sha256(
                    f"{key[0]}|{key[1]}|{key[2]}|{key[3].name}".encode()
                ).hexdigest()[:16],
                thread_id=key[0],
                address=key[1],
                size=key[2],
                kind=key[3].name,
                event_count=len(group_values),
                communication_endpoint_count=sum(
                    event.event_id in communication_endpoint_ids for event in group_values
                ),
                component_id=component_id,
                source_ppo_internal_count=internal_source,
                source_ppo_external_count=external_source,
                target_ppo_internal_count=internal_target,
                target_ppo_external_count=external_target,
                rf_candidate_total=sum(rf_counts.get(event.event_id, 0) for event in group_values),
                rf_candidate_max=max(
                    (rf_counts.get(event.event_id, 0) for event in group_values),
                    default=0,
                ),
                from_read_exposure_total=sum(
                    fr_counts.get(event.event_id, 0) for event in group_values
                ),
                from_read_exposure_max=max(
                    (fr_counts.get(event.event_id, 0) for event in group_values),
                    default=0,
                ),
                cross_thread_communication_count=cross_thread,
                relation_incidence_count=sum(
                    len(set(relation.event_ids).intersection(group_ids))
                    for relation in group_relations
                ),
                relation_types=_type_stats(
                    group_relations,
                    event_component_ids=component_ids,
                    largest_component_id=None,
                ),
                top_events=hotspot_events,
            )
        )
    return result


def _load_groups(
    events: tuple[TraceEvent, ...],
) -> list[tuple[tuple[int, int, int, EventKind], list[TraceEvent]]]:
    groups: dict[tuple[int, int, int, EventKind], list[TraceEvent]] = defaultdict(list)
    for event in events:
        if event.kind is EventKind.LOAD and event.size > 0:
            groups[(event.thread_id, event.address, event.size, event.kind)].append(event)
    return [
        (key, sorted(values, key=lambda event: (event.sequence, event.event_id)))
        for key, values in groups.items()
        if len(values) >= 2
    ]


def _pair_group_counts(relations: tuple[_Relation, ...], group_ids: set[str]) -> tuple[int, int]:
    internal = external = 0
    for relation in relations:
        ids = set(relation.event_ids)
        if not ids.intersection(group_ids):
            continue
        if ids <= group_ids:
            internal += 1
        else:
            external += 1
    return internal, external


def _bottleneck_event(
    event: TraceEvent,
    component_ids: dict[str, str],
    relation_degree: dict[str, int],
    source_degree: dict[str, int],
    target_degree: dict[str, int],
    rf_counts: dict[str, int],
    fr_counts: dict[str, int],
    communication_degree: dict[str, int],
    cross_thread_communication_degree: dict[str, int],
) -> BottleneckEvent:
    return BottleneckEvent(
        event_id=event.event_id,
        thread_id=event.thread_id,
        sequence=event.sequence,
        address=event.address,
        size=event.size,
        kind=event.kind.name,
        component_id=component_ids.get(event.event_id, ""),
        obligation_degree=relation_degree.get(event.event_id, 0),
        source_ppo_degree=source_degree.get(event.event_id, 0),
        target_ppo_degree=target_degree.get(event.event_id, 0),
        rf_candidate_count=rf_counts.get(event.event_id, 0),
        from_read_exposure_count=fr_counts.get(event.event_id, 0),
        communication_degree=communication_degree.get(event.event_id, 0),
        cross_thread_communication_degree=cross_thread_communication_degree.get(
            event.event_id, 0
        ),
    )


def _thread_contributions(
    events: tuple[TraceEvent, ...],
    relations: list[_Relation],
    event_by_id: dict[str, TraceEvent],
    *,
    top_threads: int,
) -> tuple[ThreadObligationContribution, ...]:
    by_thread: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for event in events:
        by_thread[event.thread_id]["event_count"] += 1
    for relation in relations:
        ids = _unique_event_ids(relation.event_ids)
        touched = {
            event_by_id[event_id].thread_id
            for event_id in ids
            if event_id in event_by_id
        }
        for thread_id in touched:
            by_thread[thread_id]["relation_incidence_count"] += sum(
                event_by_id[event_id].thread_id == thread_id
                for event_id in ids
                if event_id in event_by_id
            )
        if relation.kind is BottleneckRelationKind.SOURCE_PPO:
            for thread_id in touched:
                by_thread[thread_id]["source_ppo_count"] += 1
        elif relation.kind is BottleneckRelationKind.TARGET_PPO:
            for thread_id in touched:
                by_thread[thread_id]["target_ppo_count"] += 1
        elif relation.kind is BottleneckRelationKind.COMMUNICATION:
            for thread_id in touched:
                by_thread[thread_id]["communication_count"] += 1
        elif relation.kind is BottleneckRelationKind.READ_FROM_DOMAIN:
            if relation.event_ids:
                event = event_by_id.get(relation.event_ids[0])
                if event is not None:
                    by_thread[event.thread_id]["read_from_domain_count"] += 1
        elif relation.kind is BottleneckRelationKind.FROM_READ and relation.event_ids:
            event = event_by_id.get(relation.event_ids[0])
            if event is not None:
                by_thread[event.thread_id]["from_read_exposure_count"] += 1
    ordered = sorted(
        by_thread.items(),
        key=lambda item: (-item[1]["relation_incidence_count"], item[0]),
    )[:top_threads]
    return tuple(
        ThreadObligationContribution(
            thread_id=thread_id,
            event_count=values["event_count"],
            relation_incidence_count=values["relation_incidence_count"],
            source_ppo_count=values["source_ppo_count"],
            target_ppo_count=values["target_ppo_count"],
            communication_count=values["communication_count"],
            read_from_domain_count=values["read_from_domain_count"],
            from_read_exposure_count=values["from_read_exposure_count"],
        )
        for thread_id, values in ordered
    )


def _address_contributions(
    events: tuple[TraceEvent, ...],
    relations: list[_Relation],
    *,
    top_addresses: int,
) -> tuple[AddressObligationContribution, ...]:
    by_address: dict[tuple[int, int], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    event_by_id = {event.event_id: event for event in events}
    for event in events:
        if event.kind.is_memory and event.size > 0:
            values = by_address[(event.address, event.size)]
            values["event_count"] += 1
            values["load_count"] += event.kind == EventKind.LOAD
            values["store_count"] += event.kind == EventKind.STORE
    for relation in relations:
        touched_keys = {
            (event_by_id[event_id].address, event_by_id[event_id].size)
            for event_id in set(relation.event_ids)
            if event_id in event_by_id and event_by_id[event_id].kind.is_memory
        }
        for key in touched_keys:
            values = by_address[key]
            values["relation_incidence_count"] += sum(
                event_by_id[event_id].address == key[0]
                and event_by_id[event_id].size == key[1]
                for event_id in set(relation.event_ids)
                if event_id in event_by_id
            )
            if relation.kind is BottleneckRelationKind.COMMUNICATION:
                values["communication"] += 1
            elif relation.kind is BottleneckRelationKind.SOURCE_PPO:
                values["source"] += 1
            elif relation.kind is BottleneckRelationKind.TARGET_PPO:
                values["target"] += 1
            elif relation.kind is BottleneckRelationKind.READ_FROM_DOMAIN:
                values["read_from"] += 1
            elif relation.kind is BottleneckRelationKind.FROM_READ:
                values["fr"] += 1
    ordered = sorted(
        by_address.items(),
        key=lambda item: (-item[1]["relation_incidence_count"], -item[1]["event_count"], item[0]),
    )[:top_addresses]
    return tuple(
        AddressObligationContribution(
            address=key[0],
            size=key[1],
            event_count=values["event_count"],
            load_count=values["load_count"],
            store_count=values["store_count"],
            relation_incidence_count=values["relation_incidence_count"],
            communication_count=values["communication"],
            source_ppo_count=values["source"],
            target_ppo_count=values["target"],
            read_from_domain_count=values["read_from"],
            from_read_exposure_count=values["fr"],
        )
        for key, values in ordered
    )


def _unique_event_ids(event_ids: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(event_ids))


def _add_graph_edge(graph: dict[str, set[str]], left: str, right: str) -> None:
    if left == right or left not in graph or right not in graph:
        return
    graph[left].add(right)
    graph[right].add(left)


def _component_id(event_ids: list[str]) -> str:
    material = "|".join(sorted(event_ids))
    return "component-" + sha256(material.encode()).hexdigest()[:20]


def _density(event_count: int, edge_count: int) -> float:
    if event_count < 2:
        return 0.0
    return (2.0 * edge_count) / (event_count * (event_count - 1))


def _articulation_nodes(graph: dict[str, set[str]]) -> set[str]:
    """返回星形展开图中的割点，不依赖 Python 递归深度。

    SB 的窗口可能包含数千个事件；递归 DFS 在长链上会触发默认递归深度，
    把一个本来可完成的诊断变成工具异常。显式栈只改变遍历实现，不改变
    Tarjan 割点判定。
    """

    discovery: dict[str, int] = {}
    low: dict[str, int] = {}
    parent: dict[str, str | None] = {}
    children: Counter[str] = Counter()
    articulation: set[str] = set()
    clock = 0

    for root in sorted(graph):
        if root in discovery:
            continue
        clock += 1
        discovery[root] = low[root] = clock
        parent[root] = None
        stack: list[tuple[str, object]] = [(root, iter(sorted(graph[root])))]
        while stack:
            node, neighbors = stack[-1]
            try:
                neighbor = next(neighbors)  # type: ignore[arg-type]
            except StopIteration:
                stack.pop()
                predecessor = parent[node]
                if predecessor is None:
                    if children[node] > 1:
                        articulation.add(node)
                else:
                    low[predecessor] = min(low[predecessor], low[node])
                    if (
                        parent[predecessor] is not None
                        and low[node] >= discovery[predecessor]
                    ):
                        articulation.add(predecessor)
                continue
            if neighbor not in discovery:
                parent[neighbor] = node
                children[node] += 1
                clock += 1
                discovery[neighbor] = low[neighbor] = clock
                stack.append((neighbor, iter(sorted(graph[neighbor]))))
            elif neighbor != parent[node]:
                low[node] = min(low[node], discovery[neighbor])
    return articulation


__all__ = ["characterize_obligation_bottleneck"]
