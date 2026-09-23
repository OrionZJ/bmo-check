from __future__ import annotations

from bmo_check_dynamic.analysis import (
    AnalysisWindow,
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
    characterize_graph_first_window,
    replay_candidate_cycle,
)
from bmo_check_dynamic.analysis.cycle_relevance import _candidate_relations
from bmo_check_dynamic.analysis.graph_first import (
    _LabeledEdge,
    _build_candidate_graph,
    _build_candidate_violation_cycle,
    _build_local_obligations,
    _build_local_witness,
    _candidate_query_events,
    _required_local_source_edges,
)
from bmo_check_dynamic.model import (
    CandidateViolationCycle,
    CandidateViolationEdge,
    CandidateReplayFailureKind,
    EventKind,
    GraphFirstQueryStatus,
    LocalCycleObligationSet,
    LocalCycleWitness,
    TraceEvent,
)
from bmo_check_dynamic.proof import run_symbolic_shadow


def _lb_window() -> AnalysisWindow:
    # 两个线程各自先读后写；cross-thread RF 与 source PPO 可以组成候选环。
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x2000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x2000, 4),
    )
    return AnalysisWindow("graph-first-fixture", events, ())


def test_graph_first_is_bounded_and_diagnostic_only() -> None:
    report = characterize_graph_first_window(
        _lb_window(),
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        execute_local_solver=False,
    )

    assert report.diagnostic_only is True
    assert report.reduction_replay_accepted is True
    assert report.cycles_returned >= 1
    assert report.candidates[0].diagnostic_only is True
    assert report.candidates[0].includes_non_ppo is True
    assert report.candidates[0].local_query is not None
    assert report.candidates[0].local_query.status is GraphFirstQueryStatus.NOT_RUN
    assert report.may_graph is not None
    assert report.may_graph.contract.over_approximate is True
    assert report.may_graph.graph_complete_for_observed_candidates is True
    assert report.search_ledger is not None
    assert report.search_ledger.search_truncated is True
    assert report.search_ledger.not_run_count == 1
    assert report.candidates[0].candidate_violation_cycle is not None
    assert any(
        edge.relation_type == "ppo_reachability"
        for edge in report.candidates[0].candidate_violation_cycle.ordered_edges
    )
    assert report.candidates[0].local_obligations is not None
    assert report.candidates[0].local_obligations.rf_exclusivity_preserved is True


def test_graph_first_local_query_never_becomes_a_verdict() -> None:
    report = characterize_graph_first_window(
        _lb_window(),
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )

    query = report.candidates[0].local_query
    assert query is not None
    assert query.diagnostic_only is True
    assert query.status in {
        GraphFirstQueryStatus.SAT_CANDIDATE,
        GraphFirstQueryStatus.UNSAT_LOCAL,
        GraphFirstQueryStatus.UNKNOWN_LOCAL,
    }
    assert report.candidates[0].replay is not None
    # A local witness can validate its candidate structure, but it cannot be
    # reported as an accepted complete model or an execution counterexample.
    assert report.candidates[0].replay.status.value == "structure_validated"
    assert not hasattr(report, "verdict")


def test_replay_does_not_accept_unbound_rf_obligations_after_model_check() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted

    forged_obligations = item.local_obligations.model_copy(
        update={
            "selected_rf_relation_ids": (
                *item.local_obligations.selected_rf_relation_ids,
                "rf:absent-write:read:0x2000:4",
            )
        }
    )
    result = replay_candidate_cycle(
        graph,
        certificate,
        item.candidate_violation_cycle,
        forged_obligations,
        item.local_witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=window.events,
    )

    assert result.status.value == "rejected"
    assert any(
        failure.predicate == "candidate-domain-membership"
        for failure in result.failures
    )


def test_replay_does_not_accept_candidate_declaration_mismatch() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted

    forged_candidate = item.candidate_violation_cycle.model_copy(
        update={
            "rf_dependencies": (
                *item.candidate_violation_cycle.rf_dependencies,
                "rf:absent-write:read:0x2000:4",
            )
        }
    )
    result = replay_candidate_cycle(
        graph,
        certificate,
        forged_candidate,
        item.local_obligations,
        item.local_witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=window.events,
    )

    assert result.status.value == "rejected"
    assert result.failures


def test_replay_rejects_cycle_nodes_not_matching_ordered_edges() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted

    forged_candidate = item.candidate_violation_cycle.model_copy(
        update={"cycle_nodes": ("forged-node", "forged-node")}
    )
    result = replay_candidate_cycle(
        graph,
        certificate,
        forged_candidate,
        item.local_obligations,
        item.local_witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=window.events,
    )

    assert result.status.value == "rejected"
    assert any(
        failure.predicate == "candidate-edge-cycle-identity"
        for failure in result.failures
    )


def test_replay_accepts_ppo_witness_intermediates_outside_cycle_skeleton() -> None:
    # The candidate stores the endpoints of a summarized PPO edge in cycle_nodes.
    # Its reachability witness can still pass through other events in the window.
    window = AnalysisWindow(
        "ppo-witness-intermediate-fixture",
        (
            TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x1000, 4),
            TraceEvent(1, 2, 0, 0x11, EventKind.LOAD, 0x3000, 4),
            TraceEvent(1, 3, 0, 0x12, EventKind.STORE, 0x2000, 4),
            TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x2000, 4),
            TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x1000, 4),
        ),
        (),
    )
    report = characterize_graph_first_window(
        window,
        max_cycle_length=8,
        max_cycles=20,
        max_search_states=1_000,
        local_timeout_ms=1_000,
        local_max_symbolic_terms=20_000,
        execute_local_solver=True,
        capture_model=True,
    )

    candidates = [
        item
        for item in report.candidates
        if item.candidate_violation_cycle is not None
        and any(
            edge.relation_type == "ppo_reachability"
            and len(edge.ppo_reachability_path) > 2
            for edge in item.candidate_violation_cycle.ordered_edges
        )
    ]
    assert candidates, "fixture must produce a PPO witness with an interior event"
    assert any(
        item.replay is not None and item.replay.status.value != "rejected"
        for item in candidates
    ), [item.replay for item in candidates]


def test_replay_rejects_ppo_dependency_summary_not_matching_edges() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted

    forged_candidate = item.candidate_violation_cycle.model_copy(
        update={"ppo_reachability_dependencies": (("forged", "path"),)}
    )
    result = replay_candidate_cycle(
        graph,
        certificate,
        forged_candidate,
        item.local_obligations,
        item.local_witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=window.events,
    )

    assert result.status.value == "rejected"
    assert any(
        failure.predicate == "candidate-ppo-inventory"
        for failure in result.failures
    )


def test_structure_replay_rejects_unlabeled_coherence_candidate_edges() -> None:
    events = (
        TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
        TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x2000, 4),
        TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x1000, 4),
    )
    window = AnalysisWindow("unlabeled-co", events, ())
    graph = build_ppo_graph_input(window)
    certificate, certificate_replay = build_ppo_reduction_certificate(graph)
    assert certificate_replay.accepted

    candidate = CandidateViolationCycle(
        cycle_id="unlabeled-co-cycle",
        cycle_nodes=(
            events[0].event_id,
            events[1].event_id,
            events[2].event_id,
            events[3].event_id,
            events[0].event_id,
        ),
        ordered_edges=(
            CandidateViolationEdge(
                source_event=events[0].event_id,
                target_event=events[1].event_id,
                relation_type="ppo_reachability",
                side="source",
                conditional=False,
                ppo_reachability_path=(events[0].event_id, events[1].event_id),
            ),
            CandidateViolationEdge(
                source_event=events[1].event_id,
                target_event=events[2].event_id,
                relation_type="coherence",
                side="source",
                conditional=True,
                # Adversary removed the concrete CO identity from both fields.
                relation_ids=(),
                co_dependency_ids=(),
            ),
            CandidateViolationEdge(
                source_event=events[2].event_id,
                target_event=events[3].event_id,
                relation_type="ppo_reachability",
                side="source",
                conditional=False,
                ppo_reachability_path=(events[2].event_id, events[3].event_id),
            ),
            CandidateViolationEdge(
                source_event=events[3].event_id,
                target_event=events[0].event_id,
                relation_type="coherence",
                side="source",
                conditional=True,
                relation_ids=(),
                co_dependency_ids=(),
            ),
        ),
        # The declarations were weakened together, so the old endpoint-only
        # replay could see a cycle without checking the two CO propositions.
        co_dependencies=(),
        ppo_reachability_dependencies=(
            (events[0].event_id, events[1].event_id),
            (events[2].event_id, events[3].event_id),
        ),
    )
    witness = LocalCycleWitness(
        cycle_id=candidate.cycle_id,
        co_assignments=(
            (events[1].event_id, events[2].event_id),
            (events[3].event_id, events[0].event_id),
        ),
    )
    obligations = LocalCycleObligationSet(
        cycle_id=candidate.cycle_id,
        selected_rf_relation_ids=(),
        rf_candidate_domain_ids=(),
        required_co_relation_ids=(),
        ppo_witness_paths=candidate.ppo_reachability_dependencies,
        rf_exclusivity_preserved=True,
    )

    result = replay_candidate_cycle(
        graph,
        certificate,
        candidate,
        obligations,
        witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=events,
    )

    assert result.status.value == "rejected"
    assert any(
        failure.predicate == "candidate-edge-relation-identity"
        for failure in result.failures
    )


def test_replay_does_not_accept_unbound_fr_obligation_after_model_check() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted

    forged_obligations = item.local_obligations.model_copy(
        update={
            "required_fr_relation_ids": (
                *item.local_obligations.required_fr_relation_ids,
                "fr:absent-read:0:absent-write:0x1000:4",
            )
        }
    )
    result = replay_candidate_cycle(
        graph,
        certificate,
        item.candidate_violation_cycle,
        forged_obligations,
        item.local_witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=window.events,
    )

    assert result.status.value == "rejected"
    assert any(
        failure.predicate == "fr-relation-inventory"
        for failure in result.failures
    )


def test_replay_does_not_accept_unbound_co_obligation_after_model_check() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted

    forged_obligations = item.local_obligations.model_copy(
        update={"required_co_relation_ids": ("co:absent-write:other-write",)}
    )
    result = replay_candidate_cycle(
        graph,
        certificate,
        item.candidate_violation_cycle,
        forged_obligations,
        item.local_witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=window.events,
    )

    assert result.status.value == "rejected"
    assert any(
        failure.predicate == "co-obligation-inventory"
        for failure in result.failures
    )


def test_required_local_edge_projection_exposes_lost_relation_identity() -> None:
    wide_store = TraceEvent(1, 1, 0, 0x40, EventKind.STORE, 0x4000, 8)
    partial_store = TraceEvent(2, 1, 0, 0x41, EventKind.STORE, 0x4000, 4)
    wide_read = TraceEvent(3, 1, 0, 0x42, EventKind.LOAD, 0x4000, 8)
    relations = _candidate_relations((wide_store, partial_store, wide_read))
    same_endpoint_rf = tuple(
        relation
        for relation in relations
        if relation.kind == "rf"
        and relation.event_ids == (wide_store.event_id, wide_read.event_id)
    )
    assert len(same_endpoint_rf) == 2
    assert same_endpoint_rf[0].relation_id != same_endpoint_rf[1].relation_id

    selected_relation = same_endpoint_rf[0]
    graph_edge = _LabeledEdge(
        source=selected_relation.event_ids[0],
        target=selected_relation.event_ids[1],
        kind="rf",
        relation_id=selected_relation.relation_id,
        relation_ids=(selected_relation.relation_id,),
    )
    required = _required_local_source_edges((graph_edge,))

    # Endpoint-only requirements let the encoder satisfy this edge using the
    # other byte-part RF relation with the same writer and reader.
    assert (
        selected_relation.event_ids[0],
        selected_relation.event_ids[1],
        "rf",
        (selected_relation.relation_id,),
    ) in required.relation_groups


def test_candidate_query_keeps_all_byte_sources_and_replays_initial_read() -> None:
    base = 0x5000
    wide_write = TraceEvent(1, 1, 0, 0x50, EventKind.STORE, base, 8)
    cycle_read = TraceEvent(2, 1, 0, 0x51, EventKind.LOAD, base, 4)
    disjoint_write = TraceEvent(2, 2, 0, 0x52, EventKind.STORE, base + 4, 4)
    low_write = TraceEvent(3, 1, 0, 0x53, EventKind.STORE, base, 4)
    wide_read = TraceEvent(4, 1, 0, 0x54, EventKind.LOAD, base, 8)
    initial_read = TraceEvent(5, 1, 0, 0x55, EventKind.LOAD, 0x9000, 4)
    events = (
        wide_write,
        cycle_read,
        disjoint_write,
        low_write,
        wide_read,
        initial_read,
    )
    window = AnalysisWindow("p16-mixed-byte-rf", events, ())

    relations = _candidate_relations(events)
    cycle_rf = next(
        item
        for item in relations
        if item.kind == "rf"
        and item.event_ids == (wide_write.event_id, cycle_read.event_id)
    )
    wide_read_relations = tuple(
        item
        for item in relations
        if item.kind == "rf" and item.owner_event_id == wide_read.event_id
    )
    low_fragment = next(
        item
        for item in wide_read_relations
        if item.event_ids[0] == low_write.event_id and item.address == base
    )
    high_fragment = next(
        item
        for item in wide_read_relations
        if item.event_ids[0] == disjoint_write.event_id
        and item.address == base + 4
    )
    same_endpoint_wide_relations = tuple(
        item
        for item in wide_read_relations
        if item.event_ids[0] == wide_write.event_id
    )
    assert len(same_endpoint_wide_relations) == 2
    assert len({item.relation_id for item in same_endpoint_wide_relations}) == 2
    coherence_id = f"co:{disjoint_write.event_id}:{wide_write.event_id}"
    cycle_edges = (
        _LabeledEdge(
            wide_write.event_id,
            cycle_read.event_id,
            "rf",
            cycle_rf.relation_id,
            (cycle_rf.relation_id,),
        ),
        _LabeledEdge(
            cycle_read.event_id,
            disjoint_write.event_id,
            "source_ppo",
            f"ppo:{cycle_read.event_id}->{disjoint_write.event_id}",
            witness_path=(cycle_read.event_id, disjoint_write.event_id),
        ),
        _LabeledEdge(
            disjoint_write.event_id,
            wide_write.event_id,
            "coherence",
            coherence_id,
            (coherence_id,),
        ),
    )

    wide_read_label = next(
        item
        for item in wide_read_relations
        if item.event_ids[0] == low_write.event_id and item.address == base
    )
    query_edges = cycle_edges + (
        _LabeledEdge(
            low_write.event_id,
            wide_read.event_id,
            "rf",
            wide_read_label.relation_id,
            (wide_read_label.relation_id,),
        ),
    )
    local_events = _candidate_query_events(events, query_edges)
    local_relations = _candidate_relations(local_events)
    assert {event.event_id for event in local_events} == {
        event.event_id for event in events if event.event_id != initial_read.event_id
    }
    assert {
        item.relation_id
        for item in local_relations
        if item.kind == "rf" and item.owner_event_id == wide_read.event_id
    } == {
        item.relation_id
        for item in wide_read_relations
    }

    graph = build_ppo_graph_input(window)
    assert (cycle_read.event_id, disjoint_write.event_id) in graph.source_edges
    assert (cycle_read.event_id, disjoint_write.event_id) not in graph.target_edges
    certificate, certificate_replay = build_ppo_reduction_certificate(graph)
    assert certificate_replay.accepted
    source_reduced = set(graph.source_edges) - {
        (item.source_event, item.target_event)
        for item in certificate.source.removed_edges
    }
    target_reduced = set(graph.target_edges) - {
        (item.source_event, item.target_event)
        for item in certificate.target.removed_edges
    }
    required = _required_local_source_edges(cycle_edges)
    relation_groups = (
        *required.relation_groups,
        (low_write.event_id, wide_read.event_id, "rf", (low_fragment.relation_id,)),
        (
            disjoint_write.event_id,
            wide_read.event_id,
            "rf",
            (high_fragment.relation_id,),
        ),
    )
    result, observation = run_symbolic_shadow(
        window,
        source_ppo=source_reduced,
        target_ppo=target_reduced,
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=20_000,
        execute_solver=True,
        required_source_cycle_edges=required.endpoints,
        required_source_cycle_relations=relation_groups,
        capture_model=True,
    )
    assert observation.result == "sat"
    assert result.witness is not None
    assignments = {
        (item.read_event, item.write_event, item.address, item.size)
        for item in result.witness.read_from
    }
    assert (wide_read.event_id, low_write.event_id, base, 4) in assignments
    assert (wide_read.event_id, disjoint_write.event_id, base + 4, 4) in assignments
    assert (initial_read.event_id, None, 0x9000, 4) in assignments

    candidate = CandidateViolationCycle(
        cycle_id="mixed-byte-cycle",
        cycle_nodes=(
            wide_write.event_id,
            cycle_read.event_id,
            disjoint_write.event_id,
            wide_write.event_id,
        ),
        ordered_edges=(
            CandidateViolationEdge(
                source_event=wide_write.event_id,
                target_event=cycle_read.event_id,
                relation_type="rf",
                side="source",
                conditional=True,
                relation_ids=(cycle_rf.relation_id,),
                rf_candidate_ids=(cycle_rf.relation_id,),
            ),
            CandidateViolationEdge(
                source_event=cycle_read.event_id,
                target_event=disjoint_write.event_id,
                relation_type="ppo_reachability",
                side="source",
                conditional=False,
                ppo_reachability_path=(
                    cycle_read.event_id,
                    disjoint_write.event_id,
                ),
            ),
            CandidateViolationEdge(
                source_event=disjoint_write.event_id,
                target_event=wide_write.event_id,
                relation_type="coherence",
                side="source",
                conditional=True,
                relation_ids=(coherence_id,),
                co_dependency_ids=(coherence_id,),
            ),
        ),
        rf_dependencies=(cycle_rf.relation_id,),
        co_dependencies=(coherence_id,),
        ppo_reachability_dependencies=(
            (cycle_read.event_id, disjoint_write.event_id),
        ),
    )
    local_witness = _build_local_witness(
        candidate,
        cycle_edges=cycle_edges,
        local_result=result,
    )
    assert local_witness is not None
    obligations = _build_local_obligations(
        candidate,
        cycle_edges=cycle_edges,
        events=events,
        witness=local_witness,
        query_event_ids=tuple(event.event_id for event in events),
        window_event_ids=tuple(event.event_id for event in events),
    )
    assert obligations.rf_exclusivity_preserved
    replay = replay_candidate_cycle(
        graph,
        certificate,
        candidate,
        obligations,
        local_witness,
        source_reduced=frozenset(source_reduced),
        target_reduced=frozenset(target_reduced),
        events=events,
    )
    assert replay.status.value == "full_window_model_validated"
    assert replay.execution_counterexample_validated is False

    # 两个 RF relation 可以有相同事件端点，但分别约束不同 read-part。
    same_endpoint_groups = (
        *required.relation_groups,
        *(
            (
                wide_write.event_id,
                wide_read.event_id,
                "rf",
                (item.relation_id,),
            )
            for item in same_endpoint_wide_relations
        ),
    )
    same_endpoint_result, same_endpoint_observation = run_symbolic_shadow(
        window,
        source_ppo=source_reduced,
        target_ppo=target_reduced,
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=20_000,
        execute_solver=True,
        required_source_cycle_edges=required.endpoints,
        required_source_cycle_relations=same_endpoint_groups,
        capture_model=True,
    )
    assert same_endpoint_observation.result == "sat"
    assert same_endpoint_result.witness is not None
    same_endpoint_assignments = {
        (item.read_event, item.write_event, item.address, item.size)
        for item in same_endpoint_result.witness.read_from
    }
    assert (wide_read.event_id, wide_write.event_id, base, 4) in same_endpoint_assignments
    assert (
        wide_read.event_id,
        wide_write.event_id,
        base + 4,
        4,
    ) in same_endpoint_assignments


def test_merged_rf_edge_needs_only_one_selected_byte_relation() -> None:
    """同端点 RF 的合并标签表示备选关系，不要求每个分片都选同一来源。"""

    base = 0x6000
    read = TraceEvent(1, 1, 0, 0x60, EventKind.LOAD, base, 8)
    tail_write = TraceEvent(1, 2, 0, 0x61, EventKind.STORE, base + 8, 4)
    wide_write = TraceEvent(2, 1, 0, 0x62, EventKind.STORE, base, 12)
    high_write = TraceEvent(3, 1, 0, 0x63, EventKind.STORE, base + 4, 4)
    events = (read, tail_write, wide_write, high_write)
    window = AnalysisWindow("p16-rf-alternative-labels", events, ())

    relations = _candidate_relations(events)
    wide_read_ids = tuple(
        item.relation_id
        for item in relations
        if item.kind == "rf" and item.event_ids == (wide_write.event_id, read.event_id)
    )
    high_read_id = next(
        item.relation_id
        for item in relations
        if item.kind == "rf" and item.event_ids == (high_write.event_id, read.event_id)
    )
    assert len(wide_read_ids) == 2

    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted
    # 这条 Load→Store 只在 source PPO 中成立：写入落在读操作范围之外，
    # 因此 target PPO 不会把候选 source cycle 变成 target cycle。
    source_edge = (read.event_id, tail_write.event_id)
    assert source_edge in graph.source_edges
    assert source_edge not in graph.target_edges
    source_reduced = frozenset(
        set(graph.source_edges)
        - {
            (item.source_event, item.target_event)
            for item in certificate.source.removed_edges
        }
    )
    target_reduced = frozenset(
        set(graph.target_edges)
        - {
            (item.source_event, item.target_event)
            for item in certificate.target.removed_edges
        }
    )
    all_graph_edges, _, _ = _build_candidate_graph(events, source_reduced)
    rf_edge = next(
        item
        for item in all_graph_edges
        if item.source == wide_write.event_id
        and item.target == read.event_id
        and item.kind == "rf"
    )
    assert set(rf_edge.relation_ids) == set(wide_read_ids)
    tail_co_id = f"co:{tail_write.event_id}:{wide_write.event_id}"
    cycle_edges = (
        rf_edge,
        _LabeledEdge(
            read.event_id,
            tail_write.event_id,
            "source_ppo",
            f"ppo:{read.event_id}->{tail_write.event_id}",
            witness_path=(read.event_id, tail_write.event_id),
        ),
        _LabeledEdge(
            tail_write.event_id,
            wide_write.event_id,
            "coherence",
            tail_co_id,
            (tail_co_id,),
        ),
    )
    candidate = _build_candidate_violation_cycle(
        cycle_id="p16-rf-alternative-labels",
        cycle_edges=cycle_edges,
        event_by_id={item.event_id: item for item in events},
    )
    required = _required_local_source_edges(cycle_edges)
    extra_groups = (
        # 强制低分片从 wide_write 读取，但高分片从 high_write 读取。
        # candidate RF 合并边的两个标签中，只有低分片标签被真正选中。
        (wide_write.event_id, read.event_id, "rf", (wide_read_ids[0],)),
        (high_write.event_id, read.event_id, "rf", (high_read_id,)),
        (
            wide_write.event_id,
            high_write.event_id,
            "coherence",
            (f"co:{wide_write.event_id}:{high_write.event_id}",),
        ),
    )
    result, observation = run_symbolic_shadow(
        window,
        source_ppo=set(source_reduced),
        target_ppo=set(target_reduced),
        control_flow_closed=False,
        timeout_ms=1_000,
        max_symbolic_terms=20_000,
        execute_solver=True,
        required_source_cycle_edges=required.endpoints,
        required_source_cycle_relations=(*required.relation_groups, *extra_groups),
        capture_model=True,
    )
    assert observation.result == "sat"
    assert result.witness is not None
    assignments = {
        (item.read_event, item.write_event, item.address, item.size)
        for item in result.witness.read_from
    }
    assert (read.event_id, wide_write.event_id, base, 4) in assignments
    assert (read.event_id, high_write.event_id, base + 4, 4) in assignments
    assert not any(
        (read.event_id, wide_write.event_id, address, size) in assignments
        for address, size in ((base + 4, 4),)
    )

    witness = _build_local_witness(
        candidate,
        cycle_edges=cycle_edges,
        local_result=result,
    )
    assert witness is not None
    obligations = _build_local_obligations(
        candidate,
        cycle_edges=cycle_edges,
        events=events,
        witness=witness,
        query_event_ids=tuple(item.event_id for item in events),
        window_event_ids=tuple(item.event_id for item in events),
    )
    replayed = replay_candidate_cycle(
        graph,
        certificate,
        candidate,
        obligations,
        witness,
        source_reduced=source_reduced,
        target_reduced=target_reduced,
        events=events,
    )
    assert replayed.status.value == "full_window_model_validated"


def test_merged_fr_labels_are_all_active_when_target_graph_is_acyclic() -> None:
    """同端点 FR 的 OR 候选在 target-acyclic 模型中会蕴含每个分片都成立。"""

    base = 0x7000
    read = TraceEvent(1, 1, 0, 0x70, EventKind.LOAD, base, 8)
    tail_write = TraceEvent(1, 2, 0, 0x71, EventKind.STORE, base + 8, 4)
    later = TraceEvent(2, 1, 0, 0x72, EventKind.STORE, base, 12)
    old_low = TraceEvent(6, 3, 0, 0x73, EventKind.STORE, base, 4)
    old_high = TraceEvent(4, 1, 0, 0x74, EventKind.STORE, base + 4, 4)
    new_high = TraceEvent(5, 1, 0, 0x75, EventKind.STORE, base + 4, 4)
    tail_read = TraceEvent(6, 1, 0, 0x76, EventKind.LOAD, base + 8, 4)
    ppo_store = TraceEvent(6, 2, 0, 0x77, EventKind.STORE, base, 4)
    events = (
        read,
        tail_write,
        later,
        old_high,
        new_high,
        tail_read,
        ppo_store,
        old_low,
    )
    window = AnalysisWindow("p16-fr-alternative-labels", events, ())
    relations = _candidate_relations(events)
    fr_ids = tuple(
        item.relation_id
        for item in relations
        if item.kind == "fr" and item.event_ids == (read.event_id, later.event_id)
    )
    low_rf_id = next(
        item.relation_id
        for item in relations
        if item.kind == "rf"
        and item.event_ids == (old_low.event_id, read.event_id)
        and item.address == base
    )
    old_high_rf_id = next(
        item.relation_id
        for item in relations
        if item.kind == "rf"
        and item.event_ids == (old_high.event_id, read.event_id)
        and item.address == base + 4
    )
    new_high_rf_id = next(
        item.relation_id
        for item in relations
        if item.kind == "rf"
        and item.event_ids == (new_high.event_id, read.event_id)
        and item.address == base + 4
    )
    assert len(fr_ids) == 2

    graph = build_ppo_graph_input(window)
    certificate, certificate_replay = build_ppo_reduction_certificate(graph)
    assert certificate_replay.accepted
    source_reduced = frozenset(
        set(graph.source_edges)
        - {
            (item.source_event, item.target_event)
            for item in certificate.source.removed_edges
        }
    )
    target_reduced = frozenset(
        set(graph.target_edges)
        - {
            (item.source_event, item.target_event)
            for item in certificate.target.removed_edges
        }
    )
    assert (tail_read.event_id, ppo_store.event_id) in source_reduced
    assert (tail_read.event_id, ppo_store.event_id) not in target_reduced

    candidate_graph, _, _ = _build_candidate_graph(events, source_reduced)
    merged_fr_edge = next(
        item
        for item in candidate_graph
        if item.source == read.event_id
        and item.target == later.event_id
        and item.kind == "fr"
    )
    assert set(merged_fr_edge.relation_ids) == set(fr_ids)
    cycle_edges = (
        next(
            item
            for item in candidate_graph
            if item.source == later.event_id
            and item.target == tail_read.event_id
            and item.kind == "rf"
        ),
        next(
            item
            for item in candidate_graph
            if item.source == tail_read.event_id
            and item.target == ppo_store.event_id
            and item.kind == "source_ppo"
        ),
        next(
            item
            for item in candidate_graph
            if item.source == ppo_store.event_id
            and item.target == old_low.event_id
            and item.kind == "source_ppo"
        ),
        next(
            item
            for item in candidate_graph
            if item.source == old_low.event_id
            and item.target == read.event_id
            and item.kind == "rf"
        ),
        merged_fr_edge,
    )
    candidate = _build_candidate_violation_cycle(
        cycle_id="p16-fr-alternative-labels",
        cycle_edges=cycle_edges,
        event_by_id={item.event_id: item for item in events},
    )
    required = _required_local_source_edges(cycle_edges)

    def run_forced_sources(high_source: TraceEvent):
        high_co_group = (
            (
                high_source.event_id
                if high_source.event_id == old_high.event_id
                else later.event_id
            ),
            (
                later.event_id
                if high_source.event_id == old_high.event_id
                else high_source.event_id
            ),
            "coherence",
            (
                f"co:{high_source.event_id}:{later.event_id}"
                if high_source.event_id == old_high.event_id
                else f"co:{later.event_id}:{high_source.event_id}",
            ),
        )
        return run_symbolic_shadow(
            window,
            source_ppo=set(source_reduced),
            target_ppo=set(target_reduced),
            control_flow_closed=False,
            timeout_ms=1_000,
            max_symbolic_terms=20_000,
            execute_solver=True,
            required_source_cycle_edges=required.endpoints,
            required_source_cycle_relations=(
                *required.relation_groups,
                (
                    high_source.event_id,
                    read.event_id,
                    "rf",
                    (
                        old_high_rf_id
                        if high_source.event_id == old_high.event_id
                        else new_high_rf_id,
                    ),
                ),
                (
                    old_low.event_id,
                    later.event_id,
                    "coherence",
                    (f"co:{old_low.event_id}:{later.event_id}",),
                ),
                high_co_group,
            ),
            capture_model=True,
        )

    both_active, both_observation = run_forced_sources(old_high)
    assert both_observation.result == "sat"
    assert both_active.witness is not None
    selected = {
        (item.read_event, item.write_event, item.address, item.size)
        for item in both_active.witness.read_from
    }
    assert (read.event_id, old_low.event_id, base, 4) in selected
    assert (read.event_id, old_high.event_id, base + 4, 4) in selected
    witness = _build_local_witness(
        candidate,
        cycle_edges=cycle_edges,
        local_result=both_active,
    )
    assert witness is not None
    obligations = _build_local_obligations(
        candidate,
        cycle_edges=cycle_edges,
        events=events,
        witness=witness,
        query_event_ids=tuple(item.event_id for item in events),
        window_event_ids=tuple(item.event_id for item in events),
    )
    replayed = replay_candidate_cycle(
        graph,
        certificate,
        candidate,
        obligations,
        witness,
        source_reduced=source_reduced,
        target_reduced=target_reduced,
        events=events,
    )
    assert replayed.status.value == "full_window_model_validated"

    one_inactive, one_observation = run_forced_sources(new_high)
    # FR(read,later) 只要有一个分片成立就满足候选 OR；但若另一个分片从
    # coherence 上晚于 later 的写读取，就形成 later→source→read→later，
    # 被同一查询的 target-acyclicity 约束排除。
    assert one_observation.result == "unsat", (
        one_inactive.reason,
        one_observation.reason,
    )


def test_p16_complete_model_replays_synthetic_lb_witness() -> None:
    report = characterize_graph_first_window(
        _lb_window(),
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )

    item = report.candidates[0]
    assert item.local_witness is not None
    assert item.local_witness.model_snapshot is not None
    assert item.local_witness.model_snapshot.complete is True
    assert item.replay is not None
    assert item.replay.model_snapshot_valid is True
    assert item.replay.full_window_closed is True
    assert item.replay.status.value == "full_window_model_validated"
    assert item.replay.execution_counterexample_validated is False
    assert item.replay.trace_completeness_validated is False
    assert item.replay.control_flow_closure_validated is False
    assert item.replay.read_values_validated is False
    assert {
        "trace-completeness",
        "control-flow-closure",
        "read-value-validation",
        "observed-execution-binding",
    } <= set(item.replay.execution_evidence_gaps)


def test_p16_local_model_does_not_claim_full_window_closure() -> None:
    base = _lb_window()
    window = AnalysisWindow(
        "synthetic-lb-with-unrelated-event",
        base.events
        + (TraceEvent(3, 1, 0, 0x30, EventKind.STORE, 0x3000, 4),),
        (),
    )
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )

    item = report.candidates[0]
    assert item.local_query is not None
    assert item.local_query.feasibility_status.value == "FEASIBLE"
    assert item.replay is not None
    assert item.replay.full_window_closed is False
    assert item.replay.status.value == "local_model_validated"
    assert any(
        failure.kind is CandidateReplayFailureKind.LOCAL_MODEL_INCOMPLETE
        and failure.predicate == "full-window-event-closure"
        for failure in item.replay.failures
    )


def test_p16_replay_rejects_tampered_model_snapshot() -> None:
    window = _lb_window()
    graph = build_ppo_graph_input(window)
    certificate, reduction_replay = build_ppo_reduction_certificate(graph)
    assert reduction_replay.accepted
    report = characterize_graph_first_window(
        window,
        reduction_certificate=certificate,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
        capture_model=True,
    )
    item = report.candidates[0]
    assert item.local_witness is not None
    assert item.local_witness.model_snapshot is not None
    assert item.local_obligations is not None
    candidate = item.candidate_violation_cycle
    assert candidate is not None

    snapshot = item.local_witness.model_snapshot
    first = snapshot.variables[0]
    replacement_sort = "Bool" if first.sort == "Int" else "Int"
    tampered_first = first.model_copy(update={"sort": replacement_sort})
    tampered_snapshot = snapshot.model_copy(
        update={
            "variables": (tampered_first,) + snapshot.variables[1:],
        }
    )
    tampered_witness = item.local_witness.model_copy(
        update={"model_snapshot": tampered_snapshot}
    )
    source_removed = {
        (edge.source_event, edge.target_event)
        for edge in certificate.source.removed_edges
    }
    target_removed = {
        (edge.source_event, edge.target_event)
        for edge in certificate.target.removed_edges
    }
    replay = replay_candidate_cycle(
        graph,
        certificate,
        candidate,
        item.local_obligations,
        tampered_witness,
        source_reduced=frozenset(graph.source_edges - source_removed),
        target_reduced=frozenset(graph.target_edges - target_removed),
        events=window.events,
    )
    assert replay.status.value == "rejected"
    assert any(
        failure.kind is CandidateReplayFailureKind.WITNESS_SERIALIZATION_ERROR
        and failure.predicate in {"model-snapshot-integrity", "model-variable-sorts"}
        for failure in replay.failures
    )


def test_candidate_replay_rejects_tampered_ppo_witness() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, certificate_replay = build_ppo_reduction_certificate(graph)
    assert certificate_replay.accepted is True
    source_reduced = frozenset(graph.source_edges)
    target_reduced = frozenset(graph.target_edges)
    bad_cycle = item.candidate_violation_cycle.model_copy(
        update={
            "ordered_edges": tuple(
                edge.model_copy(
                    update={
                        "ppo_reachability_path": (
                            edge.ppo_reachability_path[0],
                            "missing-event",
                        )
                    }
                )
                if edge.relation_type == "ppo_reachability"
                else edge
                for edge in item.candidate_violation_cycle.ordered_edges
            )
        }
    )
    replay = replay_candidate_cycle(
        graph,
        certificate,
        bad_cycle,
        item.local_obligations,
        item.local_witness,
        source_reduced=source_reduced,
        target_reduced=target_reduced,
        events=window.events,
    )
    assert replay.status.value == "rejected"
    assert replay.ppo_reachability_valid is False


def test_candidate_replay_rejects_incomplete_rf_domain() -> None:
    window = _lb_window()
    report = characterize_graph_first_window(
        window,
        max_cycle_length=6,
        max_cycles=1,
        max_search_states=100,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )
    item = report.candidates[0]
    assert item.candidate_violation_cycle is not None
    assert item.local_obligations is not None
    assert item.local_witness is not None
    graph = build_ppo_graph_input(window)
    certificate, certificate_replay = build_ppo_reduction_certificate(graph)
    assert certificate_replay.accepted is True
    incomplete = item.local_obligations.model_copy(
        update={"rf_candidate_domain_ids": ()}
    )
    replay = replay_candidate_cycle(
        graph,
        certificate,
        item.candidate_violation_cycle,
        incomplete,
        item.local_witness,
        source_reduced=frozenset(graph.source_edges),
        target_reduced=frozenset(graph.target_edges),
        events=window.events,
    )
    assert replay.status.value == "rejected"
    assert replay.rf_exclusivity_valid is False
