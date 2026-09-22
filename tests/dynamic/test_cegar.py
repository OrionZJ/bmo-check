from __future__ import annotations

from bmo_check_dynamic.analysis import (
    canonicalize_cycle_skeleton,
    compare_candidate_coverage,
    compare_cegar_modes,
    characterize_cegar_window,
)
from bmo_check_dynamic.analysis.cegar import (
    blocking_constraint_applies,
    build_blocking_constraint,
    replay_blocking_constraint,
    replay_blocking_constraint_detail,
)
from bmo_check_dynamic.analysis.graph_first import characterize_graph_first_window
from bmo_check_dynamic.model import (
    CandidateViolationCycle,
    CandidateViolationEdge,
    LocalCycleObligationSet,
    LocalCycleStatus,
)
from bmo_check_dynamic.model import CegarExperimentMode
from bmo_check_dynamic.model import CandidateDiscoveryResourcePolicy
from bmo_check_dynamic.analysis.ppo_reduction import (
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
)

from bmo_check_dynamic.analysis import AnalysisWindow
from bmo_check_dynamic.model import EventKind, TraceEvent


def _lb_window() -> AnalysisWindow:
    return AnalysisWindow(
        "cegar-fixture",
        (
            TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x2000, 4),
            TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1000, 4),
            TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
            TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x2000, 4),
        ),
        (),
    )


def _candidate(*, cycle_id: str, ppo_path: tuple[str, ...]) -> CandidateViolationCycle:
    return CandidateViolationCycle(
        cycle_id=cycle_id,
        cycle_nodes=("r0", "w0", "r1", "w1", "r0"),
        ordered_edges=(
            CandidateViolationEdge(
                source_event="r0",
                target_event="w0",
                relation_type="ppo_reachability",
                side="source",
                conditional=False,
                ppo_reachability_path=ppo_path,
            ),
            CandidateViolationEdge(
                source_event="w0",
                target_event="r1",
                relation_type="rf",
                side="source",
                conditional=True,
                relation_ids=("rf:r1:w0",),
                rf_candidate_ids=("rf:r1:w0",),
            ),
            CandidateViolationEdge(
                source_event="r1",
                target_event="w1",
                relation_type="ppo_reachability",
                side="source",
                conditional=False,
                ppo_reachability_path=("r1", "w1"),
            ),
            CandidateViolationEdge(
                source_event="w1",
                target_event="r0",
                relation_type="rf",
                side="source",
                conditional=True,
                relation_ids=("rf:r0:w1",),
                rf_candidate_ids=("rf:r0:w1",),
            ),
        ),
        rf_dependencies=("rf:r0:w1", "rf:r1:w0"),
    )


def test_canonical_skeleton_ignores_ppo_witness_and_rotation() -> None:
    first = _candidate(cycle_id="a", ppo_path=("r0", "p0", "w0"))
    rotated = first.model_copy(
        update={
            "cycle_id": "b",
            "ordered_edges": first.ordered_edges[1:] + first.ordered_edges[:1],
        }
    )
    rotated = rotated.model_copy(
        update={
            "ordered_edges": tuple(
                edge.model_copy(
                    update={
                        "ppo_reachability_path": (
                            ("r1", "q1", "w1")
                            if edge.source_event == "r1"
                            else edge.ppo_reachability_path
                        )
                    }
                )
                for edge in rotated.ordered_edges
            )
        }
    )
    assert canonicalize_cycle_skeleton(first).canonical_id == canonicalize_cycle_skeleton(rotated).canonical_id


def test_semantic_block_preserves_rf_identity() -> None:
    candidate = _candidate(cycle_id="a", ppo_path=("r0", "p0", "w0"))
    skeleton = canonicalize_cycle_skeleton(candidate)
    obligations = LocalCycleObligationSet(
        cycle_id="a",
        selected_rf_relation_ids=candidate.rf_dependencies,
        rf_candidate_domain_ids=candidate.rf_dependencies,
        rf_exclusivity_preserved=True,
    )
    block = build_blocking_constraint(
        candidate,
        skeleton,
        obligations,
        solver_result="unsat",
        query_digest="query-a",
    )
    assert block is not None
    assert block.verified_unsat is True
    assert replay_blocking_constraint(block, candidate, skeleton, obligations)
    assert replay_blocking_constraint_detail(
        block, candidate, skeleton, obligations
    ).accepted
    assert blocking_constraint_applies(block, skeleton, obligations)
    different = obligations.model_copy(update={"selected_rf_relation_ids": ("rf:other",)})
    assert not blocking_constraint_applies(block, skeleton, different)
    tampered = block.model_copy(update={"assumptions": ("rf:other",)})
    assert not replay_blocking_constraint(tampered, candidate, skeleton, obligations)
    tampered_digest = block.model_copy(update={"candidate_digest": "wrong"})
    assert not replay_blocking_constraint_detail(
        tampered_digest, candidate, skeleton, obligations
    ).accepted


def test_cegar_shadow_is_bounded_and_never_a_verdict() -> None:
    report = characterize_cegar_window(
        _lb_window(),
        max_cycle_length=6,
        max_search_states=100,
        max_local_queries=4,
        max_generated_candidates=32,
        execute_local_solver=False,
    )
    assert report.diagnostic_only is True
    assert report.reduction_replay_accepted is True
    assert report.profile is not None
    assert report.ledger is not None
    assert report.ledger.status.value == "INCOMPLETE"
    assert report.ledger.not_run_count == sum(
        item.local_query is not None and item.local_query.status.value == "not_run"
        for item in report.candidates
    )
    assert all(
        item.local_query is not None
        for item in report.candidates
        if not item.pruned
    )
    assert all(
        item.local_query is None
        or item.local_query.feasibility_status is LocalCycleStatus.UNKNOWN
        for item in report.candidates
    )


def test_cegar_finds_replay_valid_candidate_without_formal_verdict() -> None:
    report = characterize_cegar_window(
        _lb_window(),
        max_cycle_length=6,
        max_search_states=100,
        max_local_queries=8,
        max_generated_candidates=32,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )
    feasible = [
        item
        for item in report.candidates
        if item.local_query is not None
        and item.local_query.feasibility_status is LocalCycleStatus.FEASIBLE
    ]
    assert feasible
    assert any(
        item.replay is not None and item.replay.status.value == "accepted"
        for item in feasible
    )
    assert report.diagnostic_only is True


def test_p13_same_budget_modes_record_canonical_and_blocking_effects() -> None:
    report = compare_cegar_modes(
        _lb_window(),
        fixture="synthetic-lb",
        max_cycle_length=6,
        max_search_states=100,
        max_local_queries=4,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )
    assert report.diagnostic_only is True
    assert report.isolated_process is False
    assert tuple(item.mode for item in report.modes) == (
        CegarExperimentMode.RAW_P11,
        CegarExperimentMode.CANONICAL,
        CegarExperimentMode.CANONICAL_BLOCKING,
    )
    raw, canonical, blocking = report.modes
    assert raw.raw_search_states == canonical.raw_search_states == blocking.raw_search_states
    assert canonical.duplicate_candidates >= 1
    assert blocking.local_queries <= canonical.local_queries
    assert all(item.same_budget for item in report.modes)


def test_p14_structured_discovery_is_fair_and_shadow_only() -> None:
    report = compare_cegar_modes(
        _lb_window(),
        fixture="synthetic-lb-p14",
        max_cycle_length=6,
        max_search_states=100,
        max_local_queries=4,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=False,
        include_structured=True,
    )
    structured = report.modes[-1]
    assert structured.mode is CegarExperimentMode.STRUCTURED_P14
    assert structured.discovery_profile is not None
    assert structured.discovery_profile.fair_seed_scheduling is True
    assert structured.discovery_profile.conditional_seed_count >= 1
    assert structured.diagnostic_only is True
    assert report.modes[0].discovery_profile is not None
    assert report.modes[0].discovery_profile.scheduler == "depth_first"
    assert report.candidate_sets_match is True


def test_p14_structured_candidate_set_matches_independent_small_oracle() -> None:
    window = _lb_window()
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted
    structured = characterize_graph_first_window(
        window,
        reduction_certificate=certificate,
        max_cycle_length=6,
        max_cycles=32,
        max_search_states=10_000,
        execute_local_solver=False,
        discovery_scheduler="fair_structured",
    )
    coverage = compare_candidate_coverage(
        window,
        structured,
        certificate=certificate,
        max_cycle_length=6,
        max_search_states=10_000,
        max_candidates=32,
    )
    assert coverage.missing_candidate_ids == ()
    assert coverage.unexpected_candidate_ids == ()
    assert coverage.complete is False
    assert "UNKNOWN local queries remain" in coverage.reasons


def test_p14_discovery_only_does_not_construct_local_queries() -> None:
    report = compare_cegar_modes(
        _lb_window(),
        fixture="synthetic-lb-discovery-only",
        max_cycle_length=6,
        max_search_states=100,
        max_local_queries=4,
        execute_local_solver=True,
        include_structured=True,
        discovery_only=True,
    )
    assert all(item.local_queries == 0 for item in report.modes)
    assert all("discovery-only profile" in " ".join(item.reasons) for item in report.modes)


def test_p15_lazy_discovery_is_bounded_and_resumable(tmp_path) -> None:
    window = _lb_window()
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted
    checkpoint = tmp_path / "p15-frontier.json"
    report = compare_cegar_modes(
        window,
        fixture="synthetic-lb-p15",
        reduction_certificate=certificate,
        max_cycle_length=6,
        max_search_states=100,
        max_local_queries=32,
        execute_local_solver=False,
        only_mode=CegarExperimentMode.STRUCTURED_P15,
        discovery_only=True,
        discovery_resource_policy=CandidateDiscoveryResourcePolicy(
            max_in_memory_frontier=4,
            max_search_states=1,
            sample_every=1,
            checkpoint_path=str(checkpoint),
        ),
    )
    metrics = report.modes[0]
    assert metrics.mode is CegarExperimentMode.STRUCTURED_P15
    assert metrics.discovery_profile is not None
    assert metrics.discovery_profile.scheduler == "bounded_lazy_p15"
    assert metrics.discovery_profile.search_truncated is True
    assert metrics.discovery_profile.resumable is True
    assert checkpoint.is_file()

    resumed = compare_cegar_modes(
        window,
        fixture="synthetic-lb-p15-resume",
        reduction_certificate=certificate,
        max_cycle_length=6,
        max_search_states=100,
        max_local_queries=32,
        execute_local_solver=False,
        only_mode=CegarExperimentMode.STRUCTURED_P15,
        discovery_only=True,
        discovery_resource_policy=CandidateDiscoveryResourcePolicy(
            max_in_memory_frontier=16,
            max_search_states=10_000,
            sample_every=10,
            resume_checkpoint=str(checkpoint),
        ),
    )
    resumed_profile = resumed.modes[0].discovery_profile
    assert resumed_profile is not None
    assert resumed_profile.checkpoint_binding_digest is None
    direct = compare_cegar_modes(
        window,
        fixture="synthetic-lb-p15-direct",
        reduction_certificate=certificate,
        max_cycle_length=6,
        max_search_states=10_000,
        max_local_queries=32,
        execute_local_solver=False,
        only_mode=CegarExperimentMode.STRUCTURED_P15,
        discovery_only=True,
        discovery_resource_policy=CandidateDiscoveryResourcePolicy(
            max_in_memory_frontier=16,
            max_search_states=10_000,
        ),
    )
    assert set(resumed.modes[0].candidate_skeleton_ids) == set(
        direct.modes[0].candidate_skeleton_ids
    )


def test_p15_complete_candidate_set_matches_p14_on_small_fixture() -> None:
    window = _lb_window()
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted
    p14 = characterize_graph_first_window(
        window,
        reduction_certificate=certificate,
        max_cycle_length=6,
        max_cycles=32,
        max_search_states=10_000,
        execute_local_solver=False,
        discovery_scheduler="fair_structured",
    )
    p15 = characterize_graph_first_window(
        window,
        reduction_certificate=certificate,
        max_cycle_length=6,
        max_cycles=32,
        max_search_states=10_000,
        execute_local_solver=False,
        discovery_scheduler="bounded_lazy_p15",
        discovery_resource_policy=CandidateDiscoveryResourcePolicy(
            max_in_memory_frontier=10_000,
            max_search_states=10_000,
        ),
    )
    p14_ids = {
        canonicalize_cycle_skeleton(item.candidate_violation_cycle).canonical_id
        for item in p14.candidates
    }
    p15_ids = {
        canonicalize_cycle_skeleton(item.candidate_violation_cycle).canonical_id
        for item in p15.candidates
    }
    assert p15.truncated is False
    assert p15_ids == p14_ids


def test_p13_independent_coverage_is_complete_on_small_fixture() -> None:
    window = _lb_window()
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    assert replay.accepted
    report = characterize_cegar_window(
        window,
        reduction_certificate=certificate,
        max_cycle_length=6,
        max_search_states=10_000,
        max_local_queries=32,
        max_generated_candidates=32,
        local_timeout_ms=500,
        local_max_symbolic_terms=10_000,
        execute_local_solver=True,
    )
    coverage = compare_candidate_coverage(
        window,
        report,
        certificate=certificate,
        max_cycle_length=6,
        max_search_states=10_000,
        max_candidates=32,
    )
    assert coverage.complete is True
    assert coverage.missing_candidate_ids == ()
    assert coverage.unresolved_query_count == 0


def test_p13_unknown_never_creates_block() -> None:
    candidate = _candidate(cycle_id="unknown", ppo_path=("r0", "p0", "w0"))
    skeleton = canonicalize_cycle_skeleton(candidate)
    obligations = LocalCycleObligationSet(
        cycle_id="unknown",
        selected_rf_relation_ids=candidate.rf_dependencies,
        rf_candidate_domain_ids=candidate.rf_dependencies,
        rf_exclusivity_preserved=True,
    )
    assert build_blocking_constraint(
        candidate,
        skeleton,
        obligations,
        solver_result="unknown",
        query_digest="unknown-query",
    ) is None
