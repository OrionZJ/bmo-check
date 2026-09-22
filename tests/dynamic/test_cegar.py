from __future__ import annotations

from bmo_check_dynamic.analysis import (
    canonicalize_cycle_skeleton,
    characterize_cegar_window,
)
from bmo_check_dynamic.analysis.cegar import (
    blocking_constraint_applies,
    build_blocking_constraint,
    replay_blocking_constraint,
)
from bmo_check_dynamic.model import (
    CandidateViolationCycle,
    CandidateViolationEdge,
    LocalCycleObligationSet,
    LocalCycleStatus,
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
    assert blocking_constraint_applies(block, skeleton, obligations)
    different = obligations.model_copy(update={"selected_rf_relation_ids": ("rf:other",)})
    assert not blocking_constraint_applies(block, skeleton, different)
    tampered = block.model_copy(update={"assumptions": ("rf:other",)})
    assert not replay_blocking_constraint(tampered, candidate, skeleton, obligations)


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
