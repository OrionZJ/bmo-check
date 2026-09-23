"""P13 CEGAR A/B diagnostics.

The functions in this module deliberately compare the old P11 graph search with
the two P12 shadow modes.  They never call the formal checker and therefore
cannot create a verdict.  The independent cycle enumerator is intentionally
small and bounded; it is a coverage oracle for reviewed fixtures, not a new
production search algorithm.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass

try:
    import resource
except ImportError:  # pragma: no cover - Windows development environment.
    resource = None

from bmo_check_dynamic.model import (
    CandidateCoverageReport,
    CandidateDiscoveryResourcePolicy,
    CegarModeComparisonReport,
    CegarExperimentMode,
    CegarModeMetrics,
    GraphFirstLocalQuery,
    GraphFirstQueryStatus,
    LocalCycleStatus,
    LocalWitnessClosureKind,
    LocalWitnessClosureRecord,
)
from bmo_check_dynamic.proof import run_symbolic_shadow

from .cegar import (
    _build_candidate_violation_cycle,
    characterize_cegar_window,
    canonicalize_cycle_skeleton,
    replay_blocking_constraint_detail,
)
from .graph_first import (
    _LabeledEdge,
    _build_candidate_graph,
    _build_local_obligations,
    _build_local_witness,
    _reduced_edges,
    _required_local_source_edges,
    _strongly_connected_components,
    characterize_graph_first_window,
    replay_candidate_cycle,
)
from .ppo_reduction import (
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
    ppo_certificate_digest,
    replay_ppo_reduction,
)
from .windows import AnalysisWindow


@dataclass(frozen=True, slots=True)
class _PreparedCertificate:
    certificate: object
    prepare_ms: int
    replay_ms: int
    digest: str


def _peak_rss_mb() -> float | None:
    if resource is None:
        return None
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # Linux reports KiB, macOS reports bytes.  This code is also used by the
    # WSL benchmark, where the Linux branch is the relevant one.
    return value / (1024.0 if value else 1.0)


def _prepare_certificate(window: AnalysisWindow, supplied) -> _PreparedCertificate:
    graph = build_ppo_graph_input(window)
    started = time.perf_counter()
    if supplied is None:
        certificate, _ = build_ppo_reduction_certificate(graph)
    else:
        certificate = supplied
    prepare_ms = int((time.perf_counter() - started) * 1000)
    started = time.perf_counter()
    replay = replay_ppo_reduction(graph, certificate)
    replay_ms = int((time.perf_counter() - started) * 1000)
    if not replay.accepted:
        raise ValueError("P13 certificate replay rejected: " + "; ".join(replay.reasons))
    return _PreparedCertificate(
        certificate=certificate,
        prepare_ms=prepare_ms,
        replay_ms=replay_ms,
        digest=ppo_certificate_digest(certificate),
    )


def _status_counts(records) -> tuple[int, int, int, int]:
    feasible = infeasible = unknown = not_run = 0
    for record in records:
        query = record.local_query
        if query is None:
            continue
        if query.feasibility_status.value == "FEASIBLE":
            feasible += 1
        elif query.feasibility_status.value == "INFEASIBLE":
            infeasible += 1
        else:
            unknown += 1
        if query.status.value == "not_run":
            not_run += 1
    return feasible, infeasible, unknown, not_run


def _p11_metrics(report, prepared: _PreparedCertificate, started: float) -> CegarModeMetrics:
    records = report.candidates
    feasible = infeasible = unknown = not_run = 0
    for record in records:
        query = record.local_query
        if query is None:
            continue
        if query.feasibility_status.value == "FEASIBLE":
            feasible += 1
        elif query.feasibility_status.value == "INFEASIBLE":
            infeasible += 1
        else:
            unknown += 1
        if query.status.value == "not_run":
            not_run += 1
    ledger = report.search_ledger
    replay_accepted = sum(
        record.replay is not None and record.replay.status.value == "accepted"
        for record in records
    )
    replay_rejected = sum(
        record.replay is not None and record.replay.status.value == "rejected"
        for record in records
    )
    replay_reasons = tuple(
        sorted(
            {
                reason
                for record in records
                if record.replay is not None
                for reason in record.replay.reasons
            }
        )
    )
    search_ms = int((time.perf_counter() - started) * 1000)
    return CegarModeMetrics(
        mode=CegarExperimentMode.RAW_P11,
        certificate_prepare_ms=prepared.prepare_ms,
        certificate_replay_ms=prepared.replay_ms,
        search_ms=search_ms,
        total_ms=prepared.prepare_ms + prepared.replay_ms + search_ms,
        peak_rss_mb=_peak_rss_mb(),
        raw_search_states=report.explored_states,
        generated_candidates=report.cycles_considered,
        unique_candidates=report.cycles_considered,
        candidate_skeleton_ids=tuple(
            sorted(
                {
                    canonicalize_cycle_skeleton(record.candidate_violation_cycle).canonical_id
                    for record in records
                    if record.candidate_violation_cycle is not None
                }
            )
        ),
        discovery_profile=report.discovery_profile,
        local_queries=sum(record.local_query is not None for record in records),
        feasible=feasible,
        infeasible=infeasible,
        unknown=unknown,
        not_run=not_run,
        replay_accepted=replay_accepted,
        replay_rejected=replay_rejected,
        replay_reasons=replay_reasons,
        blocked=0,
        status=("TRUNCATED" if report.truncated else "COMPLETE"),
        search_truncated=report.truncated,
        query_truncated=report.cycles_returned >= report.max_cycles and report.truncated,
        reasons=report.reasons,
    )


def _p12_metrics(report, mode: CegarExperimentMode, prepared: _PreparedCertificate, started: float) -> CegarModeMetrics:
    profile = report.profile
    ledger = report.ledger
    records = report.candidates
    feasible, infeasible, unknown, not_run = _status_counts(records)
    invalid_blocks = 0
    for record in records:
        block = record.blocking_constraint
        if block is None or record.local_obligations is None:
            continue
        replay = replay_blocking_constraint_detail(
            block,
            record.candidate_violation_cycle,
            record.canonical_skeleton,
            record.local_obligations,
        )
        if not replay.accepted:
            invalid_blocks += 1
    search_ms = int((time.perf_counter() - started) * 1000)
    replay_accepted = sum(
        record.replay is not None and record.replay.status.value == "accepted"
        for record in records
    )
    replay_rejected = sum(
        record.replay is not None and record.replay.status.value == "rejected"
        for record in records
    )
    replay_reasons = tuple(
        sorted(
            {
                reason
                for record in records
                if record.replay is not None
                for reason in record.replay.reasons
            }
        )
    )
    return CegarModeMetrics(
        mode=mode,
        certificate_prepare_ms=prepared.prepare_ms,
        certificate_replay_ms=prepared.replay_ms,
        search_ms=search_ms,
        total_ms=prepared.prepare_ms + prepared.replay_ms + search_ms,
        peak_rss_mb=_peak_rss_mb(),
        raw_search_states=profile.raw_search_states if profile else 0,
        generated_candidates=profile.generated_skeletons if profile else 0,
        unique_candidates=profile.unique_skeletons if profile else 0,
        duplicate_candidates=profile.duplicate_skeletons if profile else 0,
        candidate_skeleton_ids=tuple(
            sorted(
                {
                    record.canonical_skeleton.canonical_id
                    for record in records
                    if record.canonical_skeleton is not None
                }
            )
        ),
        same_rf_variants=profile.same_rf_assignment_variants if profile else 0,
        ppo_witness_variants=profile.same_structural_cycle_different_ppo_witness if profile else 0,
        local_queries=ledger.local_query_count if ledger else 0,
        feasible=feasible,
        infeasible=infeasible,
        unknown=unknown,
        not_run=not_run,
        replay_accepted=replay_accepted,
        replay_rejected=replay_rejected,
        replay_reasons=replay_reasons,
        blocked=ledger.pruned_by_block_count if ledger else 0,
        invalid_blocks=invalid_blocks,
        search_truncated=profile.search_truncated if profile else False,
        query_truncated=profile.query_truncated if profile else False,
        status=(ledger.status.value if ledger else "INCOMPLETE"),
        reasons=report.reasons,
    )


def _p14_metrics(
    report,
    prepared: _PreparedCertificate,
    started: float,
) -> CegarModeMetrics:
    """把结构化发现器接到同一局部 SMT 评估路径；仍是 shadow-only。"""

    metrics = _p11_metrics(report, prepared, started)
    return metrics.model_copy(
        update={
            "mode": CegarExperimentMode.STRUCTURED_P14,
            "discovery_profile": report.discovery_profile,
            "unique_candidates": len(metrics.candidate_skeleton_ids),
            "duplicate_candidates": max(
                0, metrics.generated_candidates - len(metrics.candidate_skeleton_ids)
            ),
        }
    )


def _close_local_feasible_candidates(
    window: AnalysisWindow,
    certificate: object,
    candidates,
    *,
    control_flow_closed: bool,
    timeout_ms: int,
    max_symbolic_terms: int,
) -> tuple[LocalWitnessClosureRecord, ...]:
    """用同一 checker contract 把局部 SAT 扩展到完整窗口并独立 replay。"""

    graph = build_ppo_graph_input(window)
    source_reduced = _reduced_edges(
        graph.source_edges, certificate.source.removed_edges
    )
    target_reduced = _reduced_edges(
        graph.target_edges, certificate.target.removed_edges
    )
    records: list[LocalWitnessClosureRecord] = []
    for item in candidates:
        if (
            item.local_query is None
            or item.local_query.feasibility_status is not LocalCycleStatus.FEASIBLE
            or item.candidate_violation_cycle is None
        ):
            continue
        candidate = item.candidate_violation_cycle
        cycle_edges = tuple(
            _LabeledEdge(
                source=edge.source_event,
                target=edge.target_event,
                kind=edge.relation_type,
                relation_id=(edge.relation_ids[0] if edge.relation_ids else ""),
                relation_ids=edge.relation_ids,
                witness_path=edge.ppo_reachability_path,
            )
            for edge in candidate.ordered_edges
        )
        required = frozenset(_required_local_source_edges(cycle_edges))
        result, observation = run_symbolic_shadow(
            window,
            source_ppo=set(source_reduced),
            target_ppo=set(target_reduced),
            control_flow_closed=control_flow_closed,
            timeout_ms=timeout_ms,
            max_symbolic_terms=max_symbolic_terms,
            execute_solver=True,
            required_source_cycle_edges=required,
            capture_model=True,
        )
        status = {
            "sat": GraphFirstQueryStatus.SAT_CANDIDATE,
            "unsat": GraphFirstQueryStatus.UNSAT_LOCAL,
        }.get(observation.result, GraphFirstQueryStatus.UNKNOWN_LOCAL)
        feasibility = {
            "sat": LocalCycleStatus.FEASIBLE,
            "unsat": LocalCycleStatus.INFEASIBLE,
        }.get(observation.result, LocalCycleStatus.UNKNOWN)
        query = GraphFirstLocalQuery(
            status=status,
            feasibility_status=feasibility,
            solver_result=observation.result,
            reason=observation.reason,
            event_count=len(window.events),
            source_ppo_edge_count=len(source_reduced),
            target_ppo_edge_count=len(target_reduced),
            formula_terms=observation.formula_terms,
            assertion_count=observation.assertion_count,
            z3_ast_count=observation.z3_ast_count,
            build_time_ms=observation.build_time_ms,
            solver_time_ms=observation.solver_time_ms,
        )
        witness = None
        replay = None
        witness_started = time.perf_counter()
        if result.witness is not None:
            witness = _build_local_witness(
                candidate,
                cycle_edges=cycle_edges,
                local_result=result,
            )
        witness_build_ms = max(
            0, int((time.perf_counter() - witness_started) * 1000)
        )
        obligations_started = time.perf_counter()
        obligations = _build_local_obligations(
            candidate,
            cycle_edges=cycle_edges,
            events=window.events,
            witness=witness,
            query_event_ids=tuple(event.event_id for event in window.events),
        )
        obligations_build_ms = max(
            0, int((time.perf_counter() - obligations_started) * 1000)
        )
        replay_ms = 0
        if witness is not None:
            replay_started = time.perf_counter()
            replay = replay_candidate_cycle(
                graph,
                certificate,
                candidate,
                obligations,
                witness,
                source_reduced=source_reduced,
                target_reduced=target_reduced,
                events=window.events,
            )
            replay_ms = max(0, int((time.perf_counter() - replay_started) * 1000))
        if observation.result == "unsat":
            classification = LocalWitnessClosureKind.SPURIOUS_LOCAL_SAT
        elif observation.result != "sat":
            classification = LocalWitnessClosureKind.CLOSURE_QUERY_UNKNOWN
        elif replay is not None and replay.status.value == "accepted":
            classification = LocalWitnessClosureKind.VALID_COMPLETE_WITNESS
        else:
            classification = LocalWitnessClosureKind.WITNESS_REPLAY_REJECTED
        records.append(
            LocalWitnessClosureRecord(
                candidate_id=item.cycle_id,
                local_event_count=item.local_query.event_count,
                full_window_event_count=len(window.events),
                classification=classification,
                closure_query=query,
                closure_witness=witness,
                replay=replay,
                encoding_ms=observation.build_time_ms,
                solver_ms=observation.solver_time_ms,
                witness_build_ms=witness_build_ms,
                obligations_build_ms=obligations_build_ms,
                replay_ms=replay_ms,
                reasons=(
                    replay.reasons
                    if replay is not None and replay.reasons
                    else ((observation.reason,) if observation.reason else ())
                ),
            )
        )
    return tuple(records)


def compare_cegar_modes(
    window: AnalysisWindow,
    *,
    fixture: str,
    reduction_certificate=None,
    control_flow_closed: bool = False,
    max_cycle_length: int = 12,
    max_search_states: int = 10_000,
    max_local_queries: int = 1_000,
    local_timeout_ms: int = 1_000,
    local_max_symbolic_terms: int = 100_000,
    execute_local_solver: bool = True,
    coverage: CandidateCoverageReport | None = None,
    include_structured: bool = False,
    only_mode: CegarExperimentMode | None = None,
    discovery_only: bool = False,
    include_bounded: bool = False,
    discovery_resource_policy: CandidateDiscoveryResourcePolicy | None = None,
    include_candidate_records: bool = False,
    capture_model: bool = False,
    close_feasible_candidates: bool = False,
    closure_timeout_ms: int = 5_000,
    closure_max_symbolic_terms: int = 100_000,
) -> CegarModeComparisonReport:
    """用完全相同的边界比较 P11、P12 canonical 和 P12 blocking。"""

    prepared = _prepare_certificate(window, reduction_certificate)
    modes: list[CegarModeMetrics] = []

    if only_mode in (None, CegarExperimentMode.RAW_P11):
        started = time.perf_counter()
        raw = characterize_graph_first_window(
            window,
            reduction_certificate=prepared.certificate,
            control_flow_closed=control_flow_closed,
            max_cycle_length=max_cycle_length,
            max_cycles=max_local_queries,
            max_search_states=max_search_states,
            local_timeout_ms=local_timeout_ms,
            local_max_symbolic_terms=local_max_symbolic_terms,
            execute_local_solver=execute_local_solver,
            evaluate_candidates=not discovery_only,
        )
        modes.append(_p11_metrics(raw, prepared, started))

    for mode, enable_blocking in (
        (CegarExperimentMode.CANONICAL, False),
        (CegarExperimentMode.CANONICAL_BLOCKING, True),
    ):
        if only_mode is not None and only_mode is not mode:
            continue
        started = time.perf_counter()
        report = characterize_cegar_window(
            window,
            reduction_certificate=prepared.certificate,
            control_flow_closed=control_flow_closed,
            max_cycle_length=max_cycle_length,
            max_search_states=max_search_states,
            max_local_queries=max_local_queries,
            max_generated_candidates=max_local_queries,
            local_timeout_ms=local_timeout_ms,
            local_max_symbolic_terms=local_max_symbolic_terms,
            execute_local_solver=execute_local_solver,
            evaluate_candidates=not discovery_only,
            canonicalize=True,
            enable_blocking=enable_blocking,
            mode=mode.value,
        )
        modes.append(_p12_metrics(report, mode, prepared, started))

    if (include_structured or only_mode is CegarExperimentMode.STRUCTURED_P14) and (
        only_mode is None or only_mode is CegarExperimentMode.STRUCTURED_P14
    ):
        started = time.perf_counter()
        structured = characterize_graph_first_window(
            window,
            reduction_certificate=prepared.certificate,
            control_flow_closed=control_flow_closed,
            max_cycle_length=max_cycle_length,
            max_cycles=max_local_queries,
            max_search_states=max_search_states,
            local_timeout_ms=local_timeout_ms,
            local_max_symbolic_terms=local_max_symbolic_terms,
            execute_local_solver=execute_local_solver,
            discovery_scheduler="fair_structured",
            evaluate_candidates=not discovery_only,
            capture_model=capture_model,
        )
        modes.append(_p14_metrics(structured, prepared, started))

    if (include_bounded or only_mode is CegarExperimentMode.STRUCTURED_P15) and (
        only_mode is None or only_mode is CegarExperimentMode.STRUCTURED_P15
    ):
        started = time.perf_counter()
        bounded_policy = discovery_resource_policy or CandidateDiscoveryResourcePolicy(
            max_in_memory_frontier=max(1_000, max_local_queries * 100),
            max_search_states=max_search_states,
        )
        bounded = characterize_graph_first_window(
            window,
            reduction_certificate=prepared.certificate,
            control_flow_closed=control_flow_closed,
            max_cycle_length=max_cycle_length,
            max_cycles=max_local_queries,
            max_search_states=max_search_states,
            local_timeout_ms=local_timeout_ms,
            local_max_symbolic_terms=local_max_symbolic_terms,
            execute_local_solver=execute_local_solver,
            discovery_scheduler="bounded_lazy_p15",
            discovery_resource_policy=bounded_policy,
            evaluate_candidates=not discovery_only,
            capture_model=capture_model,
        )
        metrics = _p14_metrics(bounded, prepared, started).model_copy(
            update={
                "mode": CegarExperimentMode.STRUCTURED_P15,
                "candidate_records": (
                    bounded.candidates if include_candidate_records else ()
                ),
            }
        )
        if close_feasible_candidates:
            metrics = metrics.model_copy(
                update={
                    "witness_closures": _close_local_feasible_candidates(
                        window,
                        prepared.certificate,
                        bounded.candidates,
                        control_flow_closed=control_flow_closed,
                        timeout_ms=closure_timeout_ms,
                        max_symbolic_terms=closure_max_symbolic_terms,
                    )
                }
            )
        modes.append(metrics)

    candidate_sets = {
        item.mode.value: set(item.candidate_skeleton_ids)
        for item in modes
    }
    raw_candidates = candidate_sets.get(CegarExperimentMode.RAW_P11.value, set())
    candidate_differences = {
        mode: tuple(sorted(values ^ raw_candidates))
        for mode, values in candidate_sets.items()
        if values ^ raw_candidates
    }
    baseline_differences = (
        {
            mode: values
            for mode, values in candidate_differences.items()
            if mode != CegarExperimentMode.STRUCTURED_P14.value
        }
        if CegarExperimentMode.RAW_P11.value in candidate_sets
        else {}
    )

    return CegarModeComparisonReport(
        fixture=fixture,
        window_id=window.window_id,
        event_count=len(window.events),
        max_cycle_length=max_cycle_length,
        max_search_states=max_search_states,
        max_local_queries=max_local_queries,
        local_timeout_ms=local_timeout_ms,
        local_max_symbolic_terms=local_max_symbolic_terms,
        certificate_digest=prepared.digest,
        certificate_prepare_ms=prepared.prepare_ms,
        certificate_replay_ms=prepared.replay_ms,
        modes=tuple(modes),
        # P11/P12 are the characterization baseline.  P14 deliberately uses
        # a fair scheduler, so a bounded run may expose a different prefix;
        # that difference is reported, but is not hidden as a baseline drift.
        candidate_sets_match=not baseline_differences,
        candidate_set_differences=candidate_differences,
        coverage=coverage,
        isolated_process=False,
        reasons=(
            "P13/P14 shadow-only comparison; RSS is same-process rusage and must not be used as an isolated peak bound",
        ),
    )


def _independent_cycles(
    window: AnalysisWindow,
    certificate,
    *,
    max_cycle_length: int,
    max_search_states: int,
    max_cycles: int,
) -> tuple[set[str], bool]:
    """独立 DFS 基线；不调用 P11 的 skeleton enumerator。"""

    graph = build_ppo_graph_input(window)
    source = _reduced_edges(graph.source_edges, certificate.source.removed_edges)
    labeled, _, _ = _build_candidate_graph(window.events, source)
    adjacency: dict[str, list[_LabeledEdge]] = defaultdict(list)
    for edge in labeled:
        adjacency[edge.source].append(edge)
    for values in adjacency.values():
        values.sort(key=lambda edge: (edge.target, edge.kind, edge.relation_id))
    event_by_id = {event.event_id: event for event in window.events}
    found: set[str] = set()
    states = 0
    truncated = False

    def visit(start: str, current: str, nodes: list[str], edges: list[_LabeledEdge]) -> None:
        nonlocal states, truncated
        if states >= max_search_states or len(found) >= max_cycles:
            truncated = True
            return
        if len(nodes) > max_cycle_length:
            return
        for edge in adjacency.get(current, ()):
            states += 1
            if edge.target == start and len(edges) >= 1:
                completed = tuple(edges + [edge])
                if any(item.kind == "source_ppo" for item in completed) and any(
                    item.kind != "source_ppo" for item in completed
                ):
                    candidate = _build_candidate_violation_cycle(
                        cycle_id="independent",
                        cycle_edges=completed,
                        event_by_id=event_by_id,
                    )
                    found.add(canonicalize_cycle_skeleton(candidate).canonical_id)
                    if len(found) >= max_cycles:
                        truncated = True
                        return
                continue
            if edge.target in nodes:
                continue
            visit(start, edge.target, nodes + [edge.target], edges + [edge])
            if truncated:
                return

    for start in sorted(event_by_id):
        visit(start, start, [start], [])
        if truncated:
            break
    return found, truncated


def compare_candidate_coverage(
    window: AnalysisWindow,
    report,
    *,
    certificate,
    max_cycle_length: int,
    max_search_states: int,
    max_candidates: int,
) -> CandidateCoverageReport:
    expected, exhaustive_truncated = _independent_cycles(
        window,
        certificate,
        max_cycle_length=max_cycle_length,
        max_search_states=max_search_states,
        max_cycles=max_candidates,
    )
    observed: set[str] = set()
    for item in report.candidates:
        if hasattr(item, "canonical_skeleton"):
            if not item.pruned or item.prune_reason is not None:
                observed.add(item.canonical_skeleton.canonical_id)
        elif getattr(item, "candidate_violation_cycle", None) is not None:
            observed.add(
                canonicalize_cycle_skeleton(item.candidate_violation_cycle).canonical_id
            )
    unresolved = sum(
        1
        for item in report.candidates
        if item.local_query is not None
        and (
            item.local_query.feasibility_status.value == "UNKNOWN"
            or item.local_query.status.value == "not_run"
        )
    )
    invalid = 0
    for item in report.candidates:
        block = getattr(item, "blocking_constraint", None)
        obligations = getattr(item, "local_obligations", None)
        skeleton = getattr(item, "canonical_skeleton", None)
        if block is None or obligations is None or skeleton is None:
            continue
        if not replay_blocking_constraint_detail(
            block,
            item.candidate_violation_cycle,
            skeleton,
            obligations,
        ).accepted:
            invalid += 1
    missing = tuple(sorted(expected - observed))
    unexpected = tuple(sorted(observed - expected))
    reasons: list[str] = []
    if exhaustive_truncated:
        reasons.append("independent exhaustive baseline reached its bound")
    if missing:
        reasons.append("normalized search missed independently enumerated candidates")
    if unresolved:
        reasons.append("UNKNOWN local queries remain")
    if invalid:
        reasons.append("one or more blocking constraints failed independent replay")
    complete = not exhaustive_truncated and not missing and not unexpected and not unresolved and not invalid
    return CandidateCoverageReport(
        bound_cycle_length=max_cycle_length,
        independent_candidate_count=len(expected),
        observed_candidate_count=len(observed),
        missing_candidate_ids=missing,
        unexpected_candidate_ids=unexpected,
        unresolved_query_count=unresolved,
        invalid_block_count=invalid,
        exhaustive_search_truncated=exhaustive_truncated,
        complete=complete,
        reasons=tuple(reasons),
    )


__all__ = [
    "compare_cegar_modes",
    "compare_candidate_coverage",
]
