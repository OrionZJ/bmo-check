from __future__ import annotations

import hashlib
import json
import time
from typing import Iterable

from bmo_check_dynamic.analysis.windows import AnalysisWindow
from bmo_check_dynamic.model import (
    PpoReductionCertificate,
    ShadowSolverComparison,
    ShadowSolverPhase,
    ShadowSolverRun,
    ReducedSolverRunCertificate,
    SolverRunReplay,
)

from .ppo_reduction import PpoGraphInput, replay_ppo_reduction


_INCOMPLETE_RESULTS = frozenset({"unknown", "timeout", "resource_limited", "not_run"})


def _digest_lines(lines: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for line in sorted(lines):
        digest.update(line.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def ppo_edges_digest(edges: Iterable[tuple[str, str]]) -> str:
    return _digest_lines(f"{left}\0{right}" for left, right in edges)


def _ppo_pair_digest(
    source_edges: Iterable[tuple[str, str]],
    target_edges: Iterable[tuple[str, str]],
) -> str:
    """绑定 source/target 两侧，避免交换两类 PPO 后仍得到同一 digest。"""

    return _digest_lines(
        [
            *(f"source\0{left}\0{right}" for left, right in source_edges),
            *(f"target\0{left}\0{right}" for left, right in target_edges),
        ]
    )


def window_digest(window: AnalysisWindow) -> str:
    """绑定窗口事件和通信边，避免同一 window_id 混用不同输入。"""

    lines = [
        "event|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(
            event.event_id,
            event.thread_id,
            event.sequence,
            event.ticket,
            event.pc,
            int(event.kind),
            event.address,
            event.size,
            event.value,
            int(event.flags),
        )
        for event in window.events
    ]
    lines.extend(
        f"communication|{edge.first_event}|{edge.second_event}|{edge.address}|{edge.size}"
        for edge in window.communication_edges
    )
    return _digest_lines(lines)


def solver_config_digest(
    *,
    timeout_ms: int,
    max_symbolic_terms: int,
    execute_solver: bool,
    control_flow_closed: bool,
) -> str:
    payload = {
        "timeout_ms": timeout_ms,
        "max_symbolic_terms": max_symbolic_terms,
        "execute_solver": execute_solver,
        "control_flow_closed": control_flow_closed,
        "encoder": "dynamic-checker-symbolic-v1",
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def memory_model_contract_digest(dbt_contract_sha256: str) -> str:
    from .ppo_reduction import ppo_semantic_contract

    payload = {
        "ppo": ppo_semantic_contract().contract_digest,
        "dbt_contract": dbt_contract_sha256,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _reduced_edges(
    original: frozenset[tuple[str, str]],
    removed: tuple[object, ...],
) -> set[tuple[str, str]]:
    return set(original) - {
        (getattr(item, "source_event"), getattr(item, "target_event"))
        for item in removed
    }


def _run_model(
    window_id: str,
    phase: ShadowSolverPhase,
    observation: object,
) -> ShadowSolverRun:
    return ShadowSolverRun(
        window_id=window_id,
        phase=phase,
        result=observation.result,
        reason=observation.reason,
        source_ppo_edges=observation.source_ppo_edge_count,
        target_ppo_edges=observation.target_ppo_edge_count,
        symbolic_terms=observation.formula_terms,
        z3_ast_count=observation.z3_ast_count,
        assertion_count=observation.assertion_count,
        build_time_ms=observation.build_time_ms,
        solver_time_ms=observation.solver_time_ms,
        peak_rss_mb=observation.peak_rss_mb,
        formula_breakdown=dict(observation.formula_breakdown),
        constraint_breakdown=dict(observation.constraint_breakdown),
        variable_counts=dict(observation.variable_counts),
    )


def _not_run(
    window_id: str,
    source_count: int,
    target_count: int,
    reason: str,
    phase: ShadowSolverPhase,
) -> ShadowSolverRun:
    return ShadowSolverRun(
        window_id=window_id,
        phase=phase,
        result="not_run",
        reason=reason,
        source_ppo_edges=source_count,
        target_ppo_edges=target_count,
        symbolic_terms=0,
        z3_ast_count=0,
        assertion_count=0,
        build_time_ms=0,
    )


def _ratio(full: int, reduced: int) -> float:
    return 0.0 if full <= 0 else (full - reduced) / full


def _speedup(full: int, reduced: int) -> float | None:
    if reduced <= 0:
        return None
    return full / reduced


def _result_comparison(
    full: str,
    reduced: str,
    *,
    full_reason: str = "",
    reduced_reason: str = "",
) -> tuple[bool | None, str]:
    if full == reduced:
        if full in _INCOMPLETE_RESULTS and full_reason != reduced_reason:
            return None, "both sides are incomplete but reported different reasons"
        return True, "full and reduced solver statuses match"
    if full in _INCOMPLETE_RESULTS or reduced in _INCOMPLETE_RESULTS:
        return None, "one side is incomplete/resource-limited; not treated as semantic mismatch"
    return False, "full and reduced solver statuses differ"


def build_shadow_solver_run(
    window: AnalysisWindow,
    graph: PpoGraphInput,
    reduction: PpoReductionCertificate,
    *,
    side: str,
    control_flow_closed: bool,
    timeout_ms: int,
    max_symbolic_terms: int,
    execute_solver: bool,
) -> ShadowSolverRun:
    """只运行 full 或 reduced 一侧，供隔离 benchmark worker 使用。"""

    if side not in {"full", "reduced"}:
        raise ValueError(f"unsupported PPO shadow side: {side}")
    replay_started = time.perf_counter()
    replay = replay_ppo_reduction(graph, reduction)
    replay_time_ms = max(0, int((time.perf_counter() - replay_started) * 1000))
    original_source = graph.source_edges
    original_target = graph.target_edges
    reduced_source = _reduced_edges(original_source, reduction.source.removed_edges)
    reduced_target = _reduced_edges(original_target, reduction.target.removed_edges)
    source = original_source if side == "full" else reduced_source
    target = original_target if side == "full" else reduced_target
    phase = ShadowSolverPhase.SOLVER if execute_solver else ShadowSolverPhase.ENCODING
    if not replay.accepted:
        return _not_run(
            window.window_id,
            len(source),
            len(target),
            "PPO replay failed; shadow solver not run",
            phase,
        ).model_copy(update={"ppo_replay_time_ms": replay_time_ms})

    from bmo_check_dynamic.proof import run_symbolic_shadow

    _, observation = run_symbolic_shadow(
        window,
        source_ppo=set(source),
        target_ppo=set(target),
        control_flow_closed=control_flow_closed,
        timeout_ms=timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        execute_solver=execute_solver,
    )
    return _run_model(window.window_id, phase, observation).model_copy(
        update={"ppo_replay_time_ms": replay_time_ms}
    )


def build_shadow_solver_comparison(
    window: AnalysisWindow,
    graph: PpoGraphInput,
    reduction: PpoReductionCertificate,
    *,
    control_flow_closed: bool,
    timeout_ms: int,
    max_symbolic_terms: int,
    execute_solver: bool,
) -> ShadowSolverComparison:
    """运行 full/reduced A/B；replay 失败时两侧都保持 NOT_RUN。"""

    replay = replay_ppo_reduction(graph, reduction)
    full = build_shadow_solver_run(
        window,
        graph,
        reduction,
        side="full",
        control_flow_closed=control_flow_closed,
        timeout_ms=timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        execute_solver=execute_solver,
    )
    reduced = build_shadow_solver_run(
        window,
        graph,
        reduction,
        side="reduced",
        control_flow_closed=control_flow_closed,
        timeout_ms=timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        execute_solver=execute_solver,
    )
    if not replay.accepted:
        result_match, match_reason = None, "reduction replay rejected"
    else:
        result_match, match_reason = _result_comparison(
            full.result,
            reduced.result,
            full_reason=full.reason,
            reduced_reason=reduced.reason,
        )
    rss_reduction = None
    if full.peak_rss_mb is not None and reduced.peak_rss_mb is not None:
        rss_reduction = full.peak_rss_mb - reduced.peak_rss_mb
    return ShadowSolverComparison(
        window_id=window.window_id,
        replay_accepted=replay.accepted,
        full=full,
        reduced=reduced,
        edge_reduction_ratio=_ratio(
            full.source_ppo_edges + full.target_ppo_edges,
            reduced.source_ppo_edges + reduced.target_ppo_edges,
        ),
        term_reduction_ratio=_ratio(full.symbolic_terms, reduced.symbolic_terms),
        build_speedup=_speedup(full.build_time_ms, reduced.build_time_ms),
        solver_speedup=(
            _speedup(full.solver_time_ms or 0, reduced.solver_time_ms or 0)
            if full.solver_time_ms is not None and reduced.solver_time_ms is not None
            else None
        ),
        rss_reduction_mb=rss_reduction,
        result_match=result_match,
        result_match_reason=match_reason,
        used_for_verdict=False,
    )


def build_solver_certificate(
    *,
    trace_sha256: str,
    window: AnalysisWindow,
    graph: PpoGraphInput,
    reduction: PpoReductionCertificate,
    comparison: ShadowSolverComparison,
    dbt_contract_sha256: str,
    timeout_ms: int,
    max_symbolic_terms: int,
    execute_solver: bool,
    control_flow_closed: bool,
) -> ReducedSolverRunCertificate:
    from bmo_check_dynamic.proof import symbolic_candidate_digest

    reduced_source = _reduced_edges(graph.source_edges, reduction.source.removed_edges)
    reduced_target = _reduced_edges(graph.target_edges, reduction.target.removed_edges)
    payload = {
        "window_id": window.window_id,
        "trace_sha256": trace_sha256,
        "window_digest": window_digest(window),
        "full_ppo_digest": _ppo_pair_digest(graph.source_edges, graph.target_edges),
        "reduced_ppo_digest": _ppo_pair_digest(reduced_source, reduced_target),
        "reduction_certificate_digest": reduction.proof_digest,
        "memory_model_contract_digest": memory_model_contract_digest(dbt_contract_sha256),
        "rf_fr_co_candidate_digest": symbolic_candidate_digest(window),
        "solver_config_digest": solver_config_digest(
            timeout_ms=timeout_ms,
            max_symbolic_terms=max_symbolic_terms,
            execute_solver=execute_solver,
            control_flow_closed=control_flow_closed,
        ),
        "full_result": comparison.full.result,
        "reduced_result": comparison.reduced.result,
        "result_match": comparison.result_match,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ReducedSolverRunCertificate(
        window_id=window.window_id,
        phase=comparison.full.phase,
        trace_sha256=trace_sha256,
        window_digest=payload["window_digest"],
        full_ppo_digest=payload["full_ppo_digest"],
        reduced_ppo_digest=payload["reduced_ppo_digest"],
        reduction_certificate_digest=payload["reduction_certificate_digest"],
        memory_model_contract_digest=payload["memory_model_contract_digest"],
        rf_fr_co_candidate_digest=payload["rf_fr_co_candidate_digest"],
        solver_config_digest=payload["solver_config_digest"],
        full_result=comparison.full.result,
        reduced_result=comparison.reduced.result,
        result_match=comparison.result_match,
        comparison_digest=digest,
        diagnostic_only=True,
    )


def replay_solver_certificate(
    window: AnalysisWindow,
    graph: PpoGraphInput,
    reduction: PpoReductionCertificate,
    certificate: ReducedSolverRunCertificate,
    *,
    trace_sha256: str,
    dbt_contract_sha256: str,
    timeout_ms: int,
    max_symbolic_terms: int,
    execute_solver: bool,
    control_flow_closed: bool,
) -> SolverRunReplay:
    """独立重建输入并重跑两侧，验证 solver-level binding。"""

    from bmo_check_dynamic.proof import run_symbolic_shadow, symbolic_candidate_digest

    reasons: list[str] = []
    reduction_replay = replay_ppo_reduction(graph, reduction)
    reduced_source = _reduced_edges(graph.source_edges, reduction.source.removed_edges)
    reduced_target = _reduced_edges(graph.target_edges, reduction.target.removed_edges)
    expected = {
        "window_id": window.window_id,
        "trace_sha256": trace_sha256,
        "window_digest": window_digest(window),
        "full_ppo_digest": _ppo_pair_digest(graph.source_edges, graph.target_edges),
        "reduced_ppo_digest": _ppo_pair_digest(reduced_source, reduced_target),
        "reduction_certificate_digest": reduction.proof_digest,
        "memory_model_contract_digest": memory_model_contract_digest(dbt_contract_sha256),
        "rf_fr_co_candidate_digest": symbolic_candidate_digest(window),
        "solver_config_digest": solver_config_digest(
            timeout_ms=timeout_ms,
            max_symbolic_terms=max_symbolic_terms,
            execute_solver=execute_solver,
            control_flow_closed=control_flow_closed,
        ),
    }
    for field, value in expected.items():
        if getattr(certificate, field) != value:
            reasons.append(f"{field} does not match reconstructed input")
    expected_phase = (
        ShadowSolverPhase.SOLVER if execute_solver else ShadowSolverPhase.ENCODING
    )
    if certificate.phase != expected_phase:
        reasons.append("phase does not match solver configuration")
    payload = {
        **expected,
        "full_result": certificate.full_result,
        "reduced_result": certificate.reduced_result,
        "result_match": certificate.result_match,
    }
    expected_digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if certificate.comparison_digest != expected_digest:
        reasons.append("comparison_digest does not match certificate contents")
    if not reduction_replay.accepted:
        reasons.append("PPO reduction replay failed")

    if not certificate.diagnostic_only:
        reasons.append("solver certificate is not marked diagnostic_only")

    _, full_observation = run_symbolic_shadow(
        window,
        source_ppo=set(graph.source_edges),
        target_ppo=set(graph.target_edges),
        control_flow_closed=control_flow_closed,
        timeout_ms=timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        execute_solver=execute_solver,
    )
    _, reduced_observation = run_symbolic_shadow(
        window,
        source_ppo=reduced_source,
        target_ppo=reduced_target,
        control_flow_closed=control_flow_closed,
        timeout_ms=timeout_ms,
        max_symbolic_terms=max_symbolic_terms,
        execute_solver=execute_solver,
    )
    full_result_matches = full_observation.result == certificate.full_result
    reduced_result_matches = reduced_observation.result == certificate.reduced_result
    if not full_result_matches or not reduced_result_matches:
        reasons.append("replayed full/reduced solver result does not match certificate")
    replayed_match, _ = _result_comparison(
        full_observation.result,
        reduced_observation.result,
        full_reason=full_observation.reason,
        reduced_reason=reduced_observation.reason,
    )
    if replayed_match != certificate.result_match:
        reasons.append("replayed result_match does not match certificate")
    accepted = not reasons
    return SolverRunReplay(
        window_id=window.window_id,
        binding_matches=not any("does not match reconstructed input" in item for item in reasons),
        candidate_domain_matches=(
            certificate.rf_fr_co_candidate_digest == expected["rf_fr_co_candidate_digest"]
        ),
        solver_config_matches=(
            certificate.solver_config_digest == expected["solver_config_digest"]
        ),
        result_matches=full_result_matches and reduced_result_matches,
        accepted=accepted,
        reasons=tuple(reasons),
    )


__all__ = [
    "build_shadow_solver_comparison",
    "build_shadow_solver_run",
    "build_solver_certificate",
    "memory_model_contract_digest",
    "ppo_edges_digest",
    "replay_solver_certificate",
    "solver_config_digest",
    "window_digest",
]
