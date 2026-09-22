"""Generate the small P13 CEGAR A/B fixtures.

This is a reproducible diagnostic driver, not a verifier entry point.  Large
real traces are intentionally handled by ``bmo-check cegar-ab`` so that their
trace/certificate bindings remain explicit.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from bmo_check_dynamic.analysis import AnalysisWindow, compare_cegar_modes
from bmo_check_dynamic.analysis.cegar import characterize_cegar_window
from bmo_check_dynamic.analysis.cegar_experiments import compare_candidate_coverage
from bmo_check_dynamic.analysis.communication import CommunicationEdge
from bmo_check_dynamic.analysis.ppo_reduction import (
    build_ppo_graph_input,
    build_ppo_reduction_certificate,
)
from bmo_check_dynamic.model import EventKind, TraceEvent


def _events(name: str) -> tuple[TraceEvent, ...]:
    if name == "synthetic-lb":
        return (
            TraceEvent(1, 1, 0, 0x10, EventKind.LOAD, 0x2000, 4),
            TraceEvent(1, 2, 0, 0x11, EventKind.STORE, 0x1000, 4),
            TraceEvent(2, 1, 0, 0x20, EventKind.LOAD, 0x1000, 4),
            TraceEvent(2, 2, 0, 0x21, EventKind.STORE, 0x2000, 4),
        )
    if name == "small-sb":
        return (
            TraceEvent(1, 1, 0, 0x10, EventKind.STORE, 0x1000, 4),
            TraceEvent(1, 2, 0, 0x11, EventKind.LOAD, 0x2000, 4),
            TraceEvent(2, 1, 0, 0x20, EventKind.STORE, 0x2000, 4),
            TraceEvent(2, 2, 0, 0x21, EventKind.LOAD, 0x1000, 4),
        )
    raise ValueError(f"unknown fixture: {name}")


def _window(name: str) -> AnalysisWindow:
    events = _events(name)
    edges = tuple(
        CommunicationEdge(
            first_event=left.event_id,
            second_event=right.event_id,
            address=left.address,
            size=min(left.size, right.size),
        )
        for left in events
        for right in events
        if left.thread_id != right.thread_id
        and left.overlaps(right)
        and (left.kind.is_write or right.kind.is_write)
    )
    return AnalysisWindow(name, events, edges)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", choices=("synthetic-lb", "small-sb"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-search-states", type=int, default=10_000)
    parser.add_argument("--max-local-queries", type=int, default=100)
    parser.add_argument("--local-timeout-ms", type=int, default=1_000)
    parser.add_argument("--encoding-only", action="store_true")
    args = parser.parse_args()

    window = _window(args.fixture)
    graph = build_ppo_graph_input(window)
    certificate, replay = build_ppo_reduction_certificate(graph)
    if not replay.accepted:
        raise RuntimeError("fixture reduction replay failed")
    report = compare_cegar_modes(
        window,
        fixture=args.fixture,
        reduction_certificate=certificate,
        max_cycle_length=8,
        max_search_states=args.max_search_states,
        max_local_queries=args.max_local_queries,
        local_timeout_ms=args.local_timeout_ms,
        execute_local_solver=not args.encoding_only,
    )
    canonical = characterize_cegar_window(
        window,
        reduction_certificate=certificate,
        max_cycle_length=8,
        max_search_states=args.max_search_states,
        max_local_queries=args.max_local_queries,
        max_generated_candidates=args.max_local_queries,
        local_timeout_ms=args.local_timeout_ms,
        execute_local_solver=not args.encoding_only,
        canonicalize=True,
        enable_blocking=True,
    )
    coverage = compare_candidate_coverage(
        window,
        canonical,
        certificate=certificate,
        max_cycle_length=8,
        max_search_states=args.max_search_states,
        max_candidates=args.max_local_queries,
    )
    report = report.model_copy(update={"coverage": coverage})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
