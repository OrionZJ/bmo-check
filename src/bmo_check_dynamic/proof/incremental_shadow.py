from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Mapping, Sequence

import z3

from .relations import Edge


@dataclass(frozen=True, slots=True)
class IncrementalShadowCheck:
    """一条候选约束在共享完整公式上的诊断结果。"""

    result: str
    reason: str
    build_ms: int
    solver_ms: int | None
    added_assertions: int
    added_ast_nodes: int
    push_pop_ms: int
    peak_rss_mb: float | None


@dataclass(slots=True)
class IncrementalShadowSession:
    """共享同一份完整 shadow 公式，只在 push/pop 里替换候选环条件。

    该 session 只由 shadow API 创建，不会传给正式 checker。每次查询都在
    push/pop 中临时加入精确关系条件和候选边选择器，避免前一个候选污染后一个。
    """

    solver: z3.Solver
    relation_conditions: Mapping[
        str, Sequence[tuple[Edge, str, z3.BoolRef]]
    ]
    selected_edges: Mapping[Edge, z3.BoolRef]
    window_event_ids: tuple[str, ...]
    base_formula_terms: int
    base_assertions: int
    base_ast_nodes: int
    base_build_ms: int
    source_ppo_edge_count: int
    target_ppo_edge_count: int

    @staticmethod
    def _ast_size(expression: z3.AstRef) -> int:
        count = 0
        pending = [expression]
        while pending:
            current = pending.pop()
            count += 1
            pending.extend(current.children())
        return count

    @staticmethod
    def _peak_rss_mb() -> float | None:
        try:
            import resource

            # Linux/WSL returns KiB for ru_maxrss; the diagnostic runs here are Linux-only.
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        except (ImportError, OSError):  # pragma: no cover - platform-specific fallback.
            return None

    def check_candidate(
        self,
        *,
        required_source_cycle_edges: frozenset[Edge],
        required_source_cycle_relations: tuple[
            tuple[str, str, str, tuple[str, ...]], ...
        ],
        timeout_ms: int,
    ) -> IncrementalShadowCheck:
        """只在当前 stack frame 加入候选约束，退出前一定 pop 掉。"""

        build_started = monotonic()
        assumptions: list[z3.BoolRef] = []
        for source, target, relation_kind, relation_ids in required_source_cycle_relations:
            exact_conditions: list[z3.BoolRef] = []
            for relation_id in relation_ids:
                for edge, kind, condition in self.relation_conditions.get(
                    relation_id, ()
                ):
                    normalized_kind = {"rf_fixed": "rf"}.get(kind, kind)
                    if (
                        edge == (source, target)
                        and normalized_kind == relation_kind
                    ):
                        exact_conditions.append(condition)
            if not exact_conditions:
                return IncrementalShadowCheck(
                    result="unknown",
                    reason=(
                        "candidate relation is absent from the shared full-window "
                        f"formula: {relation_kind} {source}->{target}"
                    ),
                    build_ms=0,
                    solver_ms=None,
                    added_assertions=0,
                    added_ast_nodes=0,
                    push_pop_ms=0,
                    peak_rss_mb=self._peak_rss_mb(),
                )
            assumptions.append(z3.Or(*exact_conditions))

        missing_edges = set(required_source_cycle_edges) - set(self.selected_edges)
        if missing_edges:
            return IncrementalShadowCheck(
                result="unknown",
                reason=(
                    "candidate source-cycle edge is absent from the shared formula: "
                    + ", ".join(f"{left}->{right}" for left, right in sorted(missing_edges))
                ),
                build_ms=0,
                solver_ms=None,
                added_assertions=0,
                added_ast_nodes=0,
                push_pop_ms=0,
                peak_rss_mb=self._peak_rss_mb(),
            )
        assumptions.extend(
            self.selected_edges[edge]
            for edge in sorted(required_source_cycle_edges)
        )
        ast_nodes = sum(self._ast_size(item) for item in assumptions)

        self.solver.set(timeout=timeout_ms)
        frame_started = monotonic()
        self.solver.push()
        push_ms = max(0, int((monotonic() - frame_started) * 1000))
        try:
            if assumptions:
                self.solver.add(*assumptions)
            build_ms = max(0, int((monotonic() - build_started) * 1000))
            started = monotonic()
            status = self.solver.check()
            solver_ms = max(0, int((monotonic() - started) * 1000))
            if status == z3.sat:
                result, reason = "sat", ""
            elif status == z3.unsat:
                result, reason = "unsat", ""
            else:
                result, reason = "unknown", self.solver.reason_unknown()
        finally:
            # pop 无论 SAT、UNSAT、UNKNOWN 或异常都执行；下一候选看不到本次条件。
            pop_started = monotonic()
            self.solver.pop()
            pop_ms = max(0, int((monotonic() - pop_started) * 1000))
        push_pop_ms = push_ms + pop_ms

        return IncrementalShadowCheck(
            result=result,
            reason=reason,
            build_ms=build_ms,
            solver_ms=solver_ms,
            added_assertions=len(assumptions),
            added_ast_nodes=ast_nodes,
            push_pop_ms=push_pop_ms,
            peak_rss_mb=self._peak_rss_mb(),
        )
