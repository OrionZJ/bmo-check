from __future__ import annotations

from enum import StrEnum

from .manifest import StrictModel


class SolverDiagnosticProfile(StrEnum):
    """仅供 P10 shadow 实验使用的约束消融档位。"""

    FULL = "full"
    PPO_FIXED_RF = "ppo_fixed_rf"
    PPO_RF = "ppo_rf"
    PPO_RF_FR = "ppo_rf_fr"
    PPO_RF_FR_CO = "ppo_rf_fr_co"


class SolverConstraintInventory(StrictModel):
    """一次 shadow 构造实际建立的变量、约束和依赖摘要。

    该摘要描述 solver 负载，不是 memory-model 证明。尤其是 fixed-RF
    和分层消融只用于定位性能瓶颈，不能据此生成 SAFE 或 COUNTEREXAMPLE。
    """

    schema_version: str = "solver-constraint-inventory-v1"
    profile: SolverDiagnosticProfile
    diagnostic_only: bool = True
    event_count: int
    memory_event_count: int
    formula_terms: int
    formula_breakdown: dict[str, int] = {}
    constraint_counts: dict[str, int] = {}
    variable_counts: dict[str, int] = {}
    dependency_counts: dict[str, int] = {}
    fixed_rf_parts: int = 0
    fixed_rf_assigned: int = 0
    fixed_rf_ambiguous: int = 0
    fixed_rf_initial_or_unmatched: int = 0
    fixed_rf_value_unknown: int = 0
    notes: tuple[str, ...] = ()


__all__ = ["SolverDiagnosticProfile", "SolverConstraintInventory"]
