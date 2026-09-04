from __future__ import annotations

from bmo_check_static.model import (
    MemoryEventReport,
    ProofReason,
    PruningLevel,
    SharedStateReport,
)


ABLATION_LEVELS = (
    PruningLevel.NONE,
    PruningLevel.THREAD_LOCAL,
    PruningLevel.READ_ONLY,
    PruningLevel.DISJOINT,
    PruningLevel.ATOMIC_COVERED,
)


_THREAD_LOCAL_REASONS = {
    ProofReason.TLS_STORAGE,
    ProofReason.SINGLE_MAIN_ROLE,
    ProofReason.UNESCAPED_STACK,
    ProofReason.SEQUENTIAL_BEFORE_CREATE,
    ProofReason.SEQUENTIAL_AFTER_JOIN,
    ProofReason.SEQUENTIAL_MAIN_CALLEE,
    ProofReason.NON_RETURNING_PATH,
}
_ALLOWED_REASONS = {
    PruningLevel.NONE: set(),
    PruningLevel.THREAD_LOCAL: _THREAD_LOCAL_REASONS,
    PruningLevel.READ_ONLY: _THREAD_LOCAL_REASONS
    | {ProofReason.READ_ONLY_AFTER_CREATE},
    PruningLevel.DISJOINT: _THREAD_LOCAL_REASONS
    | {ProofReason.READ_ONLY_AFTER_CREATE, ProofReason.DISJOINT_AFFINE},
    PruningLevel.ATOMIC_COVERED: set(ProofReason),
}


def ablate_shared_state(
    memory_events: MemoryEventReport,
    shared_state: SharedStateReport,
    level: PruningLevel,
) -> SharedStateReport:
    """只撤回 proof object；不重新分类地址，也不改变原始分析事实。"""

    allowed = _ALLOWED_REASONS[level]
    proofs = tuple(proof for proof in shared_state.proofs if proof.reason in allowed)
    removed = {event_id for proof in proofs for event_id in proof.event_ids}
    all_events = {event.id for event in memory_events.events}
    return shared_state.model_copy(
        update={
            "kept_event_ids": tuple(sorted(all_events - removed)),
            "removed_event_ids": tuple(sorted(removed)),
            "proofs": proofs,
        }
    )
