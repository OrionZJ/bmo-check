from .communication import (
    CompactCommunicationEdges,
    CommunicationEdge,
    CommunicationEdgeSink,
    CommunicationEndpoint,
    CommunicationScanStats,
    find_communication_edges,
    max_communication_page_events,
    prepare_communication_scan_stats,
    thread_handoffs_complete,
)
from .partition import analyze_application_partition
from .coverage import build_trace_coverage, coverage_state, digest_edges, iter_edges
from .lifecycle_adapter import characterize_trace_lifecycle
from .lifecycle_schema_adapter import (
    LifecycleMetadataError,
    lifecycle_metadata_to_ledger,
)
from .site import locate_instruction_site
from .windows import (
    AnalysisWindow,
    WindowEventInclusion,
    WindowInclusionReason,
    build_windows,
)
from .slice_contract import (
    build_obligation_inventory,
    plan_obligation_preserving_split,
)
from .slice_candidates import build_candidate_slice, build_candidate_slices
from .obligation_bottleneck import characterize_obligation_bottleneck
from .cycle_relevance import characterize_cycle_relevance
from .ppo_reduction import (
    PpoGraphInput,
    PpoReachabilityIndex,
    build_ppo_graph_input,
    build_ppo_reduction,
    build_ppo_reduction_certificate,
    profile_ppo_reduction_window,
    build_profiled_ppo_reduction_window,
    ppo_semantic_contract,
    ppo_certificate_digest,
    replay_ppo_reduction,
)
from .ppo_cache import (
    REDUCTION_ALGORITHM_VERSION,
    load_ppo_certificate_cache,
    ppo_certificate_cache_key,
    save_ppo_certificate_cache,
)
from .shadow_solver import (
    build_shadow_solver_comparison,
    build_shadow_solver_run,
    build_solver_certificate,
    memory_model_contract_digest,
    ppo_edges_digest,
    replay_solver_certificate,
    solver_config_digest,
    window_digest,
)
from .graph_first import (
    characterize_graph_first_window,
    graph_first_trace,
    replay_candidate_cycle,
)
from .cegar import (
    blocking_constraint_applies,
    build_blocking_constraint,
    canonicalize_cycle_skeleton,
    characterize_cegar_window,
    replay_blocking_constraint,
)
from .solver_benchmark import run_isolated_solver_benchmark
from .window_diagnostics import (
    WindowCharacterizationReport,
    WindowDiagnostics,
    WindowEventInclusion as WindowEventInclusionDiagnostic,
    characterize_window,
    characterize_windows,
)
from .window_graph_diagnostics import characterize_window_graph

__all__ = [
    "AnalysisWindow",
    "WindowEventInclusion",
    "WindowInclusionReason",
    "CommunicationEdge",
    "CommunicationEdgeSink",
    "CompactCommunicationEdges",
    "CommunicationEndpoint",
    "CommunicationScanStats",
    "build_windows",
    "WindowDiagnostics",
    "WindowCharacterizationReport",
    "WindowEventInclusionDiagnostic",
    "characterize_window",
    "characterize_windows",
    "characterize_window_graph",
    "find_communication_edges",
    "max_communication_page_events",
    "prepare_communication_scan_stats",
    "thread_handoffs_complete",
    "locate_instruction_site",
    "analyze_application_partition",
    "build_obligation_inventory",
    "plan_obligation_preserving_split",
    "build_candidate_slice",
    "build_candidate_slices",
    "characterize_obligation_bottleneck",
    "characterize_cycle_relevance",
    "PpoGraphInput",
    "PpoReachabilityIndex",
    "build_ppo_graph_input",
    "build_ppo_reduction",
    "build_ppo_reduction_certificate",
    "profile_ppo_reduction_window",
    "build_profiled_ppo_reduction_window",
    "ppo_semantic_contract",
    "ppo_certificate_digest",
    "replay_ppo_reduction",
    "REDUCTION_ALGORITHM_VERSION",
    "ppo_certificate_cache_key",
    "save_ppo_certificate_cache",
    "load_ppo_certificate_cache",
    "build_shadow_solver_comparison",
    "build_shadow_solver_run",
    "build_solver_certificate",
    "memory_model_contract_digest",
    "ppo_edges_digest",
    "replay_solver_certificate",
    "solver_config_digest",
    "window_digest",
    "run_isolated_solver_benchmark",
    "characterize_graph_first_window",
    "graph_first_trace",
    "replay_candidate_cycle",
    "canonicalize_cycle_skeleton",
    "build_blocking_constraint",
    "blocking_constraint_applies",
    "characterize_cegar_window",
    "replay_blocking_constraint",
    "build_trace_coverage",
    "coverage_state",
    "digest_edges",
    "iter_edges",
    "characterize_trace_lifecycle",
    "LifecycleMetadataError",
    "lifecycle_metadata_to_ledger",
]
