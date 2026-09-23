from __future__ import annotations

import hashlib
import json
import tempfile
import time
from datetime import datetime, timezone
from dataclasses import fields
from collections.abc import Callable
from itertools import chain
from pathlib import Path

from bmo_check_core import (
    ModuleId,
    TraceId,
    TraceImportLedger,
    TraceImportState,
    UnknownKind,
)
from bmo_check_dynamic import __version__
from bmo_check_dynamic.analysis import (
    CompactCommunicationEdges,
    CommunicationEdge,
    CommunicationScanStats,
    analyze_application_partition,
    build_windows,
    find_communication_edges,
    max_communication_page_events,
    prepare_communication_scan_stats,
    WindowCharacterizationReport,
    characterize_windows,
    build_candidate_slices,
    plan_obligation_preserving_split,
    characterize_obligation_bottleneck,
    characterize_cycle_relevance,
    build_ppo_graph_input,
    build_ppo_reduction,
    build_ppo_reduction_certificate,
    build_profiled_ppo_reduction_window,
    replay_ppo_reduction,
    build_shadow_solver_comparison,
    build_shadow_solver_run,
    build_solver_certificate,
    replay_solver_certificate,
    characterize_graph_first_window,
    characterize_cegar_window,
    compare_cegar_modes,
    window_digest,
)
from bmo_check_dynamic.analysis.coverage import build_trace_coverage
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.analysis.communication import CommunicationLimitError
from bmo_check_dynamic.model import (
    ApplicationPartitionEvidence,
    DynamicCertificate,
    EventKind,
    TraceCoverage,
    TraceManifest,
    TraceScope,
    TraceVerdict,
    SliceCandidateReport,
    SlicePlanReport,
    TraceObligationBottleneckReport,
    TraceCycleRelevanceReport,
    TracePpoReductionCertificate,
    PpoReductionReplay,
    TracePpoReductionReport,
    TracePpoReductionReplayReport,
    TracePpoCertificateGenerationReport,
    PpoCertificateGenerationReport,
    ReducedSolverRunCertificate,
    ShadowSolverComparison,
    TraceReducedSolverRunCertificate,
    TraceShadowSolverReport,
    TraceSolverReplayReport,
    SolverRunReplay,
    BenchmarkSide,
    ShadowSolverPhase,
    TraceShadowSolverSideReport,
    SolverDiagnosticProfile,
    TraceGraphFirstReport,
    TraceCegarReport,
    CegarExperimentReport,
    CegarExperimentMode,
    CandidateDiscoveryResourcePolicy,
)
from bmo_check_dynamic.proof import (
    characterize_symbolic_encoding,
    check_window,
    load_supported_contract,
)
from bmo_check_dynamic.storage import TraceStore, TraceStoreError
from bmo_check_dynamic.trace import TraceReader, trace_digest, validate_trace
from bmo_check_dynamic.trace import build_dynamic_certificate_binding
from bmo_check_dynamic.trace.format import event_files


class _WindowInspectionComplete(Exception):
    """内部控制流：窗口诊断完成后跳过 proof，释放临时 TraceStore。"""

    def __init__(self, report: WindowCharacterizationReport) -> None:
        super().__init__("window inspection completed")
        self.report = report


class _SliceCandidateInspectionComplete(Exception):
    """窗口候选切片生成后跳过 proof。"""

    def __init__(self, report: SliceCandidateReport) -> None:
        super().__init__("slice candidate inspection completed")
        self.report = report


class _SlicePlanInspectionComplete(Exception):
    """obligation graph plan 完成后跳过 proof。"""

    def __init__(self, report: SlicePlanReport) -> None:
        super().__init__("slice plan inspection completed")
        self.report = report


class _ObligationBottleneckInspectionComplete(Exception):
    """P6 obligation 表征完成后跳过 proof。"""

    def __init__(self, report: TraceObligationBottleneckReport) -> None:
        super().__init__("obligation bottleneck inspection completed")
        self.report = report


class _CycleRelevanceInspectionComplete(Exception):
    """P7 cycle relevance 表征完成后跳过 proof。"""

    def __init__(self, report: TraceCycleRelevanceReport) -> None:
        super().__init__("cycle relevance inspection completed")
        self.report = report


class _PpoReductionInspectionComplete(Exception):
    """P8 reduction certificate 生成后跳过正式 proof。"""

    def __init__(self, report: TracePpoReductionReport) -> None:
        super().__init__("PPO reduction inspection completed")
        self.report = report


class _PpoCertificateProfileInspectionComplete(Exception):
    """certificate profiling 完成后跳过正式 proof。"""

    def __init__(self, report: TracePpoCertificateGenerationReport) -> None:
        super().__init__("PPO certificate profiling completed")
        self.report = report


class _PpoReplayInspectionComplete(Exception):
    """P8 replay 完成后跳过正式 proof。"""

    def __init__(self, report: TracePpoReductionReplayReport) -> None:
        super().__init__("PPO reduction replay completed")
        self.report = report


class _PpoSolverInspectionComplete(Exception):
    """P9 shadow solver 完成后跳过正式 proof。"""

    def __init__(
        self,
        report: TraceShadowSolverReport,
        certificate: TraceReducedSolverRunCertificate,
    ) -> None:
        super().__init__("PPO shadow solver inspection completed")
        self.report = report
        self.certificate = certificate


class _PpoSolverReplayInspectionComplete(Exception):
    """P9 solver-level certificate replay 完成后跳过正式 proof。"""

    def __init__(self, report: TraceSolverReplayReport) -> None:
        super().__init__("PPO shadow solver replay completed")
        self.report = report


class _PpoSolverSideInspectionComplete(Exception):
    """P9.5 worker 完成单侧 shadow run 后跳过正式 proof。"""

    def __init__(self, report: TraceShadowSolverSideReport) -> None:
        super().__init__("PPO shadow solver side inspection completed")
        self.report = report


class _GraphFirstInspectionComplete(Exception):
    """graph-first 候选环诊断完成后跳过正式 proof。"""

    def __init__(self, report: TraceGraphFirstReport) -> None:
        super().__init__("graph-first shadow inspection completed")
        self.report = report


class _CegarInspectionComplete(Exception):
    """P12 CEGAR shadow 完成后跳过正式 proof。"""

    def __init__(self, report: TraceCegarReport) -> None:
        super().__init__("CEGAR shadow inspection completed")
        self.report = report


class _CegarExperimentInspectionComplete(Exception):
    """P13 A/B 完成后跳过正式 proof。"""

    def __init__(self, report: CegarExperimentReport) -> None:
        super().__init__("P13 CEGAR comparison completed")
        self.report = report


def _scan_communication_edges(
    store: TraceStore,
    *,
    limit: int,
    max_active_events: int,
    required_pc_range: tuple[int, int] | None,
    edge_pc_range: tuple[int, int] | None,
    stats: CommunicationScanStats,
) -> CompactCommunicationEdges | tuple[CommunicationEdge, ...]:
    """把正常扫描结果压缩保存；被测试替换的旧扫描器仍可返回 tuple。"""

    compact = CompactCommunicationEdges()
    yielded = tuple(
        find_communication_edges(
            store,
            limit=limit,
            max_active_events=max_active_events,
            required_pc_range=required_pc_range,
            edge_pc_range=edge_pc_range,
            stats=stats,
            edge_sink=compact,
        )
    )
    return yielded if yielded else compact



def analyze_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
    _window_observer: Callable[..., None] | None = None,
    _window_reconstruction_sink: list[float] | None = None,
) -> DynamicCertificate:
    config = config or DynamicConfig()
    config.validate()
    manifest = TraceManifest.load(trace_dir / "manifest.json")
    validation = validate_trace(trace_dir)
    unknowns = list(validation.reasons)
    unknown_kinds: list[UnknownKind] = []
    contract_sha256 = _file_digest(dbt_contract)
    contract, contract_error = load_supported_contract(dbt_contract)
    if contract_error is not None:
        unknowns.append(contract_error)
    syscall_ordering = (
        getattr(getattr(contract, "translation", None), "syscall", None)
        if contract is not None
        else None
    )
    futex_requires_contract = (
        int(EventKind.FUTEX_WAIT) in validation.event_kinds
        and (
            contract_error is not None
            or syscall_ordering is None
            or syscall_ordering.target_ordering == "unknown"
        )
    )
    if futex_requires_contract:
        unknown_kinds.append(UnknownKind.UNKNOWN_SYNCHRONIZATION)
        unknowns.append(
            "FUTEX_WAIT ordering is not declared by the bound DBT contract"
        )
    if unknowns:
        # 校验已经发现截断时，再次解码会抛异常并丢掉 UNKNOWN 报告。
        # 失败轨迹也不能凭一个局部 witness 越过完整性门槛。
        return DynamicCertificate(
            verdict=TraceVerdict.UNKNOWN,
            scope=TraceScope(
                trace_ids=(manifest.trace_id,),
                trace_sha256=(trace_digest(trace_dir),),
                executable=manifest.executable,
                libraries=manifest.libraries,
                commands=(manifest.command,),
                working_directories=(manifest.working_directory,),
                analysis_scope="application" if config.application_only else "full",
            ),
            dbt_contract_sha256=contract_sha256,
            analyzer_version=__version__,
            trace_complete=validation.structurally_complete,
            event_count=validation.event_count,
            thread_count=len(validation.thread_ids),
            object_count=0,
            unique_pc_count=0,
            communication_edge_count=0,
            indirect_target_count=0,
            unknown_kinds=tuple(dict.fromkeys(unknown_kinds)),
            unknown_reasons=tuple(unknowns),
            assumptions=("analysis stopped at preflight; analysis counts are unavailable",),
        )
    if (
        validation.event_count > config.max_object_events
        and len(validation.thread_ids) > 1
    ):
        unknowns.append(
            "object identity materialization requires "
            f"{validation.event_count} events, exceeding budget "
            f"{config.max_object_events}"
        )
        return _unknown_certificate(
            manifest,
            validation,
            trace_dir,
            config,
            contract_sha256,
            tuple(unknowns),
            event_count=validation.event_count,
            assumption=(
                "analysis stopped before event storage and object identity "
                "materialization; communication counts are unavailable"
            ),
        )
    temporary: tempfile.TemporaryDirectory[str] | None = None
    if config.database_path is None:
        temporary = tempfile.TemporaryDirectory(prefix="bmo-check-")
        database_path = Path(temporary.name) / "trace.duckdb"
    else:
        database_path = config.database_path
    try:
        with TraceStore(
            database_path, memory_limit_mb=config.database_memory_limit_mb
        ) as store:
            import_binding = _trace_import_ledger(trace_dir, manifest, config)
            try:
                store.begin_import(import_binding)
            except TraceStoreError as error:
                return _unknown_certificate(
                    manifest,
                    validation,
                    trace_dir,
                    config,
                    contract_sha256,
                    (f"trace store import binding failed: {error}",),
                    event_count=0,
                    assumption="trace storage subject could not be established",
                )
            readers = (TraceReader(path) for path in event_files(trace_dir))
            _count, storage_unknowns = store.add_events(
                chain.from_iterable(readers),
                max_pages_per_access=config.max_pages_per_access,
                batch_size=config.batch_size,
            )
            unknowns.extend(storage_unknowns)
            stored_event_count = store.event_count()
            if (
                stored_event_count > config.max_object_events
                and len(validation.thread_ids) > 1
            ):
                unknowns.append(
                    "object identity materialization requires "
                    f"{stored_event_count} events, exceeding budget "
                    f"{config.max_object_events}"
                )
                return _unknown_certificate(
                    manifest,
                    validation,
                    trace_dir,
                    config,
                    contract_sha256,
                    tuple(unknowns),
                    event_count=stored_event_count,
                    assumption=(
                        "analysis stopped before object identity materialization; "
                        "communication counts are unavailable"
                    ),
                )
            try:
                object_count = store.materialize_objects()
            except Exception as error:
                if not _is_resource_exhaustion(error):
                    raise
                unknowns.append(
                    "object identity materialization exhausted resources: "
                    f"{error}"
                )
                return _unknown_certificate(
                    manifest,
                    validation,
                    trace_dir,
                    config,
                    contract_sha256,
                    tuple(unknowns),
                    event_count=store.event_count(),
                    assumption=(
                        "analysis stopped when object identity materialization hit "
                        "the storage memory limit; communication counts are unavailable"
                    ),
                )
            try:
                store.complete_import(trace_dir)
            except TraceStoreError as error:
                return _unknown_certificate(
                    manifest,
                    validation,
                    trace_dir,
                    config,
                    contract_sha256,
                    (f"trace import completeness failed: {error}",),
                    event_count=store.event_count(),
                    assumption=(
                        "trace storage could not independently close manifest, "
                        "chunk, event, object and thread inventories"
                    ),
                )
            if len(validation.thread_ids) == 1 and not futex_requires_contract:
                coverage = build_trace_coverage(
                    store,
                    import_ledger=store.import_ledger(),
                    communication_edges=(),
                    scan_stats=CommunicationScanStats(complete=True),
                    windows=(),
                    window_unknowns=(),
                )
                return _single_thread_certificate(
                    manifest,
                    validation,
                    trace_dir,
                    config,
                    contract_sha256,
                    contract.contract_version if contract else "invalid",
                    coverage,
                    object_count=object_count,
                    unique_pc_count=int(
                        store.connection.execute(
                            "SELECT count(DISTINCT pc) FROM events WHERE pc <> 0"
                        ).fetchone()[0]
                    ),
                    indirect_target_count=int(
                        store.connection.execute(
                            "SELECT count(*) FROM events WHERE kind = 32"
                        ).fetchone()[0]
                    ),
                )
            application_partition = analyze_application_partition(
                store, trace_dir / "modules.tsv", manifest.executable.path
            )
            external_runtime_edges = 0
            communication_edges_complete = True
            scan_stats = CommunicationScanStats()
            if (
                config.application_only
                and application_partition.module_start >= application_partition.module_end
            ):
                # 没有主 ELF 的 PC 范围时，不能把外部运行库事件误当成应用事件。
                unknowns.append("application-only scope requires a known main-module range")
                raw_edge_sample = ()
                edge_sample = ()
                communication_edges_complete = False
            else:
                required_pc_range = None
                if config.application_only:
                    application_memory = int(
                        store.connection.execute(
                            """
                            SELECT count(*) FROM events
                            WHERE kind IN (1, 2, 3) AND pc >= ? AND pc < ?
                            """,
                            (
                                application_partition.module_start,
                                application_partition.module_end,
                            ),
                        ).fetchone()[0]
                    )
                    # 没有主 ELF 访存时仍扫描全部页，保留“只有运行库边”的
                    # 审计计数；有主 ELF 访存时才可安全地跳过不可能进入
                    # application scope 的热页。
                    if application_memory:
                        required_pc_range = (
                            application_partition.module_start,
                            application_partition.module_end,
                        )
                prepare_communication_scan_stats(
                    store,
                    required_pc_range=required_pc_range,
                    stats=scan_stats,
                )
                max_page_events = max_communication_page_events(
                    store, required_pc_range=required_pc_range
                )
                if max_page_events > config.max_communication_active_events:
                    reason = (
                        "communication page has "
                        f"{max_page_events} events, exceeding active-set limit "
                        f"{config.max_communication_active_events}"
                    )
                    unknowns.append(reason)
                    scan_stats.resource_limited_event_count = (
                        scan_stats.candidate_event_count
                    )
                    scan_stats.resource_limit_reason = reason
                    raw_edge_sample = ()
                    communication_edges_complete = False
                else:
                    try:
                        raw_edge_sample = _scan_communication_edges(
                            store,
                            limit=config.max_communication_edges + 1,
                            max_active_events=config.max_communication_active_events,
                            required_pc_range=required_pc_range,
                            edge_pc_range=(
                                (
                                    application_partition.module_start,
                                    application_partition.module_end,
                                )
                                if config.application_only
                                else None
                            ),
                            stats=scan_stats,
                        )
                    except CommunicationLimitError as error:
                        unknowns.append(str(error))
                        if scan_stats.resource_limited_event_count is None:
                            scan_stats.resource_limited_event_count = (
                                scan_stats.candidate_event_count
                            )
                        if scan_stats.resource_limit_reason is None:
                            scan_stats.resource_limit_reason = str(error)
                        raw_edge_sample = ()
                        communication_edges_complete = False
                edge_sample = raw_edge_sample
                external_runtime_edges = scan_stats.external_edges
                if scan_stats.complete:
                    communication_edges_complete = True
            raw_edge_count = scan_stats.total_edges
            edge_count = (
                edge_sample.edge_count
                if isinstance(edge_sample, CompactCommunicationEdges)
                else len(edge_sample)
            )
            edge_limit_exceeded = edge_count > config.max_communication_edges
            if edge_limit_exceeded:
                unknowns.append(
                    "communication edge scan exceeds "
                    f"{config.max_communication_edges} scoped edges"
                )
                communication_edges_complete = False
                edges = ()
            else:
                # 扫描器已经按页和地址稳定地产生边；窗口切分不依赖字典序。
                # 不再复制一份 sorted tuple，避免大轨迹同时保留 list、tuple 和边对象。
                edges = edge_sample
            if edge_limit_exceeded:
                # 上面的门已经决定 UNKNOWN；不再把不受证明约束的边送进
                # biconnected graph，避免“已知失败”先变成内存峰值。
                windows, window_unknowns = (), ()
            else:
                window_started = time.perf_counter()
                windows, window_unknowns = build_windows(
                    store, edges, max_events=config.max_window_events
                )
                if _window_reconstruction_sink is not None:
                    _window_reconstruction_sink.append(
                        (time.perf_counter() - window_started) * 1000.0
                    )
            unknowns.extend(window_unknowns)
            if _window_observer is not None:
                # 诊断观察必须发生在同一条 pipeline、同一个完整窗口集合上；
                # observer 不能修改输入，抛出内部完成信号后才会跳过 proof。
                _window_observer(
                    manifest,
                    validation,
                    store.event_count(),
                    scan_stats,
                    edge_sample,
                    windows,
                    window_unknowns,
                )
            coverage = build_trace_coverage(
                store,
                import_ledger=store.import_ledger(),
                communication_edges=edge_sample,
                scan_stats=scan_stats,
                windows=windows,
                window_unknowns=window_unknowns,
            )
            results = tuple(
                check_window(
                    window,
                    max_executions=config.max_executions,
                    control_flow_closed=manifest.control_flow_closed,
                    timeout_ms=config.solver_timeout_ms,
                    max_symbolic_terms=config.max_symbolic_terms,
                )
                for window in windows
            )
            unknowns.extend(
                result.reason for result in results if result.status == "unknown"
            )
            if not communication_edges_complete:
                # 分区、handoff 或空窗口只能说明某个局部条件，不能代替
                # communication graph 的完整枚举；否则相关边被遗漏时会误报 TRACE_SAFE。
                unknown_kinds.append(UnknownKind.INCOMPLETE_RECOVERY)
                unknowns.append(
                    "communication graph is incomplete; trace-scoped ordering cannot be closed"
                )
            if unknowns:
                verdict = TraceVerdict.UNKNOWN
            elif any(result.status == "counterexample" for result in results):
                verdict = TraceVerdict.COUNTEREXAMPLE
            else:
                verdict = TraceVerdict.TRACE_SAFE
            indirect_count = int(
                store.connection.execute("SELECT count(*) FROM events WHERE kind = 32").fetchone()[0]
            )
            assumptions = [
                f"DBT contract: {contract.contract_version if contract else 'invalid'}",
                "ordinary RVWMO dependencies are omitted from the target model",
                "lifecycle tickets do not establish target memory ordering",
                "the proof applies only to concrete addresses and the recorded event skeleton",
            ]
            if config.application_only:
                assumptions.append(
                    "application scope excludes external-module communication edges; "
                    "the DBT runtime contract must preserve their LOCK/XCHG and Fence paths"
                )
                if not communication_edges_complete:
                    assumptions.append(
                        "communication scanning did not close; application partition and "
                        "thread handoffs cannot replace the missing communication ledger"
                    )
            return DynamicCertificate(
                schema_version="dynamic-certificate-v2",
                verdict=verdict,
                scope=TraceScope(
                    trace_ids=(manifest.trace_id,),
                    trace_sha256=(trace_digest(trace_dir),),
                    executable=manifest.executable,
                    libraries=manifest.libraries,
                    commands=(manifest.command,),
                    working_directories=(manifest.working_directory,),
                    analysis_scope="application" if config.application_only else "full",
                ),
                dbt_contract_sha256=contract_sha256,
                analyzer_version=__version__,
                trace_complete=validation.structurally_complete,
                event_count=store.event_count(),
                thread_count=len(validation.thread_ids),
                object_count=object_count,
                unique_pc_count=int(
                    store.connection.execute(
                        "SELECT count(DISTINCT pc) FROM events WHERE pc <> 0"
                    ).fetchone()[0]
                ),
                communication_edge_count=raw_edge_count,
                external_runtime_edge_count=external_runtime_edges,
                communication_edges_complete=communication_edges_complete,
                indirect_target_count=indirect_count,
                application_partition=application_partition,
                windows=results,
                unknown_kinds=tuple(dict.fromkeys(unknown_kinds)),
                unknown_reasons=tuple(dict.fromkeys(unknowns)),
                assumptions=tuple(assumptions),
                coverage=coverage,
                binding=build_dynamic_certificate_binding(
                    trace_dir,
                    manifest,
                    coverage,
                    dbt_contract_sha256=contract_sha256,
                    config=config,
                    analyzer_version=__version__,
                ),
            )
    finally:
        if temporary is not None:
            temporary.cleanup()


def characterize_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
) -> WindowCharacterizationReport:
    """只执行导入、通信扫描和窗口构造，不启动 proof checker。"""

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        report = characterize_windows(
            manifest,
            validation,
            stored_event_count,
            scan_stats,
            edges,
            windows,
            window_unknowns,
            symbolic=tuple(characterize_symbolic_encoding(window) for window in windows),
        )
        raise _WindowInspectionComplete(report)

    try:
        certificate = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _WindowInspectionComplete as complete:
        return complete.report

    # preflight/storage 失败会在窗口阶段之前返回 certificate；不伪造窗口
    # 统计，只记录没有到达窗口构造的原因。
    return WindowCharacterizationReport(
        trace_id=certificate.scope.trace_ids[0],
        trace_complete=certificate.trace_complete,
        event_count=certificate.event_count,
        raw_event_count=None,
        thread_count=certificate.thread_count,
        candidate_page_count=0,
        candidate_event_count=0,
        scanned_event_count=None,
        filtered_event_count=0,
        communication_edge_count=certificate.communication_edge_count,
        scoped_edge_count=0,
        external_edge_count=certificate.external_runtime_edge_count,
        communication_complete=certificate.communication_edges_complete,
        analysis_reached_windows=False,
        reasons=certificate.unknown_reasons,
    )


def candidate_slice_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
) -> SliceCandidateReport:
    """生成 P3 候选切片报告，但不把候选交给 proof checker。"""

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        report = SliceCandidateReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            windows=build_candidate_slices(tuple(windows)),
            reasons=tuple(window_unknowns),
        )
        raise _SliceCandidateInspectionComplete(report)

    try:
        certificate = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _SliceCandidateInspectionComplete as complete:
        return complete.report

    return SliceCandidateReport(
        trace_id=certificate.scope.trace_ids[0],
        trace_complete=certificate.trace_complete,
        analysis_reached_windows=False,
        reasons=certificate.unknown_reasons,
    )


def slice_plan_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
) -> SlicePlanReport:
    """计算 obligation 图的保守分区计划，不把分区交给 proof。"""

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        report = SlicePlanReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            plans=tuple(plan_obligation_preserving_split(window) for window in windows),
            reasons=tuple(window_unknowns),
        )
        raise _SlicePlanInspectionComplete(report)

    try:
        certificate = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _SlicePlanInspectionComplete as complete:
        return complete.report

    return SlicePlanReport(
        trace_id=certificate.scope.trace_ids[0],
        trace_complete=certificate.trace_complete,
        analysis_reached_windows=False,
        reasons=certificate.unknown_reasons,
    )


def obligation_bottleneck_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
) -> TraceObligationBottleneckReport:
    """表征 obligation 网络，不启动 proof checker。

    该 route 复用普通 trace pipeline 的导入、通信扫描和窗口边界。P6 只把
    已经进入 checker 的窗口关系写成诊断报告；它不会删除事件、改变分区，
    也不会把诊断结果送回 ``check_window``。
    """

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        report = TraceObligationBottleneckReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            windows=tuple(
                characterize_obligation_bottleneck(window) for window in windows
            ),
            reasons=tuple(window_unknowns),
        )
        raise _ObligationBottleneckInspectionComplete(report)

    try:
        certificate = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _ObligationBottleneckInspectionComplete as complete:
        return complete.report

    # 预检、导入或通信扫描在构造窗口前失败时，只能说明没有到达 P6；
    # 这里保留 pipeline 已经记录的原因，不伪造空的 obligation 图。
    return TraceObligationBottleneckReport(
        trace_id=certificate.scope.trace_ids[0],
        trace_complete=certificate.trace_complete,
        analysis_reached_windows=False,
        reasons=certificate.unknown_reasons,
    )


def cycle_relevance_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
) -> TraceCycleRelevanceReport:
    """表征坏环关系和 PPO 可达性，不启动 proof checker。"""

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        report = TraceCycleRelevanceReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            windows=tuple(characterize_cycle_relevance(window) for window in windows),
            reasons=tuple(window_unknowns),
        )
        raise _CycleRelevanceInspectionComplete(report)

    try:
        certificate = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _CycleRelevanceInspectionComplete as complete:
        return complete.report

    return TraceCycleRelevanceReport(
        trace_id=certificate.scope.trace_ids[0],
        trace_complete=certificate.trace_complete,
        analysis_reached_windows=False,
        reasons=certificate.unknown_reasons,
    )


def ppo_reduction_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
) -> TracePpoReductionReport:
    """生成 PPO reduction shadow 报告，不把 reduced 图交给 checker。"""

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        report = TracePpoReductionReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            windows=tuple(build_ppo_reduction(window) for window in windows),
            reasons=tuple(window_unknowns),
        )
        raise _PpoReductionInspectionComplete(report)

    try:
        certificate = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _PpoReductionInspectionComplete as complete:
        return complete.report

    return TracePpoReductionReport(
        trace_id=certificate.scope.trace_ids[0],
        trace_complete=certificate.trace_complete,
        analysis_reached_windows=False,
        reasons=certificate.unknown_reasons,
    )


def ppo_certificate_profile_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
    cache_dir: Path | None = None,
) -> TracePpoCertificateGenerationReport:
    """表征 certificate producer/replay 阶段，不把结果送入正式 checker。"""

    window_reconstruction: list[float] = []
    trace_sha = trace_digest(trace_dir)
    contract_sha = _file_digest(dbt_contract)

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        profiled: list[PpoCertificateGenerationReport] = []
        for window in windows:
            cache_status = "not_requested"
            cache_reasons: tuple[str, ...] = ()
            cache_path = cache_dir / f"{window.window_id}.json" if cache_dir else None
            if cache_path is not None:
                from bmo_check_dynamic.analysis.ppo_cache import (
                    load_ppo_certificate_cache,
                    ppo_certificate_cache_key,
                )

                cache_path.parent.mkdir(parents=True, exist_ok=True)
                graph_for_cache = build_ppo_graph_input(window)
                loaded = load_ppo_certificate_cache(
                    cache_path,
                    graph_for_cache,
                    trace_digest=trace_sha,
                    window_digest=window_digest(window),
                    dbt_contract_digest=contract_sha,
                )
                cache_status = loaded.status
                cache_reasons = loaded.reasons
                if loaded.status == "hit" and loaded.certificate is not None:
                    cache_key = ppo_certificate_cache_key(
                        graph_for_cache,
                        loaded.certificate,
                        trace_digest=trace_sha,
                        window_digest=window_digest(window),
                        dbt_contract_digest=contract_sha,
                    )
                    profiled.append(
                        PpoCertificateGenerationReport(
                            window_id=window.window_id,
                            event_count=len(graph_for_cache.events),
                            source_ppo_edge_count=len(graph_for_cache.source_edges),
                            target_ppo_edge_count=len(graph_for_cache.target_edges),
                            certificate_digest=loaded.certificate.proof_digest,
                            replay_accepted=bool(loaded.replay and loaded.replay.accepted),
                            replay_reasons=loaded.replay.reasons if loaded.replay else (),
                            cache_key=cache_key,
                            cache_status="hit",
                        )
                    )
                    continue
            item = build_profiled_ppo_reduction_window(
                window,
                trace_digest=trace_sha,
                window_digest=window_digest(window),
                dbt_contract_digest=contract_sha,
            )
            if cache_path is not None:
                from bmo_check_dynamic.analysis.ppo_cache import save_ppo_certificate_cache

                save_ppo_certificate_cache(
                    cache_path,
                    item[1],
                    item[2],
                    item[3],
                    trace_digest=trace_sha,
                    window_digest=window_digest(window),
                    dbt_contract_digest=contract_sha,
                )
            profiled.append(
                item[0].model_copy(
                    update={
                        "cache_status": cache_status,
                        "cache_reasons": cache_reasons,
                    }
                )
            )
        report = TracePpoCertificateGenerationReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            window_reconstruction_time_ms=(
                sum(window_reconstruction) if window_reconstruction else None
            ),
            windows=tuple(profiled),
            reasons=tuple(window_unknowns),
        )
        raise _PpoCertificateProfileInspectionComplete(report)

    try:
        certificate = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
            _window_reconstruction_sink=window_reconstruction,
        )
    except _PpoCertificateProfileInspectionComplete as complete:
        return complete.report

    return TracePpoCertificateGenerationReport(
        trace_id=certificate.scope.trace_ids[0],
        trace_complete=certificate.trace_complete,
        analysis_reached_windows=False,
        windows=(),
        reasons=certificate.unknown_reasons,
    )


def ppo_replay_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    certificate: TracePpoReductionCertificate,
    config: DynamicConfig | None = None,
) -> TracePpoReductionReplayReport:
    """从原始窗口重新构造 graph，独立重放磁盘 certificate。"""

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        by_window = {item.window_id: item for item in certificate.windows}
        reports = []
        binding_reasons: list[str] = []
        if certificate.trace_id != manifest.trace_id:
            binding_reasons.append("certificate trace_id does not match trace manifest")
        for window in windows:
            item = by_window.get(window.window_id)
            if item is None:
                reports.append(
                    PpoReductionReplay(
                        window_id=window.window_id,
                        certificate_digest_matches=False,
                        source_replayable=False,
                        target_replayable=False,
                        source_equivalent=False,
                        target_equivalent=False,
                        accepted=False,
                        reasons=("no PPO reduction certificate for window",),
                    )
                )
                continue
            reports.append(replay_ppo_reduction(build_ppo_graph_input(window), item))
        observed_window_ids = {window.window_id for window in windows}
        extra_window_ids = sorted(set(by_window) - observed_window_ids)
        if extra_window_ids:
            binding_reasons.append(
                "certificate contains windows absent from trace: "
                + ",".join(extra_window_ids)
            )
        if binding_reasons:
            reports = [
                item.model_copy(
                    update={
                        "accepted": False,
                        "reasons": item.reasons + tuple(binding_reasons),
                    }
                )
                for item in reports
            ]
        report = TracePpoReductionReplayReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            windows=tuple(reports),
            reasons=tuple(window_unknowns) + tuple(binding_reasons),
        )
        raise _PpoReplayInspectionComplete(report)

    try:
        analyzed = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _PpoReplayInspectionComplete as complete:
        return complete.report

    return TracePpoReductionReplayReport(
        trace_id=analyzed.scope.trace_ids[0],
        trace_complete=analyzed.trace_complete,
        analysis_reached_windows=False,
        reasons=analyzed.unknown_reasons,
    )


def ppo_solver_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
    reduction_certificate: TracePpoReductionCertificate | None = None,
    execute_solver: bool = True,
) -> tuple[TraceShadowSolverReport, TraceReducedSolverRunCertificate]:
    """运行 full/reduced PPO shadow A/B，不把 reduced 图交给正式 checker。"""

    config = config or DynamicConfig()
    trace_sha256 = trace_digest(trace_dir)
    contract_sha256 = _file_digest(dbt_contract)

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        supplied = (
            {item.window_id: item for item in reduction_certificate.windows}
            if reduction_certificate is not None
            else {}
        )
        comparisons: list[ShadowSolverComparison] = []
        certificates: list[ReducedSolverRunCertificate] = []
        reasons = list(window_unknowns)
        if reduction_certificate is not None and reduction_certificate.trace_id != manifest.trace_id:
            reasons.append("PPO reduction certificate trace_id does not match trace")
        for window in windows:
            graph = build_ppo_graph_input(window)
            reduction = supplied.get(window.window_id)
            if reduction is None:
                reduction, _ = build_ppo_reduction_certificate(graph)
            comparison = build_shadow_solver_comparison(
                window,
                graph,
                reduction,
                control_flow_closed=manifest.control_flow_closed,
                timeout_ms=config.solver_timeout_ms,
                max_symbolic_terms=config.max_symbolic_terms,
                execute_solver=execute_solver,
            )
            comparisons.append(comparison)
            certificates.append(
                build_solver_certificate(
                    trace_sha256=trace_sha256,
                    window=window,
                    graph=graph,
                    reduction=reduction,
                    comparison=comparison,
                    dbt_contract_sha256=contract_sha256,
                    timeout_ms=config.solver_timeout_ms,
                    max_symbolic_terms=config.max_symbolic_terms,
                    execute_solver=execute_solver,
                    control_flow_closed=manifest.control_flow_closed,
                )
            )
        report = TraceShadowSolverReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            windows=tuple(comparisons),
            reasons=tuple(reasons),
        )
        certificate = TraceReducedSolverRunCertificate(
            trace_id=manifest.trace_id,
            windows=tuple(certificates),
        )
        raise _PpoSolverInspectionComplete(report, certificate)

    try:
        analyzed = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _PpoSolverInspectionComplete as complete:
        return complete.report, complete.certificate
    empty = TraceShadowSolverReport(
        trace_id=analyzed.scope.trace_ids[0],
        trace_complete=analyzed.trace_complete,
        analysis_reached_windows=False,
        reasons=analyzed.unknown_reasons,
    )
    return empty, TraceReducedSolverRunCertificate(trace_id=empty.trace_id)


def ppo_solver_side_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    side: BenchmarkSide,
    config: DynamicConfig | None = None,
    reduction_certificate: TracePpoReductionCertificate | None = None,
    execute_solver: bool = True,
    repetition: int = 0,
    budget_ms: int | None = None,
    profile: SolverDiagnosticProfile = SolverDiagnosticProfile.FULL,
) -> TraceShadowSolverSideReport:
    """只在当前进程构造一侧 PPO，供独立 benchmark worker 调用。"""

    config = config or DynamicConfig()
    phase = ShadowSolverPhase.SOLVER if execute_solver else ShadowSolverPhase.ENCODING

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        supplied = (
            {item.window_id: item for item in reduction_certificate.windows}
            if reduction_certificate is not None
            else {}
        )
        runs = []
        reasons = list(window_unknowns)
        if reduction_certificate is not None and reduction_certificate.trace_id != manifest.trace_id:
            reasons.append("PPO reduction certificate trace_id does not match trace")
        for window in windows:
            graph = build_ppo_graph_input(window)
            reduction = supplied.get(window.window_id)
            if reduction is None:
                reduction, _ = build_ppo_reduction_certificate(graph)
            runs.append(
                build_shadow_solver_run(
                    window,
                    graph,
                    reduction,
                    side=side.value,
                    control_flow_closed=manifest.control_flow_closed,
                    timeout_ms=config.solver_timeout_ms,
                    max_symbolic_terms=config.max_symbolic_terms,
                    execute_solver=execute_solver,
                    profile=profile,
                )
            )
        raise _PpoSolverSideInspectionComplete(
            TraceShadowSolverSideReport(
                trace_id=manifest.trace_id,
                side=side,
                phase=phase,
                profile=profile,
                # profile is carried by every window; this top-level route
                # remains a diagnostic report rather than a verdict.
                trace_complete=bool(getattr(validation, "structurally_complete", False)),
                analysis_reached_windows=True,
                windows=tuple(runs),
                reasons=tuple(reasons),
            )
        )

    try:
        analyzed = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _PpoSolverSideInspectionComplete as complete:
        return complete.report
    return TraceShadowSolverSideReport(
        trace_id=analyzed.scope.trace_ids[0],
        side=side,
        phase=phase,
        profile=profile,
        trace_complete=analyzed.trace_complete,
        analysis_reached_windows=False,
        reasons=analyzed.unknown_reasons,
    )


def graph_first_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
    reduction_certificate: TracePpoReductionCertificate | None = None,
    max_cycle_length: int = 12,
    max_cycles: int = 32,
    max_search_states: int = 100_000,
    local_timeout_ms: int = 1_000,
    local_max_symbolic_terms: int = 100_000,
    execute_local_solver: bool = True,
) -> TraceGraphFirstReport:
    """用候选坏环驱动局部 shadow SMT，不进入正式 checker。"""

    config = config or DynamicConfig()

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        supplied = (
            {item.window_id: item for item in reduction_certificate.windows}
            if reduction_certificate is not None
            else {}
        )
        reasons = list(window_unknowns)
        if reduction_certificate is not None and reduction_certificate.trace_id != manifest.trace_id:
            reasons.append("PPO reduction certificate trace_id does not match trace")
        reports = tuple(
            characterize_graph_first_window(
                window,
                reduction_certificate=supplied.get(window.window_id),
                control_flow_closed=manifest.control_flow_closed,
                max_cycle_length=max_cycle_length,
                max_cycles=max_cycles,
                max_search_states=max_search_states,
                local_timeout_ms=local_timeout_ms,
                local_max_symbolic_terms=local_max_symbolic_terms,
                execute_local_solver=execute_local_solver,
            )
            for window in windows
        )
        if reduction_certificate is not None:
            observed = {window.window_id for window in windows}
            extra = sorted(
                item.window_id
                for item in reduction_certificate.windows
                if item.window_id not in observed
            )
            if extra:
                reasons.append(
                    "reduction certificate contains windows absent from trace: "
                    + ",".join(extra)
                )
        raise _GraphFirstInspectionComplete(
            TraceGraphFirstReport(
                trace_id=manifest.trace_id,
                trace_complete=bool(getattr(validation, "structurally_complete", False)),
                analysis_reached_windows=True,
                windows=reports,
                reasons=tuple(dict.fromkeys(reasons)),
            )
        )

    try:
        analyzed = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _GraphFirstInspectionComplete as complete:
        return complete.report
    return TraceGraphFirstReport(
        trace_id=analyzed.scope.trace_ids[0],
        trace_complete=analyzed.trace_complete,
        analysis_reached_windows=False,
        reasons=analyzed.unknown_reasons,
    )


def cegar_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
    reduction_certificate: TracePpoReductionCertificate | None = None,
    max_cycle_length: int = 12,
    max_search_states: int = 10_000,
    max_local_queries: int = 1_000,
    max_generated_candidates: int = 100_000,
    local_timeout_ms: int = 1_000,
    local_max_symbolic_terms: int = 100_000,
    execute_local_solver: bool = True,
) -> TraceCegarReport:
    """运行 P12 graph-first/CEGAR shadow；绝不进入正式 verdict。"""

    config = config or DynamicConfig()

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        supplied = (
            {item.window_id: item for item in reduction_certificate.windows}
            if reduction_certificate is not None
            else {}
        )
        reasons = list(window_unknowns)
        if reduction_certificate is not None and reduction_certificate.trace_id != manifest.trace_id:
            reasons.append("PPO reduction certificate trace_id does not match trace")
        reports = tuple(
            characterize_cegar_window(
                window,
                reduction_certificate=supplied.get(window.window_id),
                control_flow_closed=manifest.control_flow_closed,
                max_cycle_length=max_cycle_length,
                max_search_states=max_search_states,
                max_local_queries=max_local_queries,
                max_generated_candidates=max_generated_candidates,
                local_timeout_ms=local_timeout_ms,
                local_max_symbolic_terms=local_max_symbolic_terms,
                execute_local_solver=execute_local_solver,
            )
            for window in windows
        )
        if reduction_certificate is not None:
            observed = {window.window_id for window in windows}
            extra = sorted(
                item.window_id
                for item in reduction_certificate.windows
                if item.window_id not in observed
            )
            if extra:
                reasons.append(
                    "reduction certificate contains windows absent from trace: "
                    + ",".join(extra)
                )
        raise _CegarInspectionComplete(
            TraceCegarReport(
                trace_id=manifest.trace_id,
                trace_complete=bool(getattr(validation, "structurally_complete", False)),
                analysis_reached_windows=True,
                windows=reports,
                reasons=tuple(dict.fromkeys(reasons)),
            )
        )

    try:
        analyzed = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _CegarInspectionComplete as complete:
        return complete.report
    return TraceCegarReport(
        trace_id=analyzed.scope.trace_ids[0],
        trace_complete=analyzed.trace_complete,
        analysis_reached_windows=False,
        reasons=analyzed.unknown_reasons,
    )


def cegar_mode_comparison_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    config: DynamicConfig | None = None,
    reduction_certificate: TracePpoReductionCertificate | None = None,
    fixture: str | None = None,
    max_cycle_length: int = 12,
    max_search_states: int = 10_000,
    max_local_queries: int = 1_000,
    local_timeout_ms: int = 1_000,
    local_max_symbolic_terms: int = 100_000,
    execute_local_solver: bool = True,
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
) -> CegarExperimentReport:
    """对真实 trace 的每个窗口执行 P13/P14 shadow A/B。"""

    config = config or DynamicConfig()

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        supplied = (
            {item.window_id: item for item in reduction_certificate.windows}
            if reduction_certificate is not None
            else {}
        )
        reasons = list(window_unknowns)
        if reduction_certificate is not None and reduction_certificate.trace_id != manifest.trace_id:
            reasons.append("PPO reduction certificate trace_id does not match trace")
        reports = tuple(
            compare_cegar_modes(
                window,
                fixture=fixture or manifest.trace_id,
                reduction_certificate=supplied.get(window.window_id),
                control_flow_closed=manifest.control_flow_closed,
                max_cycle_length=max_cycle_length,
                max_search_states=max_search_states,
                max_local_queries=max_local_queries,
                local_timeout_ms=local_timeout_ms,
                local_max_symbolic_terms=local_max_symbolic_terms,
                execute_local_solver=execute_local_solver,
                include_structured=include_structured,
                only_mode=only_mode,
                discovery_only=discovery_only,
                include_bounded=include_bounded,
                discovery_resource_policy=discovery_resource_policy,
                include_candidate_records=include_candidate_records,
                capture_model=capture_model,
                close_feasible_candidates=close_feasible_candidates,
                closure_timeout_ms=closure_timeout_ms,
                closure_max_symbolic_terms=closure_max_symbolic_terms,
            )
            for window in windows
        )
        if reduction_certificate is not None:
            observed = {window.window_id for window in windows}
            extra = sorted(
                item.window_id
                for item in reduction_certificate.windows
                if item.window_id not in observed
            )
            if extra:
                reasons.append(
                    "reduction certificate contains windows absent from trace: "
                    + ",".join(extra)
                )
        raise _CegarExperimentInspectionComplete(
            CegarExperimentReport(
                generated_at=datetime.now(timezone.utc).isoformat(),
                trace_id=manifest.trace_id,
                trace_sha256=(trace_digest(trace_dir) if capture_model else None),
                contract_sha256=(_file_digest(dbt_contract) if capture_model else None),
                trace_complete=bool(getattr(validation, "structurally_complete", False)),
                analysis_reached_windows=True,
                reports=reports,
                reasons=tuple(dict.fromkeys(reasons)),
            )
        )

    try:
        analyzed = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _CegarExperimentInspectionComplete as complete:
        return complete.report
    return CegarExperimentReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        trace_id=analyzed.scope.trace_ids[0],
        trace_sha256=(trace_digest(trace_dir) if capture_model else None),
        contract_sha256=(_file_digest(dbt_contract) if capture_model else None),
        trace_complete=analyzed.trace_complete,
        analysis_reached_windows=False,
        reasons=analyzed.unknown_reasons,
    )


def ppo_solver_replay_trace(
    trace_dir: Path,
    *,
    dbt_contract: Path,
    reduction_certificate: TracePpoReductionCertificate,
    solver_certificate: TraceReducedSolverRunCertificate,
    config: DynamicConfig | None = None,
    execute_solver: bool = True,
) -> TraceSolverReplayReport:
    """重建窗口、PPO reduction 和 solver 结果，独立 replay certificate。"""

    config = config or DynamicConfig()
    trace_sha256 = trace_digest(trace_dir)
    contract_sha256 = _file_digest(dbt_contract)

    def inspect(
        manifest: TraceManifest,
        validation: object,
        stored_event_count: int,
        scan_stats: CommunicationScanStats,
        edges: CompactCommunicationEdges | tuple[CommunicationEdge, ...],
        windows: tuple[object, ...],
        window_unknowns: tuple[str, ...],
    ) -> None:
        del stored_event_count, scan_stats, edges
        reductions = {item.window_id: item for item in reduction_certificate.windows}
        solver_runs = {item.window_id: item for item in solver_certificate.windows}
        reports: list[SolverRunReplay] = []
        reasons = list(window_unknowns)
        if reduction_certificate.trace_id != manifest.trace_id:
            reasons.append("PPO reduction certificate trace_id does not match trace")
        if solver_certificate.trace_id != manifest.trace_id:
            reasons.append("solver certificate trace_id does not match trace")
        for window in windows:
            reduction = reductions.get(window.window_id)
            solver_run = solver_runs.get(window.window_id)
            if reduction is None or solver_run is None:
                reports.append(
                    SolverRunReplay(
                        window_id=window.window_id,
                        binding_matches=False,
                        candidate_domain_matches=False,
                        solver_config_matches=False,
                        result_matches=False,
                        accepted=False,
                        reasons=("missing reduction or solver certificate window",),
                    )
                )
                continue
            graph = build_ppo_graph_input(window)
            reports.append(
                replay_solver_certificate(
                    window,
                    graph,
                    reduction,
                    solver_run,
                    trace_sha256=trace_sha256,
                    dbt_contract_sha256=contract_sha256,
                    timeout_ms=config.solver_timeout_ms,
                    max_symbolic_terms=config.max_symbolic_terms,
                    execute_solver=execute_solver,
                    control_flow_closed=manifest.control_flow_closed,
                )
            )
        observed_ids = {window.window_id for window in windows}
        extra = sorted((set(reductions) | set(solver_runs)) - observed_ids)
        if extra:
            reasons.append("certificates contain windows absent from trace: " + ",".join(extra))
        report = TraceSolverReplayReport(
            trace_id=manifest.trace_id,
            trace_complete=bool(getattr(validation, "structurally_complete", False)),
            analysis_reached_windows=True,
            windows=tuple(reports),
            reasons=tuple(reasons),
        )
        raise _PpoSolverReplayInspectionComplete(report)

    try:
        analyzed = analyze_trace(
            trace_dir,
            dbt_contract=dbt_contract,
            config=config,
            _window_observer=inspect,
        )
    except _PpoSolverReplayInspectionComplete as complete:
        return complete.report
    return TraceSolverReplayReport(
        trace_id=analyzed.scope.trace_ids[0],
        trace_complete=analyzed.trace_complete,
        analysis_reached_windows=False,
        reasons=analyzed.unknown_reasons,
    )


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _trace_import_ledger(
    trace_dir: Path,
    manifest: TraceManifest,
    config: DynamicConfig,
) -> TraceImportLedger:
    """为 pipeline 创建单一 subject 的 CREATING import binding。"""

    modules = (
        ModuleId.from_parts(manifest.executable.sha256, "executable"),
        *tuple(
            ModuleId.from_parts(item.sha256, "library")
            for item in manifest.libraries
        ),
    )
    records_digest = trace_digest(trace_dir)
    subject = TraceId.from_parts(
        "trace-1.2",
        _file_digest(trace_dir / "manifest.json"),
        modules,
        (manifest.trace_id, "complete" if manifest.complete else "incomplete"),
        records_digest,
    )
    semantic_config = {
        field.name: (
            str(value)
            if isinstance(value, Path)
            else value
        )
        for field in fields(config)
        if field.name != "database_path"
        for value in (getattr(config, field.name),)
    }
    config_digest = hashlib.sha256(
        json.dumps(
            semantic_config,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return TraceImportLedger(
        subject=subject,
        trace_digest=records_digest,
        schema_version="trace-1.2",
        config_digest=config_digest,
        state=TraceImportState.CREATING,
    )


def _is_resource_exhaustion(error: Exception) -> bool:
    """只把可预期的内存预算失败转成 UNKNOWN，其他错误仍暴露。"""

    if isinstance(error, MemoryError):
        return True
    message = str(error).lower()
    return "out of memory" in message or "memory limit" in message


def _single_thread_certificate(
    manifest: TraceManifest,
    validation: object,
    trace_dir: Path,
    config: DynamicConfig,
    contract_sha256: str,
    contract_version: str,
    coverage: TraceCoverage,
    *,
    object_count: int,
    unique_pc_count: int,
    indirect_target_count: int,
) -> DynamicCertificate:
    """完整单线程轨迹无需建立对象表，也不可能形成通信边。"""

    thread_id = int(validation.thread_ids[0])
    assumptions = [
        f"DBT contract: {contract_version}",
        "the complete trace contains one thread instance, so no cross-thread communication edge exists",
        "the proof applies only to concrete addresses and the recorded event skeleton",
    ]
    if config.application_only:
        assumptions.append(
            "application scope has no external communication edge because the trace is single-threaded"
        )
    return DynamicCertificate(
        schema_version="dynamic-certificate-v2",
        verdict=TraceVerdict.TRACE_SAFE,
        scope=TraceScope(
            trace_ids=(manifest.trace_id,),
            trace_sha256=(trace_digest(trace_dir),),
            executable=manifest.executable,
            libraries=manifest.libraries,
            commands=(manifest.command,),
            working_directories=(manifest.working_directory,),
            analysis_scope="application" if config.application_only else "full",
        ),
        dbt_contract_sha256=contract_sha256,
        analyzer_version=__version__,
        trace_complete=validation.structurally_complete,
        event_count=validation.event_count,
        thread_count=1,
        object_count=object_count,
        unique_pc_count=unique_pc_count,
        communication_edge_count=0,
        communication_edges_complete=True,
        indirect_target_count=indirect_target_count,
        application_partition=ApplicationPartitionEvidence(
            status="safe",
            main_thread=thread_id,
        ),
        unknown_reasons=(),
        assumptions=tuple(assumptions),
        coverage=coverage,
        binding=build_dynamic_certificate_binding(
            trace_dir,
            manifest,
            coverage,
            dbt_contract_sha256=contract_sha256,
            config=config,
            analyzer_version=__version__,
        ),
    )


def _unknown_certificate(
    manifest: TraceManifest,
    validation: object,
    trace_dir: Path,
    config: DynamicConfig,
    contract_sha256: str,
    unknowns: tuple[str, ...],
    *,
    event_count: int,
    assumption: str,
) -> DynamicCertificate:
    """资源闸门提前结束时仍输出完整的 UNKNOWN 证书。"""

    return DynamicCertificate(
        verdict=TraceVerdict.UNKNOWN,
        scope=TraceScope(
            trace_ids=(manifest.trace_id,),
            trace_sha256=(trace_digest(trace_dir),),
            executable=manifest.executable,
            libraries=manifest.libraries,
            commands=(manifest.command,),
            working_directories=(manifest.working_directory,),
            analysis_scope="application" if config.application_only else "full",
        ),
        dbt_contract_sha256=contract_sha256,
        analyzer_version=__version__,
        trace_complete=validation.structurally_complete,
        event_count=event_count,
        thread_count=len(validation.thread_ids),
        object_count=0,
        unique_pc_count=0,
        communication_edge_count=0,
        indirect_target_count=0,
        unknown_reasons=tuple(dict.fromkeys(unknowns)),
        assumptions=(assumption,),
    )
