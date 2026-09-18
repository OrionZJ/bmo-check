from __future__ import annotations

import hashlib
import tempfile
from itertools import chain
from pathlib import Path

from bmo_check_core import UnknownKind
from bmo_check_dynamic import __version__
from bmo_check_dynamic.analysis import (
    CompactCommunicationEdges,
    CommunicationEdge,
    CommunicationScanStats,
    analyze_application_partition,
    build_windows,
    find_communication_edges,
    max_communication_page_events,
    thread_handoffs_complete,
)
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.analysis.communication import CommunicationLimitError
from bmo_check_dynamic.model import (
    ApplicationPartitionEvidence,
    DynamicCertificate,
    EventKind,
    TraceManifest,
    TraceScope,
    TraceVerdict,
)
from bmo_check_dynamic.proof import check_window, load_supported_contract
from bmo_check_dynamic.storage import TraceStore
from bmo_check_dynamic.trace import TraceReader, trace_digest, validate_trace
from bmo_check_dynamic.trace.format import event_files


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
    if len(validation.thread_ids) == 1 and not futex_requires_contract:
        return _single_thread_certificate(
            manifest,
            validation,
            trace_dir,
            config,
            contract_sha256,
            contract.contract_version if contract else "invalid",
        )
    if validation.event_count > config.max_object_events:
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
            readers = (TraceReader(path) for path in event_files(trace_dir))
            _count, storage_unknowns = store.add_events(
                chain.from_iterable(readers),
                max_pages_per_access=config.max_pages_per_access,
                batch_size=config.batch_size,
            )
            unknowns.extend(storage_unknowns)
            stored_event_count = store.event_count()
            if stored_event_count > config.max_object_events:
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
            elif (
                config.application_only
                and application_partition.status == "safe"
                and thread_handoffs_complete(store)
            ):
                # 主模块分区已经逐字节排除了 worker/主线程的并发写重叠，
                # create/start/end/join 又提供了生命周期边界。此时继续枚举
                # 运行库热页不会增加应用证明，只会把外部边搬进内存。
                application_atomic_count = int(
                    store.connection.execute(
                        """
                        SELECT count(*) FROM events
                        WHERE kind = 3 AND pc >= ? AND pc < ?
                        """,
                        (
                            application_partition.module_start,
                            application_partition.module_end,
                        ),
                    ).fetchone()[0]
                )
                if application_atomic_count == 0:
                    raw_edge_sample = ()
                    edge_sample = ()
                    communication_edges_complete = False
                else:
                    # 原子访问可能和普通访问共同发布数据；不能把它从
                    # “无共享普通写”的充分条件里悄悄删除。
                    try:
                        raw_edge_sample = _scan_communication_edges(
                            store,
                            limit=config.max_communication_edges + 1,
                            max_active_events=config.max_communication_active_events,
                            required_pc_range=(
                                application_partition.module_start,
                                application_partition.module_end,
                            ),
                            edge_pc_range=(
                                application_partition.module_start,
                                application_partition.module_end,
                            ),
                            stats=scan_stats,
                        )
                    except CommunicationLimitError as error:
                        unknowns.append(str(error))
                        raw_edge_sample = ()
                        communication_edges_complete = False
                    edge_sample = raw_edge_sample
                    external_runtime_edges = scan_stats.external_edges
                    communication_edges_complete = scan_stats.complete
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
                max_page_events = max_communication_page_events(
                    store, required_pc_range=required_pc_range
                )
                if max_page_events > config.max_communication_active_events:
                    unknowns.append(
                        "communication page has "
                        f"{max_page_events} events, exceeding active-set limit "
                        f"{config.max_communication_active_events}"
                    )
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
                windows, window_unknowns = build_windows(
                    store, edges, max_events=config.max_window_events
                )
            unknowns.extend(window_unknowns)
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
                        "verified thread handoffs plus a disjoint application partition "
                        "closed ordinary application writes; runtime edges were not enumerated"
                    )
            return DynamicCertificate(
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
            )
    finally:
        if temporary is not None:
            temporary.cleanup()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


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
        object_count=0,
        unique_pc_count=0,
        communication_edge_count=0,
        communication_edges_complete=True,
        indirect_target_count=0,
        application_partition=ApplicationPartitionEvidence(
            status="safe",
            main_thread=thread_id,
        ),
        unknown_reasons=(),
        assumptions=tuple(assumptions),
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
