from __future__ import annotations

import hashlib
import tempfile
from itertools import chain
from pathlib import Path

from bmo_check_dynamic import __version__
from bmo_check_dynamic.analysis import (
    analyze_application_partition,
    build_windows,
    find_communication_edges,
    max_communication_page_events,
    thread_handoffs_complete,
)
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.analysis.communication import CommunicationLimitError
from bmo_check_dynamic.model import (
    DynamicCertificate,
    TraceManifest,
    TraceScope,
    TraceVerdict,
)
from bmo_check_dynamic.proof import check_window, load_supported_contract
from bmo_check_dynamic.storage import TraceStore
from bmo_check_dynamic.trace import TraceReader, trace_digest, validate_trace
from bmo_check_dynamic.trace.format import event_files


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
    contract_sha256 = _file_digest(dbt_contract)
    contract, contract_error = load_supported_contract(dbt_contract)
    if contract_error is not None:
        unknowns.append(contract_error)
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
            unknown_reasons=tuple(unknowns),
            assumptions=("analysis stopped at preflight; analysis counts are unavailable",),
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
            object_count = store.materialize_objects()
            application_partition = analyze_application_partition(
                store, trace_dir / "modules.tsv", manifest.executable.path
            )
            external_runtime_edges = 0
            communication_edges_complete = True
            if config.application_only and application_partition.status != "safe":
                # 分区证据已经失败时，运行库边不能进入应用范围证明。
                # 继续构造通信图只会把百万级运行库访问搬进 Python 图，
                # 不会改变 UNKNOWN 结论，反而可能耗尽内存。
                unknowns.append(
                    "application-only scope requires a safe main-module partition"
                )
                raw_edge_sample = ()
                edge_sample = ()
            elif config.application_only and thread_handoffs_complete(store):
                # 主模块分区已经逐字节排除了 worker/主线程的并发写重叠，
                # create/start/end/join 又提供了生命周期边界。此时继续枚举
                # 运行库热页不会增加应用证明，只会把外部边搬进内存。
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
                else:
                    try:
                        raw_edge_sample = tuple(
                            find_communication_edges(
                                store,
                                limit=config.max_communication_edges + 1,
                                max_active_events=config.max_communication_active_events,
                                required_pc_range=required_pc_range,
                            )
                        )
                    except CommunicationLimitError as error:
                        unknowns.append(str(error))
                        raw_edge_sample = ()
                if config.application_only:
                    edge_sample, external_runtime_edges = _application_edges(
                        store,
                        raw_edge_sample,
                        application_partition.module_start,
                        application_partition.module_end,
                    )
                else:
                    edge_sample = raw_edge_sample
            raw_edge_count = len(raw_edge_sample)
            edge_limit_exceeded = len(edge_sample) > config.max_communication_edges
            if edge_limit_exceeded:
                unknowns.append(
                    "communication edge count exceeds "
                    f"{config.max_communication_edges}"
                )
                edges = ()
            else:
                edges = tuple(
                    sorted(
                        edge_sample,
                        key=lambda edge: (edge.first_event, edge.second_event),
                    )
                )
            if (
                config.application_only and application_partition.status != "safe"
            ) or edge_limit_exceeded:
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


def _application_edges(
    store: TraceStore,
    edges: tuple[object, ...],
    module_start: int,
    module_end: int,
) -> tuple[tuple[object, ...], int]:
    """保留至少一端来自主 ELF 的边，外部运行库边单独计数。

    application scope 只在主模块分区已经证明无 worker/main 写冲突时启用。
    运行库普通访存不被悄悄当成安全；它们必须由 DBT 的 LOCK/XCHG/Fence
    契约承担，并在证书中留下被排除的边数量。
    """

    event_ids = {
        event_id
        for edge in edges
        for event_id in (edge.first_event, edge.second_event)
    }
    events = store.get_events(event_ids)
    by_id = {event.event_id: event for event in events}
    kept = tuple(
        edge
        for edge in edges
        if (
            module_start <= by_id[edge.first_event].pc < module_end
            or module_start <= by_id[edge.second_event].pc < module_end
        )
    )
    return kept, len(edges) - len(kept)
