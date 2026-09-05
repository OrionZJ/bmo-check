from __future__ import annotations

import hashlib
import tempfile
from itertools import chain
from pathlib import Path

from bmo_check_dynamic.analysis import (
    analyze_application_partition,
    build_windows,
    find_communication_edges,
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
            ),
            dbt_contract_sha256=contract_sha256,
            analyzer_version="0.2.0",
            trace_complete=validation.valid,
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
            try:
                edge_sample = tuple(
                    find_communication_edges(
                        store, limit=config.max_communication_edges + 1
                    )
                )
            except CommunicationLimitError as error:
                unknowns.append(str(error))
                edge_sample = ()
            if len(edge_sample) > config.max_communication_edges:
                unknowns.append(
                    "communication edge count exceeds "
                    f"{config.max_communication_edges}"
                )
                edges = edge_sample[: config.max_communication_edges]
            else:
                edges = tuple(
                    sorted(
                        edge_sample,
                        key=lambda edge: (edge.first_event, edge.second_event),
                    )
                )
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
            return DynamicCertificate(
                verdict=verdict,
                scope=TraceScope(
                    trace_ids=(manifest.trace_id,),
                    trace_sha256=(trace_digest(trace_dir),),
                    executable=manifest.executable,
                    libraries=manifest.libraries,
                    commands=(manifest.command,),
                    working_directories=(manifest.working_directory,),
                ),
                dbt_contract_sha256=contract_sha256,
                analyzer_version="0.2.0",
                trace_complete=validation.valid,
                event_count=store.event_count(),
                thread_count=len(validation.thread_ids),
                object_count=object_count,
                unique_pc_count=int(
                    store.connection.execute(
                        "SELECT count(DISTINCT pc) FROM events WHERE pc <> 0"
                    ).fetchone()[0]
                ),
                communication_edge_count=len(edges),
                indirect_target_count=indirect_count,
                application_partition=application_partition,
                windows=results,
                unknown_reasons=tuple(dict.fromkeys(unknowns)),
                assumptions=(
                    f"DBT contract: {contract.contract_version if contract else 'invalid'}",
                    "ordinary RVWMO dependencies are omitted from the target model",
                    "lifecycle tickets do not establish target memory ordering",
                    "the proof applies only to concrete addresses and the recorded event skeleton",
                ),
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
