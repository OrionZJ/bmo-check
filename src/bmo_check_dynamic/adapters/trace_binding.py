"""把 dynamic certificate 和同一条原始 trace 的诊断快照绑定。"""

from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import chain
from pathlib import Path

from bmo_check_core import (
    DynamicDiagnosticSnapshot,
    ModuleId,
    TraceId,
    TraceImportLedger,
    TraceImportState,
)

from ..analysis import (
    CompactCommunicationEdges,
    CommunicationScanStats,
    analyze_application_partition,
    build_trace_coverage,
    build_windows,
    find_communication_edges,
    max_communication_page_events,
)
from ..analysis.communication import CommunicationLimitError
from ..config import DynamicConfig, semantic_config_digest
from ..model import CoverageState, DynamicCertificate, TraceManifest, TraceVerdict
from ..storage import TraceStore, TraceStoreError
from ..trace import (
    environment_digest,
    file_sha256,
    module_closure_digest,
    trace_digest,
)
from ..trace.format import TraceReader, event_files
from .diagnostic_snapshot import dynamic_snapshot_from_trace


class DynamicTraceBindingError(ValueError):
    """证书、trace manifest、contract 或诊断快照不能绑定时抛出。"""


def verify_dynamic_certificate_coverage(certificate: DynamicCertificate) -> None:
    """拒绝没有可回放 coverage ledger 的确定性 dynamic certificate。"""

    if not isinstance(certificate, DynamicCertificate):
        raise DynamicTraceBindingError(
            "verify_dynamic_certificate_coverage expects DynamicCertificate"
        )
    if certificate.verdict not in {
        TraceVerdict.TRACE_SAFE,
        TraceVerdict.COUNTEREXAMPLE,
    }:
        return
    coverage = certificate.coverage
    if coverage is None:
        raise DynamicTraceBindingError(
            "determinate dynamic certificate lacks a coverage ledger; "
            "legacy certificate is explain-only"
        )
    if len(certificate.scope.trace_sha256) != 1:
        raise DynamicTraceBindingError(
            "determinate dynamic certificate must bind one trace digest"
        )
    if coverage.trace_sha256 != certificate.scope.trace_sha256[0]:
        raise DynamicTraceBindingError(
            "dynamic coverage trace digest differs from certificate"
        )
    if coverage.config_sha256 is None:
        raise DynamicTraceBindingError(
            "determinate dynamic certificate lacks an analyzer config digest"
        )
    if coverage.event_count != certificate.event_count:
        raise DynamicTraceBindingError(
            "dynamic coverage event count differs from certificate"
        )
    if coverage.communication.candidate_edge_count != certificate.communication_edge_count:
        raise DynamicTraceBindingError(
            "dynamic coverage edge count differs from certificate"
        )
    if coverage.communication.state is not CoverageState.COMPLETE:
        raise DynamicTraceBindingError(
            "determinate dynamic certificate has incomplete communication coverage"
        )
    if coverage.windows.state is not CoverageState.COMPLETE:
        raise DynamicTraceBindingError(
            "determinate dynamic certificate has incomplete window coverage"
        )


def verify_dynamic_certificate_binding(
    certificate: DynamicCertificate,
    trace_dir: Path,
    dbt_contract: Path,
    *,
    config: DynamicConfig | None = None,
) -> None:
    """独立重算动态证书的 manifest/config/tool binding。

    证书中的摘要只作为待核对值；manifest、contract 和配置必须从调用者
    提供的实际文件/对象重新计算。缺失或不匹配不能由 scope/coverage 的
    重复字段补齐，否则同一 trace 可能在另一套预算下被错误重放。
    """

    if certificate.verdict not in {
        TraceVerdict.TRACE_SAFE,
        TraceVerdict.COUNTEREXAMPLE,
    }:
        return
    verify_dynamic_certificate_coverage(certificate)
    if certificate.schema_version != "dynamic-certificate-v2":
        raise DynamicTraceBindingError(
            "legacy dynamic certificate is explain-only; replay requires dynamic-certificate-v2"
        )
    binding = certificate.binding
    if binding is None:
        raise DynamicTraceBindingError(
            "determinate dynamic certificate lacks immutable binding"
        )
    config = config or DynamicConfig()
    config.validate()
    try:
        manifest = TraceManifest.load(trace_dir / "manifest.json")
        actual_manifest = file_sha256(trace_dir / "manifest.json")
        actual_contract = file_sha256(dbt_contract)
        actual_trace = trace_digest(trace_dir)
        expected_config = semantic_config_digest(config)
    except (OSError, ValueError, TypeError) as error:
        raise DynamicTraceBindingError(
            f"cannot derive dynamic certificate binding: {error}"
        ) from error
    coverage = certificate.coverage
    assert coverage is not None
    expected = {
        "manifest_sha256": actual_manifest,
        "trace_subject": coverage.trace_subject,
        "trace_sha256": actual_trace,
        "executable_sha256": manifest.executable.sha256,
        "library_closure_sha256": module_closure_digest(manifest),
        "environment_sha256": environment_digest(manifest),
        "dbt_contract_sha256": actual_contract,
        "config_sha256": expected_config,
        "analyzer_version": certificate.analyzer_version,
        "dynamorio_version": manifest.dynamorio_version,
        "client_version": manifest.client_version,
    }
    for field, actual in expected.items():
        if getattr(binding, field) != actual:
            raise DynamicTraceBindingError(
                f"dynamic certificate binding {field} differs from supplied inputs"
            )
    if binding.dbt_contract_sha256 != certificate.dbt_contract_sha256:
        raise DynamicTraceBindingError(
            "dynamic certificate binding contract digest differs from certificate"
        )
    if binding.trace_sha256 != certificate.scope.trace_sha256[0]:
        raise DynamicTraceBindingError(
            "dynamic certificate binding trace digest differs from scope"
        )
    if binding.executable_sha256 != certificate.scope.executable.sha256:
        raise DynamicTraceBindingError(
            "dynamic certificate binding executable differs from scope"
        )
    if tuple(manifest.libraries) != certificate.scope.libraries:
        raise DynamicTraceBindingError(
            "dynamic certificate binding libraries differ from scope"
        )


def replay_dynamic_event_inventory(
    certificate: DynamicCertificate,
    trace_dir: Path,
) -> None:
    """从原始 chunk 重建 decoded-event inventory，不相信证书计数。"""

    verify_dynamic_certificate_coverage(certificate)
    if certificate.verdict not in {
        TraceVerdict.TRACE_SAFE,
        TraceVerdict.COUNTEREXAMPLE,
    }:
        return
    try:
        with _replayed_trace_store(certificate, trace_dir, config=DynamicConfig()) as store:
            event_count, event_digest = store.event_inventory()
    except (OSError, ValueError, TraceStoreError, DynamicTraceBindingError) as error:
        raise DynamicTraceBindingError(
            f"cannot replay dynamic event inventory: {error}"
        ) from error
    if event_count != certificate.coverage.event_count:
        raise DynamicTraceBindingError(
            "replayed event count differs from dynamic coverage"
        )
    if event_digest != certificate.coverage.event_sha256:
        raise DynamicTraceBindingError(
            "replayed event digest differs from dynamic coverage"
        )


def replay_dynamic_coverage(
    certificate: DynamicCertificate,
    trace_dir: Path,
    *,
    config: DynamicConfig | None = None,
) -> None:
    """从原始 trace 独立重建通信边和窗口 coverage。

    证书中的 coverage 只提供待核对的期望值；扫描范围、对象 generation、
    边上限和窗口分区都从 trace 与模块表重新得到。任何输入层、通信层或窗口
    层无法闭合时，绑定失败而不是把 producer 的 COMPLETE 当作事实。
    """

    verify_dynamic_certificate_coverage(certificate)
    if certificate.verdict not in {
        TraceVerdict.TRACE_SAFE,
        TraceVerdict.COUNTEREXAMPLE,
    }:
        return
    config = config or DynamicConfig()
    config.validate()
    try:
        with _replayed_trace_store(certificate, trace_dir, config=config) as store:
            actual_count, actual_digest = store.event_inventory()
            expected = certificate.coverage
            assert expected is not None
            if actual_count != expected.event_count:
                raise DynamicTraceBindingError(
                    "replayed event count differs from dynamic coverage"
                )
            if actual_digest != expected.event_sha256:
                raise DynamicTraceBindingError(
                    "replayed event digest differs from dynamic coverage"
                )

            required_pc_range: tuple[int, int] | None = None
            edge_pc_range: tuple[int, int] | None = None
            if certificate.scope.analysis_scope == "application":
                recorded_partition = certificate.application_partition
                if recorded_partition is None:
                    raise DynamicTraceBindingError(
                        "application coverage lacks a partition boundary"
                    )
                manifest = TraceManifest.load(trace_dir / "manifest.json")
                partition = analyze_application_partition(
                    store,
                    trace_dir / "modules.tsv",
                    manifest.executable.path,
                )
                if (
                    partition.module_start != recorded_partition.module_start
                    or partition.module_end != recorded_partition.module_end
                ):
                    raise DynamicTraceBindingError(
                        "application coverage module range differs from trace modules"
                    )
                if partition.module_start >= partition.module_end:
                    raise DynamicTraceBindingError(
                        "application coverage has no valid main-module range"
                    )
                edge_pc_range = (partition.module_start, partition.module_end)
                application_memory = int(
                    store.connection.execute(
                        """
                        SELECT count(*) FROM events
                        WHERE kind IN (1, 2, 3) AND pc >= ? AND pc < ?
                        """,
                        edge_pc_range,
                    ).fetchone()[0]
                )
                if application_memory:
                    required_pc_range = edge_pc_range
            scan_stats = CommunicationScanStats()
            edge_sink = CompactCommunicationEdges()
            if store.thread_count() < 2:
                edge_sample = edge_sink
                scan_stats.complete = True
            else:
                max_page_events = max_communication_page_events(
                    store,
                    required_pc_range=required_pc_range,
                )
                if max_page_events > config.max_communication_active_events:
                    raise DynamicTraceBindingError(
                        "communication replay exceeds the active-event budget"
                    )
                try:
                    yielded = tuple(
                        find_communication_edges(
                            store,
                            limit=config.max_communication_edges + 1,
                            max_active_events=config.max_communication_active_events,
                            required_pc_range=required_pc_range,
                            edge_pc_range=edge_pc_range,
                            stats=scan_stats,
                            edge_sink=edge_sink,
                        )
                    )
                except CommunicationLimitError as error:
                    raise DynamicTraceBindingError(
                        f"communication replay is incomplete: {error}"
                    ) from error
                edge_sample = yielded if yielded else edge_sink

            edge_count = (
                edge_sample.edge_count
                if isinstance(edge_sample, CompactCommunicationEdges)
                else len(edge_sample)
            )
            if edge_count > config.max_communication_edges:
                replay_windows: tuple[object, ...] = ()
                window_unknowns: tuple[str, ...] = ()
            else:
                replay_windows, window_unknowns = build_windows(
                    store,
                    edge_sample,
                    max_events=config.max_window_events,
                )
            replayed = build_trace_coverage(
                store,
                import_ledger=store.import_ledger(),
                communication_edges=edge_sample,
                scan_stats=scan_stats,
                windows=replay_windows,
                window_unknowns=window_unknowns,
            )
            if replayed.communication != expected.communication:
                raise DynamicTraceBindingError(
                    "replayed communication coverage differs from certificate"
                )
            if replayed.windows != expected.windows:
                raise DynamicTraceBindingError(
                    "replayed window coverage differs from certificate"
                )
    except (OSError, ValueError, TraceStoreError, DynamicTraceBindingError) as error:
        if isinstance(error, DynamicTraceBindingError):
            raise
        raise DynamicTraceBindingError(
            f"cannot replay dynamic communication/window coverage: {error}"
        ) from error


@contextmanager
def _replayed_trace_store(
    certificate: DynamicCertificate,
    trace_dir: Path,
    *,
    config: DynamicConfig,
) -> Iterator[TraceStore]:
    """把同一组原始 chunk 导入临时 store，并独立闭合所有导入层。"""

    coverage = certificate.coverage
    if coverage is None:
        raise DynamicTraceBindingError("determinate certificate lacks coverage")
    try:
        manifest = TraceManifest.load(trace_dir / "manifest.json")
        modules = (
            ModuleId.from_parts(manifest.executable.sha256, "executable"),
            *tuple(
                ModuleId.from_parts(item.sha256, "library")
                for item in manifest.libraries
            ),
        )
        records_digest = trace_digest(trace_dir)
        config_digest = semantic_config_digest(config)
        subject = TraceId.from_parts(
            "trace-1.2",
            _sha256(trace_dir / "manifest.json", label="trace manifest"),
            modules,
            (manifest.trace_id, "complete" if manifest.complete else "incomplete"),
            records_digest,
        )
        if subject.value != coverage.trace_subject:
            raise DynamicTraceBindingError(
                "trace coverage subject differs from independently derived import subject"
            )
        if coverage.config_sha256 != config_digest:
            raise DynamicTraceBindingError(
                "trace coverage config digest differs from replay configuration"
            )
        binding = TraceImportLedger(
            subject=subject,
            trace_digest=records_digest,
            schema_version="trace-1.2",
            config_digest=config_digest,
            state=TraceImportState.CREATING,
        )
    except (OSError, TypeError, ValueError) as error:
        raise DynamicTraceBindingError(
            f"cannot create replay import subject: {error}"
        ) from error
    with tempfile.TemporaryDirectory(prefix="bmo-check-replay-") as directory:
        with TraceStore(
            Path(directory) / "events.duckdb",
            memory_limit_mb=config.database_memory_limit_mb,
        ) as store:
            store.begin_import(binding)
            _count, unsupported = store.add_events(
                chain.from_iterable(
                    TraceReader(path) for path in event_files(trace_dir)
                ),
                max_pages_per_access=config.max_pages_per_access,
                batch_size=config.batch_size,
            )
            if unsupported:
                raise DynamicTraceBindingError(
                    "replayed event import is unsupported: " + "; ".join(unsupported)
                )
            if (
                store.thread_count() > 1
                and store.event_count() > config.max_object_events
            ):
                raise DynamicTraceBindingError(
                    "replayed object materialization exceeds the configured budget"
                )
            store.materialize_objects()
            store.complete_import(trace_dir)
            yield store


@dataclass(frozen=True, slots=True)
class BoundDynamicEvidence:
    """一条已核对来源的 trace 证书及其只读诊断观察。"""

    # certificate 保留动态 analyzer 原 verdict，不由 diagnostics 重建。
    certificate: DynamicCertificate
    # manifest 把动态 analyzer 使用的字符串 trace ID 绑定到采集输入。
    manifest: TraceManifest
    # snapshot 使用内容身份 TraceId；它与 manifest.trace_id 是不同 ID。
    snapshot: DynamicDiagnosticSnapshot
    # manifest_trace_id 是启动器的 ID，不能和下面的 TraceId 字符串比较。
    manifest_trace_id: str
    # content_trace_id 绑定快照实际从哪些 trace bytes 生成。
    content_trace_id: TraceId
    # trace_sha256 同时覆盖 manifest、模块表、marker 和所有事件分块。
    trace_sha256: str
    # dbt_contract_sha256 绑定本次 target ordering contract 的实际字节。
    dbt_contract_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.certificate, DynamicCertificate):
            raise DynamicTraceBindingError("certificate has an invalid type")
        if not isinstance(self.manifest, TraceManifest):
            raise DynamicTraceBindingError("manifest has an invalid type")
        if not isinstance(self.snapshot, DynamicDiagnosticSnapshot):
            raise DynamicTraceBindingError("snapshot has an invalid type")
        if not isinstance(self.manifest_trace_id, str) or not self.manifest_trace_id:
            raise DynamicTraceBindingError("manifest_trace_id must be non-empty")
        if not isinstance(self.content_trace_id, TraceId):
            raise DynamicTraceBindingError("content_trace_id must be a TraceId")
        if self.manifest.trace_id != self.manifest_trace_id:
            raise DynamicTraceBindingError("manifest trace ID differs from bound ID")
        if self.certificate.scope.trace_ids != (self.manifest_trace_id,):
            raise DynamicTraceBindingError(
                "bound evidence must refer to exactly the manifest trace ID"
            )
        if self.certificate.scope.executable != self.manifest.executable:
            raise DynamicTraceBindingError("certificate executable differs from manifest")
        if self.certificate.scope.libraries != self.manifest.libraries:
            raise DynamicTraceBindingError("certificate libraries differ from manifest")
        if self.certificate.scope.commands != (self.manifest.command,):
            raise DynamicTraceBindingError("certificate command differs from manifest")
        if self.certificate.scope.working_directories != (
            self.manifest.working_directory,
        ):
            raise DynamicTraceBindingError(
                "certificate working directory differs from manifest"
            )
        if self.snapshot.trace_id != self.content_trace_id:
            raise DynamicTraceBindingError(
                "snapshot TraceId differs from the trace content identity"
            )
        if self.certificate.scope.trace_sha256 != (self.trace_sha256,):
            raise DynamicTraceBindingError(
                "certificate trace digest differs from bound trace content"
            )
        if self.certificate.dbt_contract_sha256 != self.dbt_contract_sha256:
            raise DynamicTraceBindingError(
                "certificate DBT contract digest differs from bound contract content"
            )

def _sha256(path: Path, *, label: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise DynamicTraceBindingError(f"cannot hash {label} {path}: {error}") from error
    return digest.hexdigest()


def bind_dynamic_certificate_to_trace(
    certificate: DynamicCertificate,
    trace_dir: Path,
    dbt_contract: Path,
    *,
    dynamic_scope: str | None = None,
    max_sites: int = 100_000,
    config: DynamicConfig | None = None,
) -> BoundDynamicEvidence:
    """从 trace 重建 snapshot，并逐项核对 analyzer certificate 的输入绑定。

    从原 trace 创建 snapshot，而不接受调用者拼装的 ObservedFact 列表，避免
    一个证书与另一份同样引用 TraceId 的手工 snapshot 混在一起。
    """

    if not isinstance(certificate, DynamicCertificate):
        raise DynamicTraceBindingError(
            "bind_dynamic_certificate_to_trace expects DynamicCertificate"
        )
    if not isinstance(trace_dir, Path) or not isinstance(dbt_contract, Path):
        raise DynamicTraceBindingError("trace_dir and dbt_contract must be Paths")
    verify_dynamic_certificate_binding(
        certificate,
        trace_dir,
        dbt_contract,
        config=config,
    )
    if len(certificate.scope.trace_ids) != 1 or len(certificate.scope.trace_sha256) != 1:
        raise DynamicTraceBindingError(
            "dynamic certificate must bind exactly one trace for diagnostics"
        )
    if certificate.scope.analysis_scope not in {"full", "application"}:
        raise DynamicTraceBindingError(
            "dynamic certificate has an unsupported analysis scope"
        )
    try:
        manifest = TraceManifest.load(trace_dir / "manifest.json")
    except (OSError, ValueError) as error:
        raise DynamicTraceBindingError(f"cannot read trace manifest: {error}") from error

    actual_trace_digest = trace_digest(trace_dir)
    actual_contract_digest = _sha256(dbt_contract, label="DBT contract")
    replay_dynamic_coverage(certificate, trace_dir, config=config)
    expected_fields = (
        ("manifest trace ID", certificate.scope.trace_ids, (manifest.trace_id,)),
        ("trace digest", certificate.scope.trace_sha256, (actual_trace_digest,)),
        ("executable fingerprint", certificate.scope.executable, manifest.executable),
        ("loaded library fingerprints", certificate.scope.libraries, manifest.libraries),
        ("command", certificate.scope.commands, (manifest.command,)),
        (
            "working directory",
            certificate.scope.working_directories,
            (manifest.working_directory,),
        ),
        ("DBT contract digest", certificate.dbt_contract_sha256, actual_contract_digest),
    )
    for label, recorded, actual in expected_fields:
        if recorded != actual:
            raise DynamicTraceBindingError(
                f"certificate {label} does not match the supplied trace inputs"
            )

    if dynamic_scope is None:
        dynamic_scope = f"dynamic.{certificate.scope.analysis_scope}"
    try:
        snapshot = dynamic_snapshot_from_trace(
            trace_dir,
            scope=dynamic_scope,
            max_sites=max_sites,
        )
    except ValueError as error:
        raise DynamicTraceBindingError(
            f"cannot derive dynamic snapshot from the bound trace: {error}"
        ) from error
    if certificate.verdict == TraceVerdict.TRACE_SAFE and not certificate.trace_complete:
        raise DynamicTraceBindingError(
            "TRACE_SAFE certificate marks its trace incomplete"
        )
    return BoundDynamicEvidence(
        certificate=certificate,
        manifest=manifest,
        snapshot=snapshot,
        manifest_trace_id=manifest.trace_id,
        content_trace_id=snapshot.trace_id,
        trace_sha256=actual_trace_digest,
        dbt_contract_sha256=actual_contract_digest,
    )


__all__ = [
    "BoundDynamicEvidence",
    "DynamicTraceBindingError",
    "bind_dynamic_certificate_to_trace",
    "replay_dynamic_coverage",
    "replay_dynamic_event_inventory",
    "verify_dynamic_certificate_coverage",
]
