"""把 dynamic certificate 和同一条原始 trace 的诊断快照绑定。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from bmo_check_core import DynamicDiagnosticSnapshot, TraceId

from ..model import DynamicCertificate, TraceManifest, TraceVerdict
from ..trace import trace_digest
from .diagnostic_snapshot import dynamic_snapshot_from_trace


class DynamicTraceBindingError(ValueError):
    """证书、trace manifest、contract 或诊断快照不能绑定时抛出。"""


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
]
