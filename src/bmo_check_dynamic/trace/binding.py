"""动态证书使用的内容身份和配置摘要。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from bmo_check_dynamic.config import DynamicConfig, semantic_config_digest
from bmo_check_dynamic.model import DynamicCertificateBinding, TraceCoverage, TraceManifest


def file_sha256(path: Path) -> str:
    """按文件内容计算摘要；路径本身不参与证书身份。"""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def environment_digest(manifest: TraceManifest) -> str:
    """环境变量按排序后的键值绑定，避免 JSON 插入顺序影响身份。"""

    material = {key: manifest.environment[key] for key in sorted(manifest.environment)}
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def module_closure_digest(manifest: TraceManifest) -> str:
    """绑定实际加载的 executable/library 指纹，而不是模块路径列表。"""

    modules = [
        {
            "role": "executable",
            "path": manifest.executable.path,
            "sha256": manifest.executable.sha256,
            "build_id": manifest.executable.build_id,
        }
    ]
    modules.extend(
        {
            "role": "library",
            "path": item.path,
            "sha256": item.sha256,
            "build_id": item.build_id,
        }
        for item in manifest.libraries
    )
    modules.sort(key=lambda item: (item["role"], item["sha256"], item["path"]))
    return hashlib.sha256(
        json.dumps(modules, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def build_dynamic_certificate_binding(
    trace_dir: Path,
    manifest: TraceManifest,
    coverage: TraceCoverage,
    *,
    dbt_contract_sha256: str,
    config: DynamicConfig,
    analyzer_version: str,
) -> DynamicCertificateBinding:
    """从实际 manifest/coverage 生成 v2 binding，不接受调用者提供的摘要。"""

    manifest_digest = file_sha256(trace_dir / "manifest.json")
    config_digest = semantic_config_digest(config)
    if coverage.config_sha256 != config_digest:
        raise ValueError("coverage config digest differs from binding configuration")
    return DynamicCertificateBinding(
        manifest_sha256=manifest_digest,
        trace_subject=coverage.trace_subject,
        trace_sha256=coverage.trace_sha256,
        executable_sha256=manifest.executable.sha256,
        library_closure_sha256=module_closure_digest(manifest),
        environment_sha256=environment_digest(manifest),
        dbt_contract_sha256=dbt_contract_sha256,
        config_sha256=config_digest,
        analyzer_version=analyzer_version,
        dynamorio_version=manifest.dynamorio_version,
        client_version=manifest.client_version,
    )


__all__ = [
    "build_dynamic_certificate_binding",
    "environment_digest",
    "file_sha256",
    "module_closure_digest",
]
