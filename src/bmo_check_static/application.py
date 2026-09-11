"""静态分析的应用服务边界。

CLI 只负责把命令行文本解析成 ``StaticRequest`` 并渲染结果；恢复、访存
事件提取、共享状态和 portability checker 在这里按固定顺序编排。旧的
Pydantic report 仍是兼容输出，canonical sidecar 由各 producer 显式提供。
"""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from bmo_check_static.analysis import (
    analyze_shared_state,
    extract_memory_events,
)
from bmo_check_static.binary.dependency_closure import build_program_manifest
from bmo_check_static.binary.symbols import function_symbols
from bmo_check_static.config import load_contract_version, load_function_effect_contract
from bmo_check_static.controlflow import recover_control_flow
from bmo_check_static.model import (
    CheckerLimits,
    ExecutionScope,
    FingerprintReport,
    PortabilityCertificate,
    ProgramManifest,
    ProgramRecoveryReport,
    ProgramSliceReport,
    UnknownFact,
    UnknownKind,
)
from bmo_check_static.proof import verify_portability
from bmo_check_static.slicing import build_shared_memory_slice, restrict_to_application_scope
from bmo_check_static.synchronization import analyze_pthread_synchronization
from bmo_check_static.threading import discover_pthread_threads


class StaticApplicationError(ValueError):
    """请求不能形成静态分析范围时抛出。"""


@dataclass(frozen=True, slots=True)
class StaticRequest:
    """静态 service 接收的已解析请求，不携带 argparse.Namespace。"""

    executable: Path
    dbt_contract: Path
    pthread_spec: Path
    function_effects: Path
    library_roots: tuple[Path, ...] = ()
    argv: tuple[str, ...] = ()
    threads: tuple[int, int] | None = None
    environment: tuple[tuple[str, str], ...] = ()
    dbt_revision: str | None = None
    dbt_root: Path | None = None
    scope: str = "full"

    def __post_init__(self) -> None:
        for name in (
            "executable",
            "dbt_contract",
            "pthread_spec",
            "function_effects",
        ):
            if not isinstance(getattr(self, name), Path):
                raise StaticApplicationError(f"{name} must be a Path")
        if self.dbt_root is not None and not isinstance(self.dbt_root, Path):
            raise StaticApplicationError("dbt_root must be a Path")
        if self.scope not in {"full", "application"}:
            raise StaticApplicationError("scope must be 'full' or 'application'")
        if self.threads is not None:
            if (
                len(self.threads) != 2
                or self.threads[0] < 1
                or self.threads[1] < self.threads[0]
            ):
                raise StaticApplicationError("threads must be a valid MIN:MAX range")
        for key, value in self.environment:
            if not isinstance(key, str) or not key or "\x00" in key:
                raise StaticApplicationError("environment keys must be non-empty")
            if not isinstance(value, str) or "\x00" in value:
                raise StaticApplicationError("environment values cannot contain NUL")


def _git_revision(root: Path | None) -> str | None:
    if root is None:
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    revision = completed.stdout.strip()
    return revision or None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _environment(request: StaticRequest) -> Mapping[str, str]:
    return dict(request.environment)


def build_manifest(request: StaticRequest) -> ProgramManifest:
    """构造并绑定 ELF 闭包；契约读取失败仍写入 legacy Unknown。"""

    contract = load_contract_version(request.dbt_contract)
    effect_contract = load_function_effect_contract(request.function_effects)
    thread_min: int | None = None
    thread_max: int | None = None
    if request.threads is not None:
        thread_min, thread_max = request.threads

    execution = ExecutionScope(
        argv=request.argv,
        thread_count_min=thread_min,
        thread_count_max=thread_max,
        environment=dict(_environment(request)),
    )
    revision = request.dbt_revision or _git_revision(request.dbt_root)
    manifest = build_program_manifest(
        executable_path=request.executable,
        library_roots=request.library_roots,
        execution=execution,
        dbt_contract_version=contract.version,
        dbt_revision=revision,
    ).model_copy(
        update={
            "function_effect_contract_version": effect_contract.version,
            "function_effect_contract_sha256": effect_contract.sha256 or None,
        }
    )
    contract_unknowns = tuple(
        item
        for item in (contract.unknown, effect_contract.unknown)
        if item is not None
    )
    if contract_unknowns:
        return manifest.model_copy(
            update={
                "closure_complete": False,
                "unknowns": manifest.unknowns + contract_unknowns,
            }
        )
    return manifest


def fingerprint(request: StaticRequest) -> FingerprintReport:
    return FingerprintReport(manifest=build_manifest(request))


def recover(
    request: StaticRequest,
    *,
    symbol_provider: Callable[[object], Iterable[object]] = function_symbols,
) -> ProgramRecoveryReport:
    """恢复控制流、线程入口和实际 pthread 同步摘要。"""

    manifest = build_manifest(request)
    if manifest.executable is None:
        return ProgramRecoveryReport(manifest=manifest)

    control_flow = recover_control_flow(manifest.executable, manifest)
    threads = discover_pthread_threads(manifest.executable, manifest, control_flow)
    synchronization = []
    recovery_unknowns: list[UnknownFact] = []
    called_pthread_apis = {
        call.target_symbol
        for call in control_flow.call_sites
        if call.target_symbol is not None and call.target_symbol.startswith("pthread_")
    }
    for library in manifest.libraries:
        try:
            names = {symbol.name for symbol in symbol_provider(library)}
        except Exception as error:
            recovery_unknowns.append(
                UnknownFact(
                    kind=UnknownKind.ELF_BACKEND_FAILURE,
                    reason=str(error),
                    impact="synchronization implementations in this library were not discovered",
                    module=library.path,
                )
            )
            continue
        implemented_apis = names.intersection(called_pthread_apis)
        if not implemented_apis:
            continue
        try:
            synchronization.append(
                analyze_pthread_synchronization(
                    library,
                    request.pthread_spec,
                    request.dbt_contract,
                    requested_apis=implemented_apis,
                )
            )
        except Exception as error:
            # 配置或摘要失败不能表现成“该库没有同步 effect”。
            recovery_unknowns.append(
                UnknownFact(
                    kind=UnknownKind.UNKNOWN_SYNCHRONIZATION,
                    reason=str(error),
                    impact="the concrete pthread synchronization summary is unavailable",
                    module=library.path,
                )
            )
    return ProgramRecoveryReport(
        manifest=manifest,
        control_flow=control_flow,
        thread_roles=threads,
        synchronization=tuple(synchronization),
        unknowns=tuple(recovery_unknowns),
    )


def slice_report(
    request: StaticRequest,
    *,
    symbol_provider: Callable[[object], Iterable[object]] = function_symbols,
) -> ProgramSliceReport:
    """提取普通访存并建立共享内存切片。"""

    recovery = recover(request, symbol_provider=symbol_provider)
    module = recovery.manifest.executable
    if (
        module is None
        or recovery.control_flow is None
        or recovery.thread_roles is None
    ):
        return ProgramSliceReport(
            recovery=recovery,
            unknowns=recovery.manifest.unknowns + recovery.unknowns,
        )

    effect_contract = load_function_effect_contract(request.function_effects)
    events = extract_memory_events(
        module,
        recovery.control_flow,
        recovery.thread_roles,
        recovery.synchronization,
        function_effects=effect_contract.effects,
        function_integer_arguments=effect_contract.integer_arguments,
        function_memory_arguments=effect_contract.memory_arguments,
        function_internal_objects=effect_contract.internal_objects,
    )
    shared_state = analyze_shared_state(
        module,
        recovery.control_flow,
        recovery.thread_roles,
        events,
    )
    shared_slice = build_shared_memory_slice(
        events, shared_state, recovery.thread_roles
    )
    if request.scope == "application":
        shared_slice = restrict_to_application_scope(
            shared_slice,
            executable_sha256=module.sha256,
        )
    return ProgramSliceReport(
        recovery=recovery,
        memory_events=events,
        shared_state=shared_state,
        shared_slice=shared_slice,
        unknowns=recovery.unknowns,
    )


def analyze(
    request: StaticRequest,
    limits: CheckerLimits | None = None,
    *,
    symbol_provider: Callable[[object], Iterable[object]] = function_symbols,
) -> PortabilityCertificate:
    """执行 portability checker；checker 仍是唯一 legacy verdict owner。"""

    report = slice_report(request, symbol_provider=symbol_provider)
    return verify_portability(
        report,
        limits,
        analysis_options={
            "scope": request.scope,
            "pthread_spec_sha256": _file_sha256(request.pthread_spec),
        },
    )


__all__ = [
    "StaticApplicationError",
    "StaticRequest",
    "analyze",
    "build_manifest",
    "fingerprint",
    "recover",
    "slice_report",
]
