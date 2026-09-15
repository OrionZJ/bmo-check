"""解析 versioned workload manifest，并适配到现有 hybrid request。"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from bmo_check_dynamic.config import DynamicConfig
from bmo_check_static.model import CheckerLimits

from .application import HybridWorkflowRequest
from bmo_check_static.application import StaticRequest


_DYNAMIC_DEFAULTS = DynamicConfig()


class WorkloadManifestError(ValueError):
    """输入清单不符合 schema，或不能适配成一份 workload 请求。"""


class _StrictManifestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class WorkloadSpec(_StrictManifestModel):
    # executable 是两条分析路线共同使用的输入 ELF。
    executable: str
    # argv 不经 shell 拼接，避免静态和动态两边得到不同参数。
    argv: tuple[str, ...] = ()
    # working_directory 缺省时使用 manifest 所在目录。
    working_directory: str | None = None
    # environment 的值必须显式写成字符串，避免 YAML 隐式数值转换。
    environment: dict[str, str] = Field(default_factory=dict)

    @field_validator("executable")
    @classmethod
    def validate_executable(cls, value: str) -> str:
        if not value or "\x00" in value:
            raise ValueError("workload executable must be a non-empty path")
        return value

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in value for value in values):
            raise ValueError("argv entries cannot contain NUL")
        return values

    @model_validator(mode="after")
    def validate_environment(self) -> "WorkloadSpec":
        for name, value in self.environment.items():
            if not name or "=" in name or "\x00" in name or "\x00" in value:
                raise ValueError("environment names must be valid and values cannot contain NUL")
        if self.working_directory is not None and (
            not self.working_directory or "\x00" in self.working_directory
        ):
            raise ValueError("working_directory must be a valid path")
        return self


class StaticWorkflowSpec(_StrictManifestModel):
    dbt_contract: str
    pthread_spec: str
    function_effects: str
    library_roots: tuple[str, ...] = ()
    dbt_revision: str | None = None
    dbt_root: str | None = None
    scope: Literal["full", "application"] = "full"
    threads: tuple[int, int] | None = None
    provenance_instruction_limit: int | None = Field(default=None, ge=1)
    checker_limits: CheckerLimits = Field(default_factory=CheckerLimits)

    @model_validator(mode="after")
    def validate_paths_and_threads(self) -> "StaticWorkflowSpec":
        paths = [
            ("dbt_contract", self.dbt_contract),
            ("pthread_spec", self.pthread_spec),
            ("function_effects", self.function_effects),
        ]
        paths.extend(("library_roots", item) for item in self.library_roots)
        for name, value in paths:
            if not value or "\x00" in value:
                raise ValueError(f"{name} must contain valid paths")
        if self.dbt_revision is not None and (
            not self.dbt_revision or "\x00" in self.dbt_revision
        ):
            raise ValueError("dbt_revision must be non-empty when specified")
        if self.dbt_root is not None and (
            not self.dbt_root or "\x00" in self.dbt_root
        ):
            raise ValueError("dbt_root must be a valid path")
        if self.threads is not None:
            minimum, maximum = self.threads
            if minimum < 1 or maximum < minimum:
                raise ValueError("threads must be [minimum, maximum] with 1 <= minimum <= maximum")
        return self


class DynamicAnalysisSpec(_StrictManifestModel):
    # 默认值从 route config 取，避免清单和动态分析器各自演进。
    max_window_events: int = Field(default=_DYNAMIC_DEFAULTS.max_window_events, ge=1)
    max_executions: int = Field(default=_DYNAMIC_DEFAULTS.max_executions, ge=1)
    max_communication_edges: int = Field(
        default=_DYNAMIC_DEFAULTS.max_communication_edges, ge=1
    )
    max_communication_active_events: int = Field(
        default=_DYNAMIC_DEFAULTS.max_communication_active_events, ge=1
    )
    max_object_events: int = Field(default=_DYNAMIC_DEFAULTS.max_object_events, ge=1)
    max_pages_per_access: int = Field(default=_DYNAMIC_DEFAULTS.max_pages_per_access, ge=1)
    batch_size: int = Field(default=_DYNAMIC_DEFAULTS.batch_size, ge=1)
    solver_timeout_ms: int = Field(default=_DYNAMIC_DEFAULTS.solver_timeout_ms, ge=1)
    max_symbolic_terms: int = Field(default=_DYNAMIC_DEFAULTS.max_symbolic_terms, ge=1)
    database_memory_limit_mb: int = Field(
        default=_DYNAMIC_DEFAULTS.database_memory_limit_mb, ge=1
    )
    database_path: str | None = None
    application_only: bool = False


class DynamicWorkflowSpec(_StrictManifestModel):
    dynamorio_home: str | None = None
    client_path: str | None = None
    max_thread_events: int | None = Field(default=None, ge=1)
    max_snapshot_sites: int = Field(default=100_000, ge=1)
    analysis: DynamicAnalysisSpec = Field(default_factory=DynamicAnalysisSpec)

    @model_validator(mode="after")
    def validate_optional_paths(self) -> "DynamicWorkflowSpec":
        for name, value in (
            ("dynamorio_home", self.dynamorio_home),
            ("client_path", self.client_path),
            ("database_path", self.analysis.database_path),
        ):
            if value is not None and (not value or "\x00" in value):
                raise ValueError(f"{name} must be a valid path")
        return self


class HybridWorkloadManifest(_StrictManifestModel):
    """CLI 唯一接受的通用输入；分析语义仍由既有 route service 决定。"""

    schema_version: Literal["hybrid-workload-v1"]
    workload: WorkloadSpec
    static: StaticWorkflowSpec
    dynamic: DynamicWorkflowSpec = Field(default_factory=DynamicWorkflowSpec)

    def to_request(
        self,
        manifest_path: Path,
        output_dir: Path,
        *,
        dynamorio_home_override: Path | None = None,
        client_path_override: Path | None = None,
    ) -> HybridWorkflowRequest:
        if not isinstance(manifest_path, Path) or not isinstance(output_dir, Path):
            raise WorkloadManifestError("manifest_path and output_dir must be Paths")
        base_dir = manifest_path.resolve().parent
        resolved_output = output_dir.resolve()

        def resolve(value: str, name: str) -> Path:
            path = Path(value)
            return (path if path.is_absolute() else base_dir / path).resolve()

        def resolve_output_file(value: str | None) -> Path:
            if value is None:
                return resolved_output / "dynamic-analysis.duckdb"
            path = Path(value)
            return (path if path.is_absolute() else resolved_output / path).resolve()

        def choose_path(
            override: Path | None,
            manifest_value: str | None,
            default: Path,
            name: str,
        ) -> Path:
            if override is not None:
                if not isinstance(override, Path):
                    raise WorkloadManifestError(f"{name} override must be a Path")
                return override.resolve()
            if manifest_value is not None:
                return resolve(manifest_value, name)
            return default.resolve()

        dynamorio_default = Path(os.environ.get("DYNAMORIO_HOME", "/opt/dynamorio"))
        client_default = (
            Path(__file__).resolve().parents[1]
            / "bmo_check_dynamic"
            / "native"
            / "build"
            / "libbmo_trace.so"
        )
        dynamic_spec = self.dynamic
        dynamic_analysis = dynamic_spec.analysis
        database_path = resolve_output_file(dynamic_analysis.database_path)
        dynamic_config = DynamicConfig(
            max_window_events=dynamic_analysis.max_window_events,
            max_executions=dynamic_analysis.max_executions,
            max_communication_edges=dynamic_analysis.max_communication_edges,
            max_communication_active_events=(
                dynamic_analysis.max_communication_active_events
            ),
            max_object_events=dynamic_analysis.max_object_events,
            max_pages_per_access=dynamic_analysis.max_pages_per_access,
            batch_size=dynamic_analysis.batch_size,
            solver_timeout_ms=dynamic_analysis.solver_timeout_ms,
            max_symbolic_terms=dynamic_analysis.max_symbolic_terms,
            database_memory_limit_mb=dynamic_analysis.database_memory_limit_mb,
            database_path=database_path,
            application_only=dynamic_analysis.application_only,
        )
        try:
            dynamic_config.validate()
            return HybridWorkflowRequest(
                static_request=StaticRequest(
                    executable=resolve(self.workload.executable, "workload.executable"),
                    dbt_contract=resolve(self.static.dbt_contract, "static.dbt_contract"),
                    pthread_spec=resolve(self.static.pthread_spec, "static.pthread_spec"),
                    function_effects=resolve(
                        self.static.function_effects, "static.function_effects"
                    ),
                    library_roots=tuple(
                        resolve(item, "static.library_roots")
                        for item in self.static.library_roots
                    ),
                    argv=self.workload.argv,
                    threads=self.static.threads,
                    environment=tuple(sorted(self.workload.environment.items())),
                    dbt_revision=self.static.dbt_revision,
                    dbt_root=(
                        resolve(self.static.dbt_root, "static.dbt_root")
                        if self.static.dbt_root is not None
                        else None
                    ),
                    scope=self.static.scope,
                    provenance_instruction_limit=self.static.provenance_instruction_limit,
                ),
                dynamorio_home=choose_path(
                    dynamorio_home_override,
                    dynamic_spec.dynamorio_home,
                    dynamorio_default,
                    "dynamorio_home",
                ),
                client_path=choose_path(
                    client_path_override,
                    dynamic_spec.client_path,
                    client_default,
                    "client_path",
                ),
                trace_dir=resolved_output / "trace",
                working_directory=(
                    resolve(self.workload.working_directory, "working_directory")
                    if self.workload.working_directory is not None
                    else base_dir
                ),
                max_thread_events=dynamic_spec.max_thread_events,
                dynamic_config=dynamic_config,
                checker_limits=self.static.checker_limits,
                max_snapshot_sites=dynamic_spec.max_snapshot_sites,
            )
        except (TypeError, ValueError) as error:
            raise WorkloadManifestError(f"cannot build hybrid request: {error}") from error


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise WorkloadManifestError("workload manifest mapping keys must be strings")
        if key in mapping:
            raise WorkloadManifestError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_workload_manifest(path: Path) -> HybridWorkloadManifest:
    """严格读取 v1 manifest；未知字段、重复 key 和未知 schema 都失败关闭。"""

    if not isinstance(path, Path):
        raise WorkloadManifestError("workload manifest path must be a Path")
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise WorkloadManifestError(f"cannot read workload manifest {path}: {error}") from error
    try:
        document = yaml.load(source, Loader=_UniqueKeySafeLoader)
    except WorkloadManifestError:
        raise
    except yaml.YAMLError as error:
        raise WorkloadManifestError(f"invalid workload YAML: {error}") from error
    if not isinstance(document, dict):
        raise WorkloadManifestError("workload manifest root must be a YAML mapping")

    def require_string_mapping_keys(value: object, seen: set[int]) -> None:
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise WorkloadManifestError("workload manifest mapping keys must be strings")
            if id(value) in seen:
                return
            seen.add(id(value))
            for child in value.values():
                require_string_mapping_keys(child, seen)
        elif isinstance(value, list):
            if id(value) in seen:
                return
            seen.add(id(value))
            for child in value:
                require_string_mapping_keys(child, seen)

    try:
        require_string_mapping_keys(document, set())
        payload = json.dumps(document, ensure_ascii=False, allow_nan=False)
        return HybridWorkloadManifest.model_validate_json(payload)
    except (RecursionError, TypeError, ValueError, ValidationError) as error:
        raise WorkloadManifestError(f"invalid workload manifest: {error}") from error


def validate_request_inputs(request: HybridWorkflowRequest) -> None:
    """在分配 trace/storage 目录前检查必需输入，失败时不留半成品。"""

    files = (
        (request.static_request.executable, "workload executable"),
        (request.static_request.dbt_contract, "DBT contract"),
        (request.static_request.pthread_spec, "pthread contract"),
        (request.static_request.function_effects, "function-effect contract"),
        (request.client_path, "DynamoRIO client"),
        (request.dynamorio_home / "bin64" / "drrun", "DynamoRIO launcher"),
    )
    for path, label in files:
        if not path.is_file():
            raise WorkloadManifestError(f"{label} is not a file: {path}")
    for path in request.static_request.library_roots:
        if not path.is_dir():
            raise WorkloadManifestError(f"library root is not a directory: {path}")
    if request.static_request.dbt_root is not None and not request.static_request.dbt_root.is_dir():
        raise WorkloadManifestError(
            f"DBT root is not a directory: {request.static_request.dbt_root}"
        )
    if request.working_directory is not None and not request.working_directory.is_dir():
        raise WorkloadManifestError(
            f"working directory is not a directory: {request.working_directory}"
        )
    database_path = request.dynamic_config.database_path
    if database_path is not None and database_path.exists():
        raise WorkloadManifestError(
            f"refusing to reuse existing DuckDB file: {database_path}"
        )


def validate_output_layout(request: HybridWorkflowRequest, output_dir: Path) -> None:
    """拒绝把 DuckDB 写到输出目录外，或覆盖 workflow 自己的产物。"""

    output_root = output_dir.resolve()
    database_path = request.dynamic_config.database_path
    if database_path is None:
        return
    database_path = database_path.resolve()
    if database_path.parent != output_root:
        raise WorkloadManifestError(
            "DuckDB path must be a direct child of output-dir; relative paths resolve there"
        )
    reserved = {
        "hybrid-workflow-report.json",
        "static-certificate.json",
        "dynamic-certificate.json",
    }
    if database_path.name in reserved or database_path.name == "trace":
        raise WorkloadManifestError(
            f"DuckDB path conflicts with a workflow artifact: {database_path}"
        )


__all__ = [
    "DynamicAnalysisSpec",
    "DynamicWorkflowSpec",
    "HybridWorkloadManifest",
    "StaticWorkflowSpec",
    "WorkloadManifestError",
    "WorkloadSpec",
    "load_workload_manifest",
    "validate_request_inputs",
    "validate_output_layout",
]
