"""PARSEC 评测的 typed application service。

这里负责选择 suite、编排每个 benchmark 的静态 pipeline、写出消融证书，
以及为大型程序建立独立 worker 边界。命令行只把文本参数转换成
``ParsecEvaluationRequest``，因此静态分析核心不需要知道 PARSEC 的目录约定。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from time import monotonic

from bmo_check_static.analysis import (
    analyze_shared_state,
    extract_memory_events,
    prove_symbolic_lifecycle,
    prove_symbolic_partition,
)
from bmo_check_static.application import StaticRequest, recover as static_recover
from bmo_check_static.config import load_function_effect_contract
from bmo_check_static.evaluation import (
    ABLATION_LEVELS,
    ablate_shared_state,
    find_publication_risks,
    load_evaluation_suite,
    run_native_benchmark,
)
from bmo_check_static.model import (
    AblationMeasurement,
    BenchmarkDefinition,
    BenchmarkMeasurement,
    CheckerLimits,
    EvaluationReport,
    EvaluationStatus,
    EvaluationSuite,
    NativeRunMeasurement,
    PhaseTimings,
    ProgramSliceReport,
    RiskScreeningStatus,
    StrictModel,
)
from bmo_check_static.proof import verify_portability
from bmo_check_static.slicing import (
    build_shared_memory_slice,
    restrict_to_application_scope,
)


class EvaluationApplicationError(ValueError):
    """评测请求不能形成稳定执行范围时抛出。"""


@dataclass(frozen=True, slots=True)
class ParsecEvaluationRequest:
    """已经解析的 PARSEC 请求；服务层不接收 argparse.Namespace。

    每个字段都固定本次评测的输入和资源边界。这样 worker 重启时可以从
    显式 payload 重建请求，而不会依赖父进程里隐含的 argparse 状态。
    """

    # suite 描述 benchmark 的机器码入口、参数和证明提示。
    suite: Path
    # parsec_root 是 suite 相对路径的唯一解析根。
    parsec_root: Path
    # DBT contract 和 function effects 绑定本次静态证书的语义输入。
    dbt_contract: Path
    # pthread_spec 决定同步摘要；更换规格必须重新生成证书。
    pthread_spec: Path
    # function_effects 描述 helper 的访存效果和参数传播。
    function_effects: Path
    # 输出根目录保存每个消融级别的证书和汇总报告。
    output_dir: Path
    # 空 tuple 表示运行 suite 中全部 benchmark。
    benchmark_ids: tuple[str, ...] = ()
    # library_roots 按 ELF 依赖搜索顺序传给静态闭包恢复。
    library_roots: tuple[Path, ...] = ()
    # None 使用 suite 的线程数；非 None 覆盖所有 benchmark。
    threads_override: int | None = None
    # environment 是有序键值对，避免把可变 dict 当成服务协议。
    environment: tuple[tuple[str, str], ...] = ()
    # dbt_revision 记录翻译器版本；缺省时从 dbt_root 读取 HEAD。
    dbt_revision: str | None = None
    # dbt_root 是读取 revision 的仓库目录，不参与程序闭包。
    dbt_root: Path | None = None
    # application 只限制主 ELF；full 保留整个闭包。
    scope: str = "full"
    # 是否附带运行原生程序；原生结果不参与 portability verdict。
    run_native: bool = False
    # 原生 benchmark 超时后只记录失败，不阻塞其它静态结果。
    native_timeout_seconds: int = 300
    # worker 的地址空间和墙钟上限防止大型程序拖垮父进程。
    analysis_memory_limit_mb: int = 4096
    # 单 benchmark 超过墙钟上限时，父进程写入 Timeout 状态。
    analysis_timeout_seconds: int = 900
    # checker limits 控制单个 portability 窗口的规模。
    max_events: int = 24
    # checker 允许参与一个窗口的最大线程角色数。
    max_threads: int = 8
    # checker 最多枚举的候选执行数。
    max_executions: int = 4096
    # solver 单次查询的毫秒上限。
    checker_timeout_ms: int = 10_000
    # True 只用于 worker 或显式调试；默认由服务建立隔离 worker。
    in_process: bool = False

    def __post_init__(self) -> None:
        for name in (
            "suite",
            "parsec_root",
            "dbt_contract",
            "pthread_spec",
            "function_effects",
            "output_dir",
        ):
            if not isinstance(getattr(self, name), Path):
                raise EvaluationApplicationError(f"{name} must be a Path")
        if self.dbt_root is not None and not isinstance(self.dbt_root, Path):
            raise EvaluationApplicationError("dbt_root must be a Path")
        if any(not isinstance(path, Path) for path in self.library_roots):
            raise EvaluationApplicationError("library_roots must contain Paths")
        if self.scope not in {"full", "application"}:
            raise EvaluationApplicationError("scope must be 'full' or 'application'")
        if any(not isinstance(item, str) or not item for item in self.benchmark_ids):
            raise EvaluationApplicationError("benchmark_ids must contain non-empty strings")
        if self.threads_override is not None and self.threads_override < 1:
            raise EvaluationApplicationError("threads_override must be positive")
        for key, value in self.environment:
            if not isinstance(key, str) or not key or "\x00" in key:
                raise EvaluationApplicationError("environment keys must be non-empty")
            if not isinstance(value, str) or "\x00" in value:
                raise EvaluationApplicationError("environment values cannot contain NUL")
        for name in (
            "native_timeout_seconds",
            "analysis_memory_limit_mb",
            "analysis_timeout_seconds",
            "max_events",
            "max_threads",
            "max_executions",
            "checker_timeout_ms",
        ):
            if getattr(self, name) < 1:
                raise EvaluationApplicationError(f"{name} must be positive")

    def with_in_process(self, value: bool) -> "ParsecEvaluationRequest":
        """为 worker 明确切换执行边界，不修改其它评测输入。"""

        return replace(self, in_process=value)

    def to_payload(self) -> dict[str, object]:
        """生成跨进程传输的显式 schema；业务代码不直接消费这个 dict。"""

        return {
            "suite": str(self.suite),
            "parsec_root": str(self.parsec_root),
            "benchmark_ids": list(self.benchmark_ids),
            "library_roots": [str(path) for path in self.library_roots],
            "threads_override": self.threads_override,
            "environment": [[key, value] for key, value in self.environment],
            "dbt_contract": str(self.dbt_contract),
            "dbt_revision": self.dbt_revision,
            "dbt_root": str(self.dbt_root) if self.dbt_root is not None else None,
            "pthread_spec": str(self.pthread_spec),
            "function_effects": str(self.function_effects),
            "output_dir": str(self.output_dir),
            "scope": self.scope,
            "run_native": self.run_native,
            "native_timeout_seconds": self.native_timeout_seconds,
            "analysis_memory_limit_mb": self.analysis_memory_limit_mb,
            "analysis_timeout_seconds": self.analysis_timeout_seconds,
            "max_events": self.max_events,
            "max_threads": self.max_threads,
            "max_executions": self.max_executions,
            "checker_timeout_ms": self.checker_timeout_ms,
            "in_process": self.in_process,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "ParsecEvaluationRequest":
        """只在 worker 入口解码 payload，字段缺失时拒绝执行。"""

        if not isinstance(payload, dict):
            raise EvaluationApplicationError("evaluation request payload must be an object")
        try:
            environment = tuple(
                (str(item[0]), str(item[1]))
                for item in payload.get("environment", [])
            )
            return cls(
                suite=Path(str(payload["suite"])),
                parsec_root=Path(str(payload["parsec_root"])),
                benchmark_ids=tuple(str(item) for item in payload.get("benchmark_ids", [])),
                library_roots=tuple(
                    Path(str(item)) for item in payload.get("library_roots", [])
                ),
                threads_override=(
                    int(payload["threads_override"])
                    if payload.get("threads_override") is not None
                    else None
                ),
                environment=environment,
                dbt_contract=Path(str(payload["dbt_contract"])),
                dbt_revision=(
                    str(payload["dbt_revision"])
                    if payload.get("dbt_revision") is not None
                    else None
                ),
                dbt_root=(
                    Path(str(payload["dbt_root"]))
                    if payload.get("dbt_root") is not None
                    else None
                ),
                pthread_spec=Path(str(payload["pthread_spec"])),
                function_effects=Path(str(payload["function_effects"])),
                output_dir=Path(str(payload["output_dir"])),
                scope=str(payload.get("scope", "full")),
                run_native=bool(payload.get("run_native", False)),
                native_timeout_seconds=int(payload.get("native_timeout_seconds", 300)),
                analysis_memory_limit_mb=int(
                    payload.get("analysis_memory_limit_mb", 4096)
                ),
                analysis_timeout_seconds=int(
                    payload.get("analysis_timeout_seconds", 900)
                ),
                max_events=int(payload.get("max_events", 24)),
                max_threads=int(payload.get("max_threads", 8)),
                max_executions=int(payload.get("max_executions", 4096)),
                checker_timeout_ms=int(payload.get("checker_timeout_ms", 10_000)),
                in_process=bool(payload.get("in_process", False)),
            )
        except (KeyError, TypeError, ValueError, IndexError) as error:
            raise EvaluationApplicationError(
                f"invalid evaluation request payload: {error}"
            ) from error


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _checker_limits(request: ParsecEvaluationRequest) -> CheckerLimits:
    return CheckerLimits(
        max_events=request.max_events,
        max_threads=request.max_threads,
        max_executions=request.max_executions,
        timeout_ms=request.checker_timeout_ms,
    )


def _static_request(
    request: ParsecEvaluationRequest,
    executable: Path,
    argv: tuple[str, ...],
    threads: int,
) -> StaticRequest:
    """把评测范围转换成静态 service 的唯一请求类型。"""

    return StaticRequest(
        executable=executable,
        library_roots=request.library_roots,
        argv=argv,
        threads=(threads, threads),
        environment=request.environment,
        dbt_contract=request.dbt_contract,
        dbt_revision=request.dbt_revision,
        dbt_root=request.dbt_root,
        pthread_spec=request.pthread_spec,
        function_effects=request.function_effects,
        scope=request.scope,
    )


def _write_json(report: StrictModel, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # 报告模型在这里才序列化；pipeline 内部不把 JSON 当作事实模型。
    path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _select_definitions(
    request: ParsecEvaluationRequest,
) -> tuple[EvaluationSuite, tuple[BenchmarkDefinition, ...]]:
    try:
        suite = load_evaluation_suite(request.suite)
    except ValueError as error:
        raise EvaluationApplicationError(str(error)) from error
    requested = set(request.benchmark_ids)
    available = {item.id for item in suite.benchmarks}
    missing = requested - available
    if missing:
        raise EvaluationApplicationError(
            f"suite has no benchmark IDs: {', '.join(sorted(missing))}"
        )
    definitions = tuple(
        item for item in suite.benchmarks if not requested or item.id in requested
    )
    return suite, definitions


def _evaluate_definition(
    request: ParsecEvaluationRequest,
    definition: BenchmarkDefinition,
    limits: CheckerLimits,
) -> BenchmarkMeasurement:
    threads = request.threads_override or definition.threads
    argv = tuple(item.replace("{threads}", str(threads)) for item in definition.argv)
    executable = (request.parsec_root / definition.executable).resolve()

    recovery_started = monotonic()
    recovery = static_recover(
        _static_request(request, executable, argv, threads)
    )
    recovery_seconds = monotonic() - recovery_started
    event_seconds = 0.0
    shared_state_seconds = 0.0
    memory_events = None
    shared_state = None
    partition_proofs = ()
    lifecycle_proof = None
    module = recovery.manifest.executable
    if (
        module is not None
        and recovery.control_flow is not None
        and recovery.thread_roles is not None
    ):
        event_started = monotonic()
        effect_contract = load_function_effect_contract(request.function_effects)
        if definition.lifecycle_hint is not None:
            lifecycle_proof = prove_symbolic_lifecycle(
                module, definition.lifecycle_hint, threads
            )
        memory_events = extract_memory_events(
            module,
            recovery.control_flow,
            recovery.thread_roles,
            recovery.synchronization,
            function_effects=effect_contract.effects,
            function_integer_arguments=effect_contract.integer_arguments,
            function_memory_arguments=effect_contract.memory_arguments,
            function_internal_objects=effect_contract.internal_objects,
            worker_argument_base=(
                lifecycle_proof.worker_argument_base
                if lifecycle_proof is not None and lifecycle_proof.proven
                else None
            ),
            worker_argument_alias_base=(
                definition.lifecycle_hint.worker_argument_alias_base
                if lifecycle_proof is not None
                and lifecycle_proof.proven
                and definition.lifecycle_hint is not None
                else None
            ),
        )
        event_seconds = monotonic() - event_started
        shared_started = monotonic()
        partition_proofs = tuple(
            prove_symbolic_partition(module, hint, threads)
            for hint in definition.partition_hints
        )
        shared_state = analyze_shared_state(
            module,
            recovery.control_flow,
            recovery.thread_roles,
            memory_events,
            partition_proofs,
            lifecycle_proof,
            definition.normal_completion_only,
        )
        shared_state_seconds = monotonic() - shared_started

    ablations: list[AblationMeasurement] = []
    for level in ABLATION_LEVELS:
        slice_started = monotonic()
        if memory_events is not None and shared_state is not None:
            level_state = ablate_shared_state(memory_events, shared_state, level)
            shared_slice = build_shared_memory_slice(
                memory_events, level_state, recovery.thread_roles
            )
            if request.scope == "application" and module is not None:
                shared_slice = restrict_to_application_scope(
                    shared_slice,
                    executable_sha256=module.sha256,
                )
            program_report = ProgramSliceReport(
                recovery=recovery,
                memory_events=memory_events,
                shared_state=level_state,
                shared_slice=shared_slice,
                unknowns=recovery.unknowns,
            )
        else:
            shared_slice = None
            program_report = ProgramSliceReport(
                recovery=recovery,
                unknowns=recovery.manifest.unknowns + recovery.unknowns,
            )
        slice_seconds = monotonic() - slice_started

        checker_started = monotonic()
        certificate = verify_portability(
            program_report,
            limits,
            analysis_options={
                "scope": request.scope,
                "pruning_level": level.value,
                "normal_completion_only": definition.normal_completion_only,
                # 同步规格变化时，旧 certificate 不能被新摘要复用。
                "pthread_spec_sha256": _file_sha256(request.pthread_spec),
                # suite 提供的提示和证明结果绑定到本次消融证书。
                "partition_hints": [
                    item.model_dump(mode="json")
                    for item in definition.partition_hints
                ],
                "partition_proofs": [
                    {
                        "proven": item.proven,
                        "object_base": item.object_base,
                        "index_term": item.index_term,
                        "element_size": item.element_size,
                        "item_count": item.item_count,
                        "thread_count": item.thread_count,
                        "evidence": list(item.evidence),
                        "worker_pc": item.worker_pc,
                        "loop_pc": item.loop_pc,
                    }
                    for item in partition_proofs
                ],
                "lifecycle_hint": (
                    definition.lifecycle_hint.model_dump(mode="json")
                    if definition.lifecycle_hint is not None
                    else None
                ),
                "lifecycle_proof": (
                    {
                        "proven": lifecycle_proof.proven,
                        "start_pc": lifecycle_proof.start_pc,
                        "post_join_pc": lifecycle_proof.post_join_pc,
                        "thread_count": lifecycle_proof.thread_count,
                        "created_handles": list(lifecycle_proof.created_handles),
                        "joined_handles": list(lifecycle_proof.joined_handles),
                        "created_arguments": list(lifecycle_proof.created_arguments),
                        "worker_argument_base": lifecycle_proof.worker_argument_base,
                        "evidence": list(lifecycle_proof.evidence),
                    }
                    if lifecycle_proof is not None
                    else None
                ),
            },
        )
        checker_seconds = monotonic() - checker_started
        screening_started = monotonic()
        findings = (
            find_publication_risks(shared_slice) if shared_slice is not None else ()
        )
        screening_seconds = monotonic() - screening_started
        if certificate.verdict.value == "SAFE":
            screening_status = RiskScreeningStatus.PROVED_SAFE
        elif certificate.verdict.value == "COUNTEREXAMPLE":
            screening_status = RiskScreeningStatus.CONFIRMED_COUNTEREXAMPLE
        elif findings:
            screening_status = RiskScreeningStatus.POTENTIAL_RISK
        else:
            screening_status = RiskScreeningStatus.NO_RISK_FOUND
        certificate_path = (
            request.output_dir / definition.id / f"{level.value}.certificate.json"
        )
        _write_json(certificate, certificate_path)
        pruning_counts = certificate.coverage.pruning_counts
        ablations.append(
            AblationMeasurement(
                level=level,
                timings=PhaseTimings(
                    recovery_seconds=recovery_seconds,
                    event_seconds=event_seconds,
                    shared_state_seconds=shared_state_seconds,
                    slice_seconds=slice_seconds,
                    checker_seconds=checker_seconds,
                    screening_seconds=screening_seconds,
                ),
                total_events=(shared_slice.coverage.total_events if shared_slice else 0),
                remaining_events=(
                    shared_slice.coverage.remaining_shared_events if shared_slice else 0
                ),
                conflict_candidates=(len(shared_slice.conflicts) if shared_slice else 0),
                pruning_counts=pruning_counts,
                checker_executions=certificate.checker.examined_executions,
                verdict=certificate.verdict,
                relevant_unknowns=len(certificate.relevant_unknowns),
                screening_status=screening_status,
                risk_findings=findings,
                certificate_file=str(
                    certificate_path.relative_to(request.output_dir).as_posix()
                ),
                certificate_sha256=_file_sha256(certificate_path),
            )
        )

    native = NativeRunMeasurement()
    if request.run_native:
        native = run_native_benchmark(
            definition,
            request.parsec_root,
            argv,
            request.native_timeout_seconds,
        )
    return BenchmarkMeasurement(
        benchmark_id=definition.id,
        executable=str(executable),
        executable_sha256=(module.sha256 if module is not None else None),
        argv=argv,
        threads=threads,
        ablations=tuple(ablations),
        native_run=native,
    )


def _run_in_process(
    request: ParsecEvaluationRequest,
    suite: EvaluationSuite,
    definitions: tuple[BenchmarkDefinition, ...],
) -> EvaluationReport:
    try:
        import resource

        limit = request.analysis_memory_limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except (ImportError, OSError, ValueError):
        # 非 POSIX 平台没有 RLIMIT_AS 时仍由外层 worker 的超时控制风险。
        pass
    started = monotonic()
    limits = _checker_limits(request)
    measurements = tuple(
        _evaluate_definition(request, definition, limits) for definition in definitions
    )
    return EvaluationReport(
        suite_name=suite.name,
        parsec_root=str(request.parsec_root.resolve()),
        library_roots=tuple(str(path.resolve()) for path in request.library_roots),
        dbt_contract=str(request.dbt_contract.resolve()),
        dbt_revision=request.dbt_revision or _git_revision(request.dbt_root),
        benchmarks=measurements,
        total_seconds=monotonic() - started,
    )


def _failed_measurement(
    request: ParsecEvaluationRequest,
    definition: BenchmarkDefinition,
    status: EvaluationStatus,
    failure: str,
) -> BenchmarkMeasurement:
    threads = request.threads_override or definition.threads
    argv = tuple(item.replace("{threads}", str(threads)) for item in definition.argv)
    executable = (request.parsec_root / definition.executable).resolve()
    native = NativeRunMeasurement()
    if request.run_native:
        native = run_native_benchmark(
            definition,
            request.parsec_root,
            argv,
            request.native_timeout_seconds,
        )
    return BenchmarkMeasurement(
        benchmark_id=definition.id,
        executable=str(executable),
        executable_sha256=_file_sha256(executable) if executable.is_file() else None,
        argv=argv,
        threads=threads,
        status=status,
        failure=failure,
        native_run=native,
    )


def _run_isolated(
    request: ParsecEvaluationRequest,
    suite: EvaluationSuite,
    definitions: tuple[BenchmarkDefinition, ...],
) -> EvaluationReport:
    request.output_dir.mkdir(parents=True, exist_ok=True)
    started = monotonic()
    measurements: list[BenchmarkMeasurement] = []
    worker_report = request.output_dir / "evaluation.json"
    for index, definition in enumerate(definitions):
        worker_report.unlink(missing_ok=True)
        worker_request = request.with_in_process(True)
        worker_request = replace(worker_request, benchmark_ids=(definition.id,))
        request_path: Path | None = None
        status = EvaluationStatus.FAILED
        failure = "evaluation worker did not produce a report"
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=request.output_dir,
                prefix=f".bmo-evaluation-request-{index}-",
                suffix=".json",
                delete=False,
            ) as stream:
                request_path = Path(stream.name)
                json.dump(worker_request.to_payload(), stream, sort_keys=True)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "bmo_check_evaluation.worker",
                    "--request",
                    str(request_path),
                ],
                capture_output=True,
                text=True,
                timeout=request.analysis_timeout_seconds,
                check=False,
            )
            if completed.returncode == 0 and worker_report.is_file():
                partial = EvaluationReport.model_validate_json(
                    worker_report.read_text(encoding="utf-8")
                )
                if len(partial.benchmarks) != 1:
                    raise EvaluationApplicationError(
                        "evaluation worker returned an unexpected benchmark count"
                    )
                measurements.append(partial.benchmarks[0])
                continue
            if completed.returncode < 0 or "MemoryError" in completed.stderr:
                status = EvaluationStatus.RESOURCE_LIMIT
                failure = (
                    f"worker exited {completed.returncode} under the "
                    f"{request.analysis_memory_limit_mb} MiB memory limit"
                )
            else:
                failure = (
                    completed.stderr.strip()[-2000:]
                    or f"worker exited {completed.returncode} without a report"
                )
        except subprocess.TimeoutExpired:
            status = EvaluationStatus.TIMEOUT
            failure = f"analysis exceeded {request.analysis_timeout_seconds} seconds"
        except (OSError, ValueError, EvaluationApplicationError) as error:
            failure = str(error)
        finally:
            if request_path is not None:
                request_path.unlink(missing_ok=True)

        measurements.append(
            _failed_measurement(request, definition, status, failure)
        )

    return EvaluationReport(
        suite_name=suite.name,
        parsec_root=str(request.parsec_root.resolve()),
        library_roots=tuple(str(path.resolve()) for path in request.library_roots),
        dbt_contract=str(request.dbt_contract.resolve()),
        dbt_revision=request.dbt_revision or _git_revision(request.dbt_root),
        benchmarks=tuple(measurements),
        total_seconds=monotonic() - started,
    )


def run_parsec(request: ParsecEvaluationRequest) -> EvaluationReport:
    """运行一组 PARSEC benchmark，并返回可序列化的汇总报告。"""

    suite, definitions = _select_definitions(request)
    if request.in_process:
        return _run_in_process(request, suite, definitions)
    return _run_isolated(request, suite, definitions)


__all__ = [
    "EvaluationApplicationError",
    "ParsecEvaluationRequest",
    "run_parsec",
]
