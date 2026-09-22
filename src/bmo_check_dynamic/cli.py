from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import sys
try:
    import resource
except ImportError:  # pragma: no cover - benchmark workers run on Linux/WSL.
    resource = None
from pathlib import Path

import yaml

from bmo_check_dynamic.application import (
    AnalyzeRequest,
    CaptureRequest,
    analyze as analyze_request,
    candidate_slices as candidate_slices_request,
    characterize as characterize_request,
    slice_plan as slice_plan_request,
    obligation_bottleneck as obligation_bottleneck_request,
    cycle_relevance as cycle_relevance_request,
    ppo_reduction as ppo_reduction_request,
    ppo_replay as ppo_replay_request,
    ppo_solver as ppo_solver_request,
    ppo_solver_replay as ppo_solver_replay_request,
    ppo_solver_side as ppo_solver_side_request,
    capture as capture_request,
)
from bmo_check_dynamic.capture import CaptureError
from bmo_check_dynamic.adapters import (
    DynamicTraceBindingError,
    replay_dynamic_certificate,
)
from bmo_check_dynamic.analysis import locate_instruction_site
from bmo_check_dynamic.analysis import run_isolated_solver_benchmark
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import (
    CampaignMember,
    CampaignSummary,
    DynamicCertificate,
    TracePpoReductionCertificate,
    TraceReducedSolverRunCertificate,
    TraceVerdict,
    BenchmarkSide,
    SolverBenchmarkChildReport,
    ShadowSolverPhase,
    SolverDiagnosticProfile,
)
from bmo_check_dynamic.storage import TraceStoreError
from bmo_check_dynamic.report import explain_certificate


EXIT_CODES = {
    TraceVerdict.TRACE_SAFE: 0,
    TraceVerdict.COUNTEREXAMPLE: 1,
    TraceVerdict.UNKNOWN: 2,
}


def _default_contract() -> Path:
    repository_spec = (
        Path(__file__).resolve().parents[2]
        / "specs"
        / "dynamic"
        / "dbt6-mo-off.yaml"
    )
    if repository_spec.is_file():
        return repository_spec
    return Path(__file__).resolve().parent / "data" / "dbt6-mo-off.yaml"


def _environment(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, content = value.partition("=")
        if not separator or not key:
            raise argparse.ArgumentTypeError("--env requires KEY=VALUE")
        result[key] = content
    return result


def _command(values: list[str]) -> tuple[str, ...]:
    if values and values[0] == "--":
        values = values[1:]
    if not values:
        raise argparse.ArgumentTypeError("missing program after --")
    return tuple(values)


def _capture(args: argparse.Namespace) -> int:
    manifest = capture_request(
        CaptureRequest(
            command=_command(args.command),
            output_dir=args.output,
            dynamorio_home=args.dynamorio_home,
            client_path=args.client,
            environment=tuple(sorted(_environment(args.env).items())),
            working_directory=args.cwd,
            max_thread_events=args.max_thread_events,
        )
    )
    print(manifest.model_dump_json(indent=2))
    return 0 if manifest.complete else 2


def _analysis_config(args: argparse.Namespace) -> DynamicConfig:
    return DynamicConfig(
        max_window_events=args.max_window_events,
        max_executions=args.max_executions,
        max_communication_edges=args.max_communication_edges,
        max_communication_active_events=args.max_communication_active_events,
        max_object_events=args.max_object_events,
        max_pages_per_access=args.max_pages_per_access,
        batch_size=args.batch_size,
        solver_timeout_ms=args.solver_timeout_ms,
        max_symbolic_terms=args.max_symbolic_terms,
        database_memory_limit_mb=args.database_memory_limit_mb,
        database_path=args.database,
        application_only=args.application_only,
    )


def _analyze(args: argparse.Namespace) -> int:
    certificate = analyze_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(certificate.model_dump_json(indent=2), encoding="utf-8")
    print(explain_certificate(certificate))
    return EXIT_CODES[certificate.verdict]


def _characterize(args: argparse.Namespace) -> int:
    report = characterize_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _slice_candidates(args: argparse.Namespace) -> int:
    report = candidate_slices_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _slice_plan(args: argparse.Namespace) -> int:
    report = slice_plan_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _obligation_bottleneck(args: argparse.Namespace) -> int:
    report = obligation_bottleneck_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    # 这是只读表征命令，不把诊断状态映射成 verdict exit code。
    return 0


def _cycle_relevance(args: argparse.Namespace) -> int:
    report = cycle_relevance_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _ppo_reduction(args: argparse.Namespace) -> int:
    report = ppo_reduction_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if args.certificate is not None:
        certificate = TracePpoReductionCertificate(
            trace_id=report.trace_id,
            windows=tuple(item.certificate for item in report.windows),
        )
        args.certificate.parent.mkdir(parents=True, exist_ok=True)
        args.certificate.write_text(
            certificate.model_dump_json(indent=2),
            encoding="utf-8",
        )
    print(report.model_dump_json(indent=2))
    return 0


def _ppo_replay(args: argparse.Namespace) -> int:
    certificate = TracePpoReductionCertificate.model_validate_json(
        args.certificate.read_text(encoding="utf-8")
    )
    report = ppo_replay_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        certificate,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0 if all(item.accepted for item in report.windows) else 2


def _ppo_solver(args: argparse.Namespace) -> int:
    reduction = None
    if args.reduction_certificate is not None:
        reduction = TracePpoReductionCertificate.model_validate_json(
            args.reduction_certificate.read_text(encoding="utf-8")
        )
    report, certificate = ppo_solver_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        reduction,
        execute_solver=not args.encoding_only,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if args.certificate is not None:
        args.certificate.parent.mkdir(parents=True, exist_ok=True)
        args.certificate.write_text(
            certificate.model_dump_json(indent=2),
            encoding="utf-8",
        )
    print(report.model_dump_json(indent=2))
    return 0


def _ppo_solver_replay(args: argparse.Namespace) -> int:
    reduction = TracePpoReductionCertificate.model_validate_json(
        args.reduction_certificate.read_text(encoding="utf-8")
    )
    solver = TraceReducedSolverRunCertificate.model_validate_json(
        args.certificate.read_text(encoding="utf-8")
    )
    report = ppo_solver_replay_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        reduction,
        solver,
        execute_solver=not args.encoding_only,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0 if all(item.accepted for item in report.windows) else 2


def _worker_rusage() -> tuple[float, float, float | None]:
    if resource is None:
        return 0.0, 0.0, None
    usage = resource.getrusage(resource.RUSAGE_SELF)
    rss = float(usage.ru_maxrss)
    if sys.platform != "darwin":
        rss /= 1024.0
    else:
        rss /= 1024.0 * 1024.0
    return usage.ru_utime, usage.ru_stime, rss


def _ppo_solver_worker(args: argparse.Namespace) -> int:
    reduction = None
    if args.reduction_certificate is not None:
        reduction = TracePpoReductionCertificate.model_validate_json(
            args.reduction_certificate.read_text(encoding="utf-8")
        )
    started = time.perf_counter()
    before_user, before_system, _ = _worker_rusage()
    report = ppo_solver_side_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        ),
        BenchmarkSide(args.side),
        reduction,
        execute_solver=args.phase == ShadowSolverPhase.SOLVER.value,
        repetition=args.repetition,
        budget_ms=args.budget_ms,
        profile=SolverDiagnosticProfile(args.profile),
    )
    after_user, after_system, peak_rss = _worker_rusage()
    wall_time_ms = max(0, int((time.perf_counter() - started) * 1000))
    replay_time_ms = sum(window.ppo_replay_time_ms for window in report.windows)
    build_time_ms = sum(window.build_time_ms for window in report.windows)
    solver_time_ms = sum(
        window.solver_time_ms
        for window in report.windows
        if window.solver_time_ms is not None
    )
    analysis_overhead_ms = max(
        0,
        wall_time_ms - replay_time_ms - build_time_ms - solver_time_ms,
    )
    child = SolverBenchmarkChildReport(
        trace_id=report.trace_id,
        side=report.side,
        phase=report.phase,
        profile=SolverDiagnosticProfile(args.profile),
        repetition=args.repetition,
        budget_ms=args.budget_ms,
        trace_complete=report.trace_complete,
        analysis_reached_windows=report.analysis_reached_windows,
        windows=report.windows,
        wall_time_ms=wall_time_ms,
        user_cpu_ms=max(0, int((after_user - before_user) * 1000)),
        system_cpu_ms=max(0, int((after_system - before_system) * 1000)),
        analysis_overhead_ms=analysis_overhead_ms,
        peak_rss_mb=peak_rss,
        reasons=report.reasons,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(child.model_dump_json(indent=2), encoding="utf-8")
    return 0


def _parse_budgets(value: str) -> tuple[int, ...]:
    budgets = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    if not budgets or any(item <= 0 for item in budgets):
        raise argparse.ArgumentTypeError("--budgets must contain positive milliseconds")
    return budgets


def _ppo_solver_benchmark(args: argparse.Namespace) -> int:
    certificates = tuple(args.reduction_certificate or ())
    if certificates and len(certificates) not in {1, len(args.trace)}:
        raise ValueError("--reduction-certificate may be given once or once per trace")
    if certificates:
        cert_paths = certificates
    else:
        cert_paths = ()
    sides = tuple(
        BenchmarkSide(item)
        for item in (args.side or [item.value for item in BenchmarkSide])
    )
    phase = ShadowSolverPhase(args.phase)
    report = run_isolated_solver_benchmark(
        tuple(args.trace),
        dbt_contract=args.dbt_contract,
        reduction_certificates=cert_paths,
        phase=phase,
        sides=sides,
        repetitions=args.repetitions,
        budgets_ms=args.budgets,
        config=_analysis_config(args),
        process_grace_ms=args.process_grace_ms,
        worker_output_dir=args.worker_output_dir,
        profile=SolverDiagnosticProfile(args.profile),
        python_executable=args.python_executable,
        keep_worker_outputs=args.keep_worker_outputs,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(report.model_dump_json(indent=2))
    return 0


def _run(args: argparse.Namespace) -> int:
    manifest = capture_request(
        CaptureRequest(
            command=_command(args.command),
            output_dir=args.trace,
            dynamorio_home=args.dynamorio_home,
            client_path=args.client,
            environment=tuple(sorted(_environment(args.env).items())),
            working_directory=args.cwd,
            max_thread_events=args.max_thread_events,
        )
    )
    if not manifest.complete:
        print("Trace is incomplete; analysis will return UNKNOWN.", file=sys.stderr)
    certificate = analyze_request(
        AnalyzeRequest(
            trace_dir=args.trace,
            dbt_contract=args.dbt_contract,
            config=_analysis_config(args),
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(certificate.model_dump_json(indent=2), encoding="utf-8")
    print(explain_certificate(certificate))
    return EXIT_CODES[certificate.verdict]


def _campaign(args: argparse.Namespace) -> int:
    document = yaml.safe_load(args.manifest.read_text(encoding="utf-8")) or {}
    runs = _validate_campaign_document(document)
    args.output.mkdir(parents=True, exist_ok=True)
    if (args.output / "campaign.json").exists():
        raise ValueError("campaign output already contains campaign.json")

    members: list[CampaignMember] = []
    first_by_key: dict[str, str] = {}
    unique_bytes = 0
    total_events = 0
    total_pcs = 0
    total_bytes = 0
    resource_limited_count = 0
    for item in runs:
        name = item["name"]
        repeat = item["repeat"]
        for iteration in range(repeat):
            trace_dir = args.output / f"{name}-{iteration:03d}"
            if trace_dir.exists():
                raise ValueError(f"campaign trace directory already exists: {trace_dir}")
            capture_started = time.perf_counter()
            manifest = None
            certificate: DynamicCertificate | None = None
            error: str | None = None
            try:
                manifest = capture_request(
                    CaptureRequest(
                        command=tuple(str(value) for value in item["command"]),
                        output_dir=trace_dir,
                        dynamorio_home=args.dynamorio_home,
                        client_path=args.client,
                        environment=tuple(
                            sorted(
                                (str(k), str(v))
                                for k, v in item.get("environment", {}).items()
                            )
                        ),
                        working_directory=(
                            Path(item["working_directory"])
                            if item.get("working_directory")
                            else None
                        ),
                        max_thread_events=args.max_thread_events,
                    )
                )
            except (CaptureError, OSError, ValueError) as caught:
                error = f"capture failed: {caught}"
            capture_seconds = time.perf_counter() - capture_started
            analysis_started = time.perf_counter()
            if error is None:
                try:
                    certificate = analyze_request(
                        AnalyzeRequest(
                            trace_dir=trace_dir,
                            dbt_contract=args.dbt_contract,
                            config=_analysis_config(args),
                        )
                    )
                except (OSError, ValueError, TraceStoreError) as caught:
                    error = f"analysis failed: {caught}"
            analysis_seconds = time.perf_counter() - analysis_started
            replay_seconds = 0.0
            if certificate is not None and certificate.verdict in {
                TraceVerdict.TRACE_SAFE,
                TraceVerdict.COUNTEREXAMPLE,
            }:
                replay_started = time.perf_counter()
                try:
                    replay_dynamic_certificate(
                        certificate,
                        trace_dir,
                        args.dbt_contract,
                        config=_analysis_config(args),
                    )
                except (DynamicTraceBindingError, OSError, ValueError) as caught:
                    error = f"certificate replay failed: {caught}"
                    certificate = certificate.model_copy(
                        update={
                            "verdict": TraceVerdict.UNKNOWN,
                            "unknown_reasons": tuple(
                                dict.fromkeys(
                                    (*certificate.unknown_reasons, str(caught))
                                )
                            ),
                        }
                    )
                replay_seconds = time.perf_counter() - replay_started

            certificate_path: Path | None = None
            if certificate is not None:
                certificate_path = trace_dir / "certificate.json"
                certificate_path.write_text(
                    certificate.model_dump_json(indent=2), encoding="utf-8"
                )
            trace_bytes = _directory_bytes(trace_dir)
            verdict = certificate.verdict if certificate is not None else TraceVerdict.UNKNOWN
            trace_id = (
                certificate.scope.trace_ids[0]
                if certificate is not None and certificate.scope.trace_ids
                else None
            )
            trace_sha256 = (
                certificate.scope.trace_sha256[0]
                if certificate is not None and certificate.scope.trace_sha256
                else None
            )
            dedup_key = _certificate_dedup_key(certificate)
            duplicate_of = first_by_key.get(dedup_key) if dedup_key else None
            if dedup_key and duplicate_of is None:
                first_by_key[dedup_key] = f"{name}-{iteration:03d}"
                unique_bytes += trace_bytes
            elif dedup_key is None:
                # 没有稳定 digest 的失败成员不能和其他成员合并，仍计入
                # 唯一存储，避免资源报告把失败输入的占用记成零。
                unique_bytes += trace_bytes
            resource_limited = _certificate_resource_limited(certificate)
            if resource_limited:
                resource_limited_count += 1
            event_count = certificate.event_count if certificate is not None else 0
            unique_pc_count = certificate.unique_pc_count if certificate is not None else 0
            total_events += event_count
            total_pcs += unique_pc_count
            total_bytes += trace_bytes
            members.append(
                CampaignMember(
                    name=name,
                    iteration=iteration,
                    trace_directory=str(trace_dir.relative_to(args.output)),
                    certificate_path=(
                        str(certificate_path.relative_to(args.output))
                        if certificate_path is not None
                        else None
                    ),
                    verdict=verdict,
                    trace_id=trace_id,
                    trace_sha256=trace_sha256,
                    event_count=event_count,
                    unique_pc_count=unique_pc_count,
                    trace_bytes=trace_bytes,
                    capture_seconds=capture_seconds,
                    analysis_seconds=analysis_seconds,
                    replay_seconds=replay_seconds,
                    max_rss_kb=_max_rss_kb(),
                    resource_limited=resource_limited,
                    dedup_key=dedup_key,
                    duplicate_of=duplicate_of,
                    error=error,
                )
            )

    if not members:
        raise ValueError("campaign produced no trace members")
    verdict = _campaign_verdict(member.verdict for member in members)
    summary = CampaignSummary(
        verdict=verdict,
        trace_count=len(members),
        member_count=len(members),
        verdict_counts={
            candidate.value: sum(item.verdict == candidate for item in members)
            for candidate in TraceVerdict
        },
        unique_trace_count=len(first_by_key) + sum(
            item.dedup_key is None for item in members
        ),
        duplicate_trace_count=sum(item.duplicate_of is not None for item in members),
        total_events=total_events,
        total_unique_pcs_per_trace=total_pcs,
        total_trace_bytes=total_bytes,
        unique_trace_bytes=unique_bytes,
        resource_limited_count=resource_limited_count,
        certificates=tuple(members),
    )
    (args.output / "campaign.json").write_text(
        summary.model_dump_json(indent=2), encoding="utf-8"
    )
    print(f"Campaign verdict: {verdict.value} ({len(members)} traces)")
    return EXIT_CODES[verdict]


def _validate_campaign_document(document: object) -> list[dict[str, object]]:
    if not isinstance(document, dict):
        raise ValueError("campaign manifest must be a mapping")
    raw_runs = document.get("runs")
    if not isinstance(raw_runs, list) or not raw_runs:
        raise ValueError("campaign manifest requires a non-empty runs list")
    runs: list[dict[str, object]] = []
    names: set[str] = set()
    for item in raw_runs:
        if not isinstance(item, dict) or not isinstance(item.get("command"), list):
            raise ValueError("each campaign run requires command: [..]")
        command = item["command"]
        if not command or any(not isinstance(value, str) or not value for value in command):
            raise ValueError("campaign command must contain non-empty strings")
        name = str(item.get("name", "run"))
        if not name or name in {".", ".."} or Path(name).name != name:
            raise ValueError("campaign run name must be a unique directory name")
        if name in names:
            raise ValueError(f"duplicate campaign run name: {name}")
        names.add(name)
        try:
            repeat = int(item.get("repeat", 1))
        except (TypeError, ValueError) as error:
            raise ValueError("campaign repeat must be a positive integer") from error
        if repeat < 1:
            raise ValueError("campaign repeat must be a positive integer")
        environment = item.get("environment", {})
        if not isinstance(environment, dict):
            raise ValueError("campaign environment must be a mapping")
        runs.append({**item, "name": name, "repeat": repeat})
    return runs


def _campaign_verdict(verdicts: object) -> TraceVerdict:
    values = tuple(verdicts)
    if not values:
        raise ValueError("campaign cannot aggregate an empty member set")
    if TraceVerdict.COUNTEREXAMPLE in values:
        return TraceVerdict.COUNTEREXAMPLE
    if TraceVerdict.UNKNOWN in values:
        return TraceVerdict.UNKNOWN
    return TraceVerdict.TRACE_SAFE


def _certificate_dedup_key(certificate: DynamicCertificate | None) -> str | None:
    if certificate is None or not certificate.scope.trace_sha256:
        return None
    config_sha = certificate.binding.config_sha256 if certificate.binding else (
        certificate.coverage.config_sha256 if certificate.coverage else None
    )
    material = {
        "trace_sha256": certificate.scope.trace_sha256[0],
        "contract_sha256": certificate.dbt_contract_sha256,
        "config_sha256": config_sha,
        "schema_version": certificate.schema_version,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _certificate_resource_limited(certificate: DynamicCertificate | None) -> bool:
    if certificate is None:
        return True
    return any(
        marker in reason.lower()
        for reason in certificate.unknown_reasons
        for marker in ("limit", "budget", "resource", "memory")
    )


def _directory_bytes(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(
        item.stat().st_size
        for item in path.rglob("*")
        if item.is_file()
    )


def _max_rss_kb() -> int | None:
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # Linux reports KiB; macOS reports bytes. This process is Linux in the
        # supported deployment, but normalizing keeps the field interpretable.
        return value if value < 10_000_000 else value // 1024
    except (ImportError, AttributeError, OSError):
        return None


def _explain(args: argparse.Namespace) -> int:
    certificate = DynamicCertificate.model_validate_json(
        args.certificate.read_text(encoding="utf-8")
    )
    print(explain_certificate(certificate))
    return EXIT_CODES[certificate.verdict]


def _locate(args: argparse.Namespace) -> int:
    evidence = locate_instruction_site(args.trace, args.module, args.offset)
    print(evidence.model_dump_json(indent=2))
    return 0


def _verify(args: argparse.Namespace) -> int:
    certificate = DynamicCertificate.model_validate_json(
        args.certificate.read_text(encoding="utf-8")
    )
    replay_dynamic_certificate(
        certificate,
        args.trace,
        args.dbt_contract,
        config=_analysis_config(args),
    )
    print(f"Certificate replay verified: {certificate.verdict.value}")
    return EXIT_CODES[certificate.verdict]


def _diagnose(args: argparse.Namespace) -> int:
    """把诊断命令交给 CLI 组合层，避免 dynamic route 读取 diagnostics 内部。"""

    from bmo_check_cli.diagnose import run_diagnose

    return run_diagnose(args)


def _hybrid(args: argparse.Namespace) -> int:
    """单 workload 编排交给 CLI package，dynamic route 不反向依赖 workflow。"""

    from bmo_check_cli.hybrid import run_hybrid

    return run_hybrid(args)


def _add_capture_options(parser: argparse.ArgumentParser) -> None:
    default_home = Path(os.environ.get("DYNAMORIO_HOME", "/opt/dynamorio"))
    parser.add_argument("--dynamorio-home", type=Path, default=default_home)
    parser.add_argument(
        "--client",
        type=Path,
        default=Path(__file__).parent / "native" / "build" / "libbmo_trace.so",
    )
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--cwd", type=Path)
    parser.add_argument(
        "--max-thread-events",
        type=int,
        help="stop recording a thread after this many events and return UNKNOWN",
    )


def _add_analysis_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dbt-contract", type=Path, default=_default_contract())
    parser.add_argument("--database", type=Path)
    parser.add_argument("--max-window-events", type=int, default=64)
    parser.add_argument("--max-executions", type=int, default=20_000)
    parser.add_argument("--max-communication-edges", type=int, default=100_000)
    parser.add_argument("--max-communication-active-events", type=int, default=600_000)
    parser.add_argument("--max-object-events", type=int, default=5_000_000)
    parser.add_argument("--max-pages-per-access", type=int, default=16)
    parser.add_argument("--batch-size", type=int, default=50_000)
    parser.add_argument("--solver-timeout-ms", type=int, default=10_000)
    parser.add_argument("--max-symbolic-terms", type=int, default=100_000)
    parser.add_argument("--database-memory-limit-mb", type=int, default=512)
    parser.add_argument(
        "--application-only",
        action="store_true",
        help=(
            "prove main-ELF-touching communication after scanning all candidate pages; "
            "runtime-only edges are counted and excluded from the application window "
            "only after the complete scan"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bmo-check",
        description="Dynamic trace-scoped verifier for DBT6 mo-off",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    capture = subparsers.add_parser("capture", help="capture a native x86-64 trace")
    capture.add_argument("--output", type=Path, required=True)
    _add_capture_options(capture)
    capture.add_argument("command", nargs=argparse.REMAINDER)
    capture.set_defaults(handler=_capture)

    analyze = subparsers.add_parser("analyze", help="analyze one trace directory")
    analyze.add_argument("trace", type=Path)
    analyze.add_argument("--output", type=Path, required=True)
    _add_analysis_options(analyze)
    analyze.set_defaults(handler=_analyze)

    characterize = subparsers.add_parser(
        "characterize",
        help="scan communication and windows without running the proof checker",
    )
    characterize.add_argument("trace", type=Path)
    characterize.add_argument("--output", type=Path, required=True)
    _add_analysis_options(characterize)
    characterize.set_defaults(handler=_characterize)

    slice_candidates = subparsers.add_parser(
        "slice-candidates",
        help="report obligation-aware slice candidates without running proof",
    )
    slice_candidates.add_argument("trace", type=Path)
    slice_candidates.add_argument("--output", type=Path, required=True)
    _add_analysis_options(slice_candidates)
    slice_candidates.set_defaults(handler=_slice_candidates)

    slice_plan = subparsers.add_parser(
        "slice-plan",
        help="plan only obligation-preserving partitions without running proof",
    )
    slice_plan.add_argument("trace", type=Path)
    slice_plan.add_argument("--output", type=Path, required=True)
    _add_analysis_options(slice_plan)
    slice_plan.set_defaults(handler=_slice_plan)

    obligation_bottleneck = subparsers.add_parser(
        "obligation-bottleneck",
        help="characterize obligation bottlenecks without running proof",
    )
    obligation_bottleneck.add_argument("trace", type=Path)
    obligation_bottleneck.add_argument("--output", type=Path, required=True)
    _add_analysis_options(obligation_bottleneck)
    obligation_bottleneck.set_defaults(handler=_obligation_bottleneck)

    cycle_relevance = subparsers.add_parser(
        "cycle-relevance",
        help="characterize cycle-relevant relations without running proof",
    )
    cycle_relevance.add_argument("trace", type=Path)
    cycle_relevance.add_argument("--output", type=Path, required=True)
    _add_analysis_options(cycle_relevance)
    cycle_relevance.set_defaults(handler=_cycle_relevance)

    ppo_reduction = subparsers.add_parser(
        "ppo-reduction",
        help="build and independently replay a PPO reachability shadow certificate",
    )
    ppo_reduction.add_argument("trace", type=Path)
    ppo_reduction.add_argument("--output", type=Path, required=True)
    ppo_reduction.add_argument("--certificate", type=Path)
    _add_analysis_options(ppo_reduction)
    ppo_reduction.set_defaults(handler=_ppo_reduction)

    ppo_replay = subparsers.add_parser(
        "ppo-replay",
        help="independently replay a PPO reduction certificate",
    )
    ppo_replay.add_argument("trace", type=Path)
    ppo_replay.add_argument("--certificate", type=Path, required=True)
    ppo_replay.add_argument("--output", type=Path, required=True)
    _add_analysis_options(ppo_replay)
    ppo_replay.set_defaults(handler=_ppo_replay)

    ppo_solver = subparsers.add_parser(
        "ppo-solver-compare",
        help="compare full and certified-reduced PPO shadow solver runs",
    )
    ppo_solver.add_argument("trace", type=Path)
    ppo_solver.add_argument("--reduction-certificate", type=Path)
    ppo_solver.add_argument("--output", type=Path, required=True)
    ppo_solver.add_argument("--certificate", type=Path)
    ppo_solver.add_argument(
        "--encoding-only",
        action="store_true",
        help="build full/reduced Z3 assertions without calling the solver",
    )
    _add_analysis_options(ppo_solver)
    ppo_solver.set_defaults(handler=_ppo_solver)

    ppo_solver_replay = subparsers.add_parser(
        "ppo-solver-replay",
        help="replay a solver-level full/reduced binding certificate",
    )
    ppo_solver_replay.add_argument("trace", type=Path)
    ppo_solver_replay.add_argument("--reduction-certificate", type=Path, required=True)
    ppo_solver_replay.add_argument("--certificate", type=Path, required=True)
    ppo_solver_replay.add_argument("--output", type=Path, required=True)
    ppo_solver_replay.add_argument("--encoding-only", action="store_true")
    _add_analysis_options(ppo_solver_replay)
    ppo_solver_replay.set_defaults(handler=_ppo_solver_replay)

    ppo_solver_worker = subparsers.add_parser(
        "ppo-solver-worker",
        help=argparse.SUPPRESS,
    )
    ppo_solver_worker.add_argument("trace", type=Path)
    ppo_solver_worker.add_argument("--side", choices=[item.value for item in BenchmarkSide], required=True)
    ppo_solver_worker.add_argument("--phase", choices=[item.value for item in ShadowSolverPhase], required=True)
    ppo_solver_worker.add_argument("--repetition", type=int, required=True)
    ppo_solver_worker.add_argument("--budget-ms", type=int, required=True)
    ppo_solver_worker.add_argument(
        "--profile",
        choices=[item.value for item in SolverDiagnosticProfile],
        default=SolverDiagnosticProfile.FULL.value,
    )
    ppo_solver_worker.add_argument("--reduction-certificate", type=Path)
    ppo_solver_worker.add_argument("--output", type=Path, required=True)
    ppo_solver_worker.add_argument("--encoding-only", action="store_true")
    _add_analysis_options(ppo_solver_worker)
    ppo_solver_worker.set_defaults(handler=_ppo_solver_worker)

    ppo_solver_benchmark = subparsers.add_parser(
        "ppo-solver-benchmark",
        help="measure full/reduced shadow solver runs in isolated child processes",
    )
    ppo_solver_benchmark.add_argument("trace", type=Path, nargs="+")
    ppo_solver_benchmark.add_argument("--reduction-certificate", type=Path, action="append")
    ppo_solver_benchmark.add_argument("--output", type=Path, required=True)
    ppo_solver_benchmark.add_argument(
        "--phase",
        choices=[item.value for item in ShadowSolverPhase],
        default=ShadowSolverPhase.ENCODING.value,
    )
    ppo_solver_benchmark.add_argument(
        "--side",
        choices=[item.value for item in BenchmarkSide],
        action="append",
        default=None,
        help="repeat for each side; defaults to full and reduced",
    )
    ppo_solver_benchmark.add_argument("--repetitions", type=int, default=3)
    ppo_solver_benchmark.add_argument(
        "--profile",
        choices=[item.value for item in SolverDiagnosticProfile],
        default=SolverDiagnosticProfile.FULL.value,
        help="diagnostic-only constraint ablation profile",
    )
    ppo_solver_benchmark.add_argument(
        "--budgets",
        type=_parse_budgets,
        default=(60_000,),
        help="comma-separated per-child solver/construction budgets in milliseconds",
    )
    ppo_solver_benchmark.add_argument(
        "--process-grace-ms",
        type=int,
        default=120_000,
        help="extra external grace after the in-process budget",
    )
    ppo_solver_benchmark.add_argument(
        "--worker-output-dir",
        type=Path,
        default=Path(".experiments") / "solver-benchmark-workers",
    )
    ppo_solver_benchmark.add_argument("--keep-worker-outputs", action="store_true")
    ppo_solver_benchmark.add_argument(
        "--python-executable",
        default=sys.executable,
        help="Python executable used for isolated workers",
    )
    _add_analysis_options(ppo_solver_benchmark)
    ppo_solver_benchmark.set_defaults(handler=_ppo_solver_benchmark)

    run = subparsers.add_parser("run", help="capture and immediately analyze")
    run.add_argument("--trace", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    _add_capture_options(run)
    _add_analysis_options(run)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(handler=_run)

    campaign = subparsers.add_parser("campaign", help="run a trace corpus")
    campaign.add_argument("manifest", type=Path)
    campaign.add_argument("--output", type=Path, required=True)
    _add_capture_options(campaign)
    _add_analysis_options(campaign)
    campaign.set_defaults(handler=_campaign)

    explain = subparsers.add_parser("explain", help="explain a certificate")
    explain.add_argument("certificate", type=Path)
    explain.set_defaults(handler=_explain)

    verify = subparsers.add_parser(
        "verify", help="independently replay a determinate dynamic certificate"
    )
    verify.add_argument("certificate", type=Path)
    verify.add_argument("--trace", type=Path, required=True)
    _add_analysis_options(verify)
    verify.set_defaults(handler=_verify)

    locate = subparsers.add_parser(
        "locate", help="locate one module-relative instruction in a trace"
    )
    locate.add_argument("trace", type=Path)
    locate.add_argument("--module", required=True)
    locate.add_argument("--offset", type=lambda value: int(value, 0), required=True)
    locate.set_defaults(handler=_locate)

    diagnose = subparsers.add_parser(
        "diagnose",
        help="correlate static Unknowns with a dynamic diagnostic snapshot",
    )
    # 位置参数是最短调用形式；选项别名方便脚本明确标注输入角色。
    diagnose.add_argument("static_snapshot", nargs="?", type=Path)
    diagnose.add_argument("dynamic_snapshot", nargs="?", type=Path)
    diagnose.add_argument("--static-snapshot", dest="static_snapshot_option", type=Path)
    diagnose.add_argument("--dynamic-snapshot", dest="dynamic_snapshot_option", type=Path)
    diagnose.add_argument(
        "--trace",
        dest="trace_dir",
        type=Path,
        help="build the dynamic snapshot by streaming a trace directory",
    )
    diagnose.add_argument(
        "--max-snapshot-sites",
        type=int,
        default=100_000,
        help="bound distinct thread/site observations when --trace is used",
    )
    diagnose.add_argument("--output", type=Path, required=True)
    diagnose.add_argument(
        "--affine-output",
        type=Path,
        help="also write the trace-bound UnknownAffineBounds coverage report",
    )
    diagnose.add_argument("--static-certificate", type=Path)
    diagnose.add_argument("--trace-certificate", type=Path)
    diagnose.add_argument("--static-certificate-id")
    diagnose.add_argument("--trace-certificate-id")
    diagnose.add_argument(
        "--unknown-id",
        action="append",
        default=[],
        help="limit the report to this static EvidenceId (repeatable)",
    )
    diagnose.set_defaults(handler=_diagnose)

    hybrid = subparsers.add_parser(
        "hybrid",
        help="run static and dynamic analysis for one workload and write one report",
    )
    hybrid.add_argument("--workload", type=Path, required=True, help="versioned YAML workload manifest")
    hybrid.add_argument("--output-dir", type=Path, required=True)
    hybrid.add_argument(
        "--dynamorio-home",
        type=Path,
        help="override the manifest's DynamoRIO root (or DYNAMORIO_HOME default)",
    )
    hybrid.add_argument(
        "--client",
        type=Path,
        help="override the manifest's native client path",
    )
    hybrid.set_defaults(handler=_hybrid)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return int(args.handler(args))
    except (CaptureError, OSError, ValueError) as error:
        print(f"bmo-check: error: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
