from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from time import monotonic

from bmo_check.analysis import analyze_shared_state, extract_memory_events
from bmo_check.binary.dependency_closure import build_program_manifest
from bmo_check.binary.symbols import function_symbols
from bmo_check.config import load_contract_version, load_function_effect_contract
from bmo_check.controlflow import recover_control_flow
from bmo_check.model import (
    AblationMeasurement,
    BenchmarkMeasurement,
    CheckerLimits,
    EvaluationReport,
    EvaluationStatus,
    ExecutionScope,
    FingerprintReport,
    NativeRunMeasurement,
    PhaseTimings,
    PortabilityCertificate,
    ProgramManifest,
    ProgramRecoveryReport,
    ProgramSliceReport,
    RiskScreeningStatus,
    StrictModel,
    UnknownFact,
    UnknownKind,
)
from bmo_check.evaluation import (
    ABLATION_LEVELS,
    ablate_shared_state,
    find_publication_risks,
    load_evaluation_suite,
    run_native_benchmark,
)
from bmo_check.proof import explain_certificate, verify_portability
from bmo_check.synchronization import analyze_pthread_synchronization
from bmo_check.slicing import build_shared_memory_slice
from bmo_check.threading import discover_pthread_threads


def _argv_json(value: str) -> tuple[str, ...]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError(f"invalid JSON: {error}") from error
    if not isinstance(parsed, list) or not all(
        isinstance(item, str) for item in parsed
    ):
        raise argparse.ArgumentTypeError("argv JSON must be an array of strings")
    return tuple(parsed)


def _thread_range(value: str) -> tuple[int, int]:
    try:
        if ":" in value:
            low_text, high_text = value.split(":", 1)
            low, high = int(low_text), int(high_text)
        else:
            low = high = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "thread range must be N or MIN:MAX"
        ) from error
    if low < 1 or high < low:
        raise argparse.ArgumentTypeError(
            "thread range requires 1 <= MIN <= MAX"
        )
    return low, high


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("value must be a positive integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _environment(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise argparse.ArgumentTypeError(
                f"environment entry must be KEY=VALUE: {value!r}"
            )
        key, item = value.split("=", 1)
        if not key:
            raise argparse.ArgumentTypeError("environment key cannot be empty")
        result[key] = item
    return result


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


def _write_json(report: StrictModel, output: Path | None) -> None:
    text = report.model_dump_json(indent=2) + "\n"
    if output is None:
        sys.stdout.write(text)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")


def _build_manifest(args: argparse.Namespace) -> ProgramManifest:
    contract = load_contract_version(args.dbt_contract)
    effect_contract = load_function_effect_contract(args.function_effects)
    thread_min: int | None = None
    thread_max: int | None = None
    if args.threads is not None:
        thread_min, thread_max = args.threads

    execution = ExecutionScope(
        argv=args.argv_json,
        thread_count_min=thread_min,
        thread_count_max=thread_max,
        environment=_environment(args.environment),
    )
    revision = args.dbt_revision or _git_revision(args.dbt_root)
    manifest = build_program_manifest(
        executable_path=args.executable,
        library_roots=tuple(args.library_root),
        execution=execution,
        dbt_contract_version=contract.version,
        dbt_revision=revision,
    )
    manifest = manifest.model_copy(
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
        manifest = manifest.model_copy(
            update={
                "closure_complete": False,
                "unknowns": manifest.unknowns + contract_unknowns,
            }
        )
    return manifest


def _fingerprint(args: argparse.Namespace) -> int:
    manifest = _build_manifest(args)
    _write_json(FingerprintReport(manifest=manifest), args.output)
    return 0 if manifest.closure_complete else 1


def _build_recovery(args: argparse.Namespace) -> ProgramRecoveryReport:
    manifest = _build_manifest(args)
    if manifest.executable is None:
        return ProgramRecoveryReport(manifest=manifest)

    control_flow = recover_control_flow(manifest.executable, manifest)
    threads = discover_pthread_threads(
        manifest.executable, manifest, control_flow
    )
    synchronization = []
    recovery_unknowns: list[UnknownFact] = []
    called_pthread_apis = {
        call.target_symbol
        for call in control_flow.call_sites
        if call.target_symbol is not None and call.target_symbol.startswith("pthread_")
    }
    for library in manifest.libraries:
        try:
            names = {symbol.name for symbol in function_symbols(library)}
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
                    args.pthread_spec,
                    args.dbt_contract,
                    requested_apis=implemented_apis,
                )
            )
        except Exception as error:
            # 配置或分析失败不能表现成“这个库没有同步 effect”。
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


def _recover(args: argparse.Namespace) -> int:
    recovery = _build_recovery(args)
    _write_json(recovery, args.output)
    return 0 if recovery.manifest.closure_complete else 1


def _build_slice_report(args: argparse.Namespace) -> ProgramSliceReport:
    recovery = _build_recovery(args)
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

    events = extract_memory_events(
        module,
        recovery.control_flow,
        recovery.thread_roles,
        recovery.synchronization,
        function_effects=load_function_effect_contract(
            args.function_effects
        ).effects,
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
    return ProgramSliceReport(
        recovery=recovery,
        memory_events=events,
        shared_state=shared_state,
        shared_slice=shared_slice,
        unknowns=recovery.unknowns,
    )


def _slice(args: argparse.Namespace) -> int:
    report = _build_slice_report(args)
    _write_json(report, args.output)
    return 0 if report.recovery.manifest.closure_complete else 1


def _checker_limits(args: argparse.Namespace) -> CheckerLimits:
    return CheckerLimits(
        max_events=args.max_events,
        max_threads=args.max_threads,
        max_executions=args.max_executions,
        timeout_ms=args.checker_timeout_ms,
    )


def _analyze(args: argparse.Namespace) -> int:
    report = _build_slice_report(args)
    certificate = verify_portability(report, _checker_limits(args))
    _write_json(certificate, args.output)
    if certificate.verdict.value == "SAFE":
        return 0
    if certificate.verdict.value == "COUNTEREXAMPLE":
        return 3
    return 1


def _explain(args: argparse.Namespace) -> int:
    try:
        certificate = PortabilityCertificate.model_validate_json(
            args.certificate.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as error:
        raise argparse.ArgumentTypeError(
            f"cannot read certificate {args.certificate}: {error}"
        ) from error
    sys.stdout.write(explain_certificate(certificate))
    return 0


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evaluate(args: argparse.Namespace) -> int:
    if args.in_process:
        try:
            import resource

            limit = args.analysis_memory_limit_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        except (ImportError, OSError, ValueError):
            # 非 WSL 平台不能设置地址空间上限时，父进程仍保留墙钟超时和退出码。
            pass
    try:
        suite = load_evaluation_suite(args.suite)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    requested = set(args.benchmark)
    available = {item.id for item in suite.benchmarks}
    missing = requested - available
    if missing:
        raise argparse.ArgumentTypeError(
            f"suite has no benchmark IDs: {', '.join(sorted(missing))}"
        )
    definitions = tuple(
        item for item in suite.benchmarks if not requested or item.id in requested
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    limits = _checker_limits(args)
    suite_started = monotonic()
    measurements: list[BenchmarkMeasurement] = []

    for definition in definitions:
        threads = args.threads_override or definition.threads
        argv = tuple(item.replace("{threads}", str(threads)) for item in definition.argv)
        executable = (args.parsec_root / definition.executable).resolve()
        pipeline_args = argparse.Namespace(
            executable=executable,
            library_root=args.library_root,
            argv_json=argv,
            threads=(threads, threads),
            environment=args.environment,
            dbt_contract=args.dbt_contract,
            dbt_revision=args.dbt_revision,
            dbt_root=args.dbt_root,
            pthread_spec=args.pthread_spec,
            function_effects=args.function_effects,
        )

        recovery_started = monotonic()
        recovery = _build_recovery(pipeline_args)
        recovery_seconds = monotonic() - recovery_started
        event_seconds = 0.0
        shared_state_seconds = 0.0
        memory_events = None
        shared_state = None
        module = recovery.manifest.executable
        if (
            module is not None
            and recovery.control_flow is not None
            and recovery.thread_roles is not None
        ):
            event_started = monotonic()
            memory_events = extract_memory_events(
                module,
                recovery.control_flow,
                recovery.thread_roles,
                recovery.synchronization,
                function_effects=load_function_effect_contract(
                    args.function_effects
                ).effects,
            )
            event_seconds = monotonic() - event_started
            shared_started = monotonic()
            shared_state = analyze_shared_state(
                module,
                recovery.control_flow,
                recovery.thread_roles,
                memory_events,
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
                analysis_options={"pruning_level": level.value},
            )
            checker_seconds = monotonic() - checker_started
            screening_started = monotonic()
            findings = (
                find_publication_risks(shared_slice)
                if shared_slice is not None
                else ()
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
                args.output_dir / definition.id / f"{level.value}.certificate.json"
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
                    total_events=(
                        shared_slice.coverage.total_events if shared_slice else 0
                    ),
                    remaining_events=(
                        shared_slice.coverage.remaining_shared_events
                        if shared_slice
                        else 0
                    ),
                    conflict_candidates=(
                        len(shared_slice.conflicts) if shared_slice else 0
                    ),
                    pruning_counts=pruning_counts,
                    checker_executions=certificate.checker.examined_executions,
                    verdict=certificate.verdict,
                    relevant_unknowns=len(certificate.relevant_unknowns),
                    screening_status=screening_status,
                    risk_findings=findings,
                    certificate_file=str(
                        certificate_path.relative_to(args.output_dir).as_posix()
                    ),
                    certificate_sha256=_file_sha256(certificate_path),
                )
            )

        native = NativeRunMeasurement()
        if args.run_native:
            native = run_native_benchmark(
                definition,
                args.parsec_root,
                argv,
                args.native_timeout_seconds,
            )
        measurements.append(
            BenchmarkMeasurement(
                benchmark_id=definition.id,
                executable=str(executable),
                executable_sha256=(module.sha256 if module is not None else None),
                argv=argv,
                threads=threads,
                ablations=tuple(ablations),
                native_run=native,
            )
        )

    report = EvaluationReport(
        suite_name=suite.name,
        parsec_root=str(args.parsec_root.resolve()),
        library_roots=tuple(str(path.resolve()) for path in args.library_root),
        dbt_contract=str(args.dbt_contract.resolve()),
        dbt_revision=args.dbt_revision or _git_revision(args.dbt_root),
        benchmarks=tuple(measurements),
        total_seconds=monotonic() - suite_started,
    )
    _write_json(report, args.output_dir / "evaluation.json")
    return 0


def _evaluation_worker_command(
    args: argparse.Namespace, benchmark_id: str
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "bmo_check.cli",
        "evaluate",
        "--suite",
        str(args.suite),
        "--parsec-root",
        str(args.parsec_root),
        "--benchmark",
        benchmark_id,
        "--dbt-contract",
        str(args.dbt_contract),
        "--pthread-spec",
        str(args.pthread_spec),
        "--function-effects",
        str(args.function_effects),
        "--output-dir",
        str(args.output_dir),
        "--analysis-memory-limit-mb",
        str(args.analysis_memory_limit_mb),
        "--analysis-timeout-seconds",
        str(args.analysis_timeout_seconds),
        "--max-events",
        str(args.max_events),
        "--max-threads",
        str(args.max_threads),
        "--max-executions",
        str(args.max_executions),
        "--checker-timeout-ms",
        str(args.checker_timeout_ms),
        "--in-process",
    ]
    for root in args.library_root:
        command.extend(("--library-root", str(root)))
    for item in args.environment:
        command.extend(("--environment", item))
    if args.threads_override is not None:
        command.extend(("--threads-override", str(args.threads_override)))
    if args.dbt_revision:
        command.extend(("--dbt-revision", args.dbt_revision))
    if args.dbt_root:
        command.extend(("--dbt-root", str(args.dbt_root)))
    if args.run_native:
        command.append("--run-native")
        command.extend(
            ("--native-timeout-seconds", str(args.native_timeout_seconds))
        )
    return command


def _evaluate_isolated(args: argparse.Namespace) -> int:
    if args.in_process:
        return _evaluate(args)
    try:
        suite = load_evaluation_suite(args.suite)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    requested = set(args.benchmark)
    available = {item.id for item in suite.benchmarks}
    missing = requested - available
    if missing:
        raise argparse.ArgumentTypeError(
            f"suite has no benchmark IDs: {', '.join(sorted(missing))}"
        )
    definitions = tuple(
        item for item in suite.benchmarks if not requested or item.id in requested
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    started = monotonic()
    measurements: list[BenchmarkMeasurement] = []
    worker_report = args.output_dir / "evaluation.json"
    for definition in definitions:
        worker_report.unlink(missing_ok=True)
        status = EvaluationStatus.FAILED
        failure = "evaluation worker did not produce a report"
        try:
            completed = subprocess.run(
                _evaluation_worker_command(args, definition.id),
                capture_output=True,
                text=True,
                timeout=args.analysis_timeout_seconds,
                check=False,
            )
            if completed.returncode == 0 and worker_report.is_file():
                partial = EvaluationReport.model_validate_json(
                    worker_report.read_text(encoding="utf-8")
                )
                measurements.append(partial.benchmarks[0])
                continue
            if completed.returncode < 0 or "MemoryError" in completed.stderr:
                status = EvaluationStatus.RESOURCE_LIMIT
                failure = (
                    f"worker exited {completed.returncode} under the "
                    f"{args.analysis_memory_limit_mb} MiB memory limit"
                )
            else:
                failure = (
                    completed.stderr.strip()[-2000:]
                    or f"worker exited {completed.returncode} without a report"
                )
        except subprocess.TimeoutExpired:
            status = EvaluationStatus.TIMEOUT
            failure = (
                f"analysis exceeded {args.analysis_timeout_seconds} seconds"
            )

        threads = args.threads_override or definition.threads
        argv = tuple(item.replace("{threads}", str(threads)) for item in definition.argv)
        executable = (args.parsec_root / definition.executable).resolve()
        native = NativeRunMeasurement()
        if args.run_native:
            native = run_native_benchmark(
                definition,
                args.parsec_root,
                argv,
                args.native_timeout_seconds,
            )
        measurements.append(
            BenchmarkMeasurement(
                benchmark_id=definition.id,
                executable=str(executable),
                executable_sha256=(
                    _file_sha256(executable) if executable.is_file() else None
                ),
                argv=argv,
                threads=threads,
                status=status,
                failure=failure,
                native_run=native,
            )
        )

    report = EvaluationReport(
        suite_name=suite.name,
        parsec_root=str(args.parsec_root.resolve()),
        library_roots=tuple(str(path.resolve()) for path in args.library_root),
        dbt_contract=str(args.dbt_contract.resolve()),
        dbt_revision=args.dbt_revision or _git_revision(args.dbt_root),
        benchmarks=tuple(measurements),
        total_seconds=monotonic() - started,
    )
    _write_json(report, worker_report)
    return 0


def _add_input_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--executable", "--exe", type=Path, required=True)
    parser.add_argument(
        "--library-root",
        type=Path,
        action="append",
        default=[],
        help="ordered directory containing concrete guest libraries",
    )
    parser.add_argument("--argv-json", type=_argv_json, default=(), metavar="JSON")
    parser.add_argument("--threads", type=_thread_range, metavar="N|MIN:MAX")
    parser.add_argument(
        "--environment", action="append", default=[], metavar="KEY=VALUE"
    )
    parser.add_argument("--dbt-contract", type=Path, required=True)
    parser.add_argument("--dbt-revision")
    parser.add_argument("--dbt-root", type=Path)
    parser.add_argument(
        "--function-effects",
        type=Path,
        default=Path("specs/library-effects.yaml"),
    )
    parser.add_argument("--output", type=Path)


def _add_checker_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-events", type=_positive_int, default=24)
    parser.add_argument("--max-threads", type=_positive_int, default=8)
    parser.add_argument("--max-executions", type=_positive_int, default=4096)
    parser.add_argument("--checker-timeout-ms", type=_positive_int, default=10_000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bmo-check")
    subcommands = parser.add_subparsers(dest="command", required=True)

    fingerprint = subcommands.add_parser(
        "fingerprint", help="recover the concrete ELF dependency closure"
    )
    _add_input_arguments(fingerprint)
    fingerprint.set_defaults(handler=_fingerprint)

    recover = subcommands.add_parser(
        "recover", help="recover CFG, pthread roles, and concrete sync summaries"
    )
    _add_input_arguments(recover)
    recover.add_argument(
        "--pthread-spec",
        type=Path,
        default=Path("specs/pthread-api.yaml"),
    )
    recover.set_defaults(handler=_recover)

    slice_command = subcommands.add_parser(
        "slice", help="build a proof-carrying shared-memory slice"
    )
    _add_input_arguments(slice_command)
    slice_command.add_argument(
        "--pthread-spec",
        type=Path,
        default=Path("specs/pthread-api.yaml"),
    )
    slice_command.set_defaults(handler=_slice)

    analyze = subcommands.add_parser(
        "analyze", help="check x86-TSO portability and emit a certificate"
    )
    _add_input_arguments(analyze)
    _add_checker_arguments(analyze)
    analyze.add_argument(
        "--pthread-spec",
        type=Path,
        default=Path("specs/pthread-api.yaml"),
    )
    analyze.set_defaults(handler=_analyze)

    explain = subcommands.add_parser(
        "explain", help="render a portability certificate for review"
    )
    explain.add_argument("certificate", type=Path)
    explain.set_defaults(handler=_explain)

    evaluate = subcommands.add_parser(
        "evaluate", help="run reproducible PARSEC analysis and pruning ablations"
    )
    evaluate.add_argument("--suite", type=Path, required=True)
    evaluate.add_argument("--parsec-root", type=Path, required=True)
    evaluate.add_argument(
        "--benchmark", action="append", default=[], metavar="ID"
    )
    evaluate.add_argument(
        "--library-root", type=Path, action="append", default=[], required=True
    )
    evaluate.add_argument("--threads-override", type=_positive_int)
    evaluate.add_argument("--environment", action="append", default=[])
    evaluate.add_argument("--dbt-contract", type=Path, required=True)
    evaluate.add_argument("--dbt-revision")
    evaluate.add_argument("--dbt-root", type=Path)
    evaluate.add_argument(
        "--pthread-spec", type=Path, default=Path("specs/pthread-api.yaml")
    )
    evaluate.add_argument(
        "--function-effects",
        type=Path,
        default=Path("specs/library-effects.yaml"),
    )
    evaluate.add_argument("--output-dir", type=Path, required=True)
    evaluate.add_argument("--run-native", action="store_true")
    evaluate.add_argument(
        "--native-timeout-seconds", type=_positive_int, default=300
    )
    evaluate.add_argument(
        "--analysis-memory-limit-mb", type=_positive_int, default=4096
    )
    evaluate.add_argument(
        "--analysis-timeout-seconds", type=_positive_int, default=900
    )
    evaluate.add_argument("--in-process", action="store_true", help=argparse.SUPPRESS)
    _add_checker_arguments(evaluate)
    evaluate.set_defaults(handler=_evaluate_isolated)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
    NativeRunMeasurement,
    PhaseTimings,
