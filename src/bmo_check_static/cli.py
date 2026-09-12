from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from bmo_check_evaluation import (
    EvaluationApplicationError,
    ParsecEvaluationRequest,
    run_parsec,
)

from bmo_check_static.application import (
    StaticRequest,
    analyze as analyze_request,
    build_manifest as application_manifest,
    recover as application_recover,
    slice_report as application_slice_report,
)


def _default_static_spec(name: str) -> Path:
    repository_spec = Path(__file__).resolve().parents[2] / "specs" / "static" / name
    if repository_spec.is_file():
        return repository_spec
    return Path(__file__).resolve().parent / "data" / name

from bmo_check_static.binary.symbols import function_symbols
from bmo_check_static.model import (
    CheckerLimits,
    FingerprintReport,
    PortabilityCertificate,
    ProgramManifest,
    ProgramRecoveryReport,
    ProgramSliceReport,
    StrictModel,
)
from bmo_check_static.proof import explain_certificate, verify_portability


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


def _write_json(report: StrictModel, output: Path | None) -> None:
    text = report.model_dump_json(indent=2) + "\n"
    if output is None:
        sys.stdout.write(text)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")


def _build_manifest(args: argparse.Namespace) -> ProgramManifest:
    return application_manifest(_request_from_args(args))


def _request_from_args(args: argparse.Namespace) -> StaticRequest:
    """把 argparse 的临时 namespace 收口为静态 service 的 typed request。"""

    return StaticRequest(
        executable=args.executable,
        dbt_contract=args.dbt_contract,
        pthread_spec=getattr(
            args, "pthread_spec", _default_static_spec("pthread-api.yaml")
        ),
        function_effects=getattr(
            args, "function_effects", _default_static_spec("library-effects.yaml")
        ),
        library_roots=tuple(args.library_root),
        argv=tuple(args.argv_json),
        threads=getattr(args, "threads", None),
        environment=tuple(sorted(_environment(args.environment).items())),
        dbt_revision=getattr(args, "dbt_revision", None),
        dbt_root=getattr(args, "dbt_root", None),
        scope=getattr(args, "scope", "full"),
        provenance_instruction_limit=getattr(
            args, "provenance_instruction_limit", None
        ),
    )


def _fingerprint(args: argparse.Namespace) -> int:
    manifest = _build_manifest(args)
    _write_json(FingerprintReport(manifest=manifest), args.output)
    return 0 if manifest.closure_complete else 1


def _build_recovery(args: argparse.Namespace) -> ProgramRecoveryReport:
    return application_recover(
        _request_from_args(args), symbol_provider=function_symbols
    )


def _recover(args: argparse.Namespace) -> int:
    recovery = _build_recovery(args)
    _write_json(recovery, args.output)
    return 0 if recovery.manifest.closure_complete else 1


def _build_slice_report(args: argparse.Namespace) -> ProgramSliceReport:
    return application_slice_report(
        _request_from_args(args), symbol_provider=function_symbols
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
    certificate = analyze_request(
        _request_from_args(args),
        _checker_limits(args),
        symbol_provider=function_symbols,
    )
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


def _evaluation_request_from_args(
    args: argparse.Namespace,
) -> ParsecEvaluationRequest:
    """把 CLI 参数一次性转换成评测 service 的 typed request。"""

    return ParsecEvaluationRequest(
        suite=args.suite,
        parsec_root=args.parsec_root,
        dbt_contract=args.dbt_contract,
        pthread_spec=args.pthread_spec,
        function_effects=args.function_effects,
        output_dir=args.output_dir,
        benchmark_ids=tuple(args.benchmark),
        library_roots=tuple(args.library_root),
        threads_override=args.threads_override,
        environment=tuple(sorted(_environment(args.environment).items())),
        dbt_revision=args.dbt_revision,
        dbt_root=args.dbt_root,
        scope=args.scope,
        run_native=args.run_native,
        native_timeout_seconds=args.native_timeout_seconds,
        analysis_memory_limit_mb=args.analysis_memory_limit_mb,
        analysis_timeout_seconds=args.analysis_timeout_seconds,
        max_events=args.max_events,
        max_threads=args.max_threads,
        max_executions=args.max_executions,
        checker_timeout_ms=args.checker_timeout_ms,
        in_process=args.in_process,
    )


def _evaluate(args: argparse.Namespace) -> int:
    try:
        report = run_parsec(_evaluation_request_from_args(args))
    except EvaluationApplicationError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    _write_json(report, args.output_dir / "evaluation.json")
    return 0


def _evaluate_isolated(args: argparse.Namespace) -> int:
    """保留旧 handler 名称，实际执行交给 evaluation application service。"""

    return _evaluate(args)


def _litmus(args: argparse.Namespace) -> int:
    """运行真实 ELF conformance；结果不是 static SAFE verdict。"""

    from bmo_check_evaluation.litmus.service import (
        LitmusConformanceRequest,
        LitmusServiceError,
        run_litmus_conformance,
    )
    from bmo_check_evaluation.litmus.model import LitmusFixtureError

    request = LitmusConformanceRequest(
        manifest=args.manifest,
        corpus_root=args.corpus_root,
        dbt_contract=args.dbt_contract,
        pthread_spec=args.pthread_spec,
        function_effects=args.function_effects,
        library_roots=tuple(args.library_root),
        dbt_revision=args.dbt_revision,
        scope=args.scope,
        provenance_instruction_limit=args.provenance_instruction_limit,
    )
    try:
        report = run_litmus_conformance(request)
    except (LitmusFixtureError, LitmusServiceError, OSError, ValueError) as error:
        print(f"litmus conformance input error: {error}", file=sys.stderr)
        return 3
    payload = asdict(report)
    payload["status"] = report.status.value
    output = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=lambda value: value.value,
    )
    if args.output is None:
        print(output)
    else:
        args.output.write_text(output + "\n", encoding="utf-8")
    return 0 if report.status.value == "MATCHED" else 2


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
        default=_default_static_spec("library-effects.yaml"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--scope",
        choices=("full", "application"),
        default="full",
        help="prove the full process or only the explicitly bounded main-ELF application scope",
    )
    parser.add_argument(
        "--application-only",
        dest="scope",
        action="store_const",
        const="application",
        help="alias for --scope application",
    )
    parser.add_argument(
        "--provenance-instruction-limit",
        type=_positive_int,
        help=(
            "bound address-provenance CFG work; skipped complex functions remain "
            "conservative MayAlias events"
        ),
    )


def _add_checker_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-events", type=_positive_int, default=24)
    parser.add_argument("--max-threads", type=_positive_int, default=8)
    parser.add_argument("--max-executions", type=_positive_int, default=4096)
    parser.add_argument("--checker-timeout-ms", type=_positive_int, default=10_000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bmo-check-static")
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
        default=_default_static_spec("pthread-api.yaml"),
    )
    recover.set_defaults(handler=_recover)

    slice_command = subcommands.add_parser(
        "slice", help="build a proof-carrying shared-memory slice"
    )
    _add_input_arguments(slice_command)
    slice_command.add_argument(
        "--pthread-spec",
        type=Path,
        default=_default_static_spec("pthread-api.yaml"),
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
        default=_default_static_spec("pthread-api.yaml"),
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
        "--pthread-spec", type=Path, default=_default_static_spec("pthread-api.yaml")
    )
    evaluate.add_argument(
        "--function-effects",
        type=Path,
        default=_default_static_spec("library-effects.yaml"),
    )
    evaluate.add_argument("--output-dir", type=Path, required=True)
    evaluate.add_argument(
        "--scope",
        choices=("full", "application"),
        default="full",
        help="prove the full process or only the explicitly bounded main-ELF application scope",
    )
    evaluate.add_argument(
        "--application-only",
        dest="scope",
        action="store_const",
        const="application",
        help="alias for --scope application",
    )
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

    litmus = subcommands.add_parser(
        "litmus",
        help="run end-to-end conformance on versioned real x86 litmus ELF files",
    )
    litmus.add_argument("--manifest", type=Path, required=True)
    litmus.add_argument("--corpus-root", type=Path, required=True)
    litmus.add_argument("--library-root", type=Path, action="append", default=[])
    litmus.add_argument("--dbt-contract", type=Path, required=True)
    litmus.add_argument(
        "--pthread-spec", type=Path, default=_default_static_spec("pthread-api.yaml")
    )
    litmus.add_argument(
        "--function-effects",
        type=Path,
        default=_default_static_spec("library-effects.yaml"),
    )
    litmus.add_argument("--dbt-revision")
    litmus.add_argument(
        "--scope",
        choices=("full", "application"),
        default="full",
        help="pass the same explicit scope to the ordinary static pipeline",
    )
    litmus.add_argument(
        "--provenance-instruction-limit",
        type=_positive_int,
        default=256,
        help=(
            "bound address-provenance CFG work for generated harness functions"
        ),
    )
    litmus.add_argument("--output", type=Path)
    litmus.set_defaults(handler=_litmus)
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
