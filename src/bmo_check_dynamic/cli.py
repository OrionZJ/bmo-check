from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

import yaml

from bmo_check_dynamic.application import (
    AnalyzeRequest,
    CaptureRequest,
    analyze as analyze_request,
    capture as capture_request,
)
from bmo_check_dynamic.capture import CaptureError
from bmo_check_dynamic.analysis import locate_instruction_site
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.model import DynamicCertificate, TraceVerdict
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
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise argparse.ArgumentTypeError("campaign manifest requires a non-empty runs list")
    args.output.mkdir(parents=True, exist_ok=True)
    certificates: list[DynamicCertificate] = []
    for item in runs:
        if not isinstance(item, dict) or not isinstance(item.get("command"), list):
            raise argparse.ArgumentTypeError("each campaign run requires command: [..]")
        repeat = int(item.get("repeat", 1))
        for iteration in range(repeat):
            name = str(item.get("name", "run"))
            trace_dir = args.output / f"{name}-{iteration:03d}-{uuid.uuid4().hex[:8]}"
            capture_request(
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
            certificate = analyze_request(
                AnalyzeRequest(
                    trace_dir=trace_dir,
                    dbt_contract=args.dbt_contract,
                    config=_analysis_config(args),
                )
            )
            certificate_path = trace_dir / "certificate.json"
            certificate_path.write_text(
                certificate.model_dump_json(indent=2), encoding="utf-8"
            )
            certificates.append(certificate)
    if any(item.verdict == TraceVerdict.COUNTEREXAMPLE for item in certificates):
        verdict = TraceVerdict.COUNTEREXAMPLE
    elif any(item.verdict == TraceVerdict.UNKNOWN for item in certificates):
        verdict = TraceVerdict.UNKNOWN
    else:
        verdict = TraceVerdict.TRACE_SAFE
    summary = {
        "schema_version": "1.0",
        "verdict": verdict.value,
        "trace_count": len(certificates),
        "verdict_counts": {
            candidate.value: sum(item.verdict == candidate for item in certificates)
            for candidate in TraceVerdict
        },
        "total_events": sum(item.event_count for item in certificates),
        "total_unique_pcs_per_trace": sum(
            item.unique_pc_count for item in certificates
        ),
        "certificates": [item.model_dump(mode="json") for item in certificates],
        "limitation": "campaign verdict covers only the listed trace certificates",
    }
    (args.output / "campaign.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Campaign verdict: {verdict.value} ({len(certificates)} traces)")
    return EXIT_CODES[verdict]


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
    parser.add_argument("--max-communication-active-events", type=int, default=100_000)
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
            "prove main-ELF-touching communication; use the disjoint-partition fast path "
            "when available, otherwise scan main-touched pages; runtime-only edges "
            "remain covered by the DBT contract"
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
