from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from bmo_check.binary.dependency_closure import build_program_manifest
from bmo_check.binary.symbols import function_symbols
from bmo_check.config import load_contract_version
from bmo_check.controlflow import recover_control_flow
from bmo_check.model import (
    ExecutionScope,
    FingerprintReport,
    ProgramManifest,
    ProgramRecoveryReport,
    StrictModel,
    UnknownFact,
    UnknownKind,
)
from bmo_check.synchronization import analyze_pthread_synchronization
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
    if contract.unknown is not None:
        manifest = manifest.model_copy(
            update={
                "closure_complete": False,
                "unknowns": manifest.unknowns + (contract.unknown,),
            }
        )
    return manifest


def _fingerprint(args: argparse.Namespace) -> int:
    manifest = _build_manifest(args)
    _write_json(FingerprintReport(manifest=manifest), args.output)
    return 0 if manifest.closure_complete else 1


def _recover(args: argparse.Namespace) -> int:
    manifest = _build_manifest(args)
    if manifest.executable is None:
        _write_json(ProgramRecoveryReport(manifest=manifest), args.output)
        return 1

    control_flow = recover_control_flow(manifest.executable, manifest)
    threads = discover_pthread_threads(
        manifest.executable, manifest, control_flow
    )
    synchronization = []
    recovery_unknowns: list[UnknownFact] = []
    pthread_names = {"pthread_spin_unlock", "pthread_mutex_lock", "pthread_once"}
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
        if not names.intersection(pthread_names):
            continue
        try:
            synchronization.append(
                analyze_pthread_synchronization(
                    library,
                    args.pthread_spec,
                    args.dbt_contract,
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
    _write_json(
        ProgramRecoveryReport(
            manifest=manifest,
            control_flow=control_flow,
            thread_roles=threads,
            synchronization=tuple(synchronization),
            unknowns=tuple(recovery_unknowns),
        ),
        args.output,
    )
    return 0 if manifest.closure_complete else 1


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
    parser.add_argument("--output", type=Path)


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
