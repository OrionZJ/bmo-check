"""显式刷新和重放 E2.5 herd oracle。

该模块只运行外部 herd 并保存可审计的观察结果。target 输入必须由调用者
依据 canonical DBT contract 预先生成；这里不把 x86 指令名直接翻译成 RISC-V，
也不把 oracle 结果送入 static proof 或最终 verdict。
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .herd import HerdOracleRequest, HerdOracleRun, HerdReplayStatus, replay_herd_oracle, run_herd_oracle
from .model import HerdOracleRecord


ORACLE_REPORT_SCHEMA = "e2.5-herd-oracle-run-v1"


class OracleToolError(ValueError):
    """oracle 命令缺少绑定输入或记录格式不受支持。"""


def _request_payload(request: HerdOracleRequest) -> dict[str, Any]:
    payload = asdict(request)
    payload["source_input"] = str(request.source_input)
    payload["target_input"] = str(request.target_input)
    return payload


def oracle_record_from_run(
    run: HerdOracleRun,
    *,
    herd_version: str,
) -> HerdOracleRecord:
    """把一次 source/target invocation 固化为 manifest 可嵌入的记录。"""

    if not herd_version:
        raise OracleToolError("herd_version must be supplied when recording an oracle")
    if not run.source.input_sha256 or not run.target.input_sha256:
        raise OracleToolError(
            "cannot record an oracle when source or target input could not be hashed"
        )
    request = run.request
    return HerdOracleRecord(
        herd_version=herd_version,
        source_model=request.source_model,
        target_model=request.target_model,
        source_outcome=run.source.outcome,
        target_outcome=run.target.outcome,
        source_input_sha256=run.source.input_sha256,
        target_input_sha256=run.target.input_sha256,
        elf_sha256=request.elf_sha256,
        contract_version=request.contract_version,
        contract_sha256=request.contract_sha256,
        raw_output_sha256=run.raw_output_sha256,
    )


def report_payload(run: HerdOracleRun, *, herd_version: str) -> dict[str, Any]:
    """返回不含证明字段的规范化运行报告。"""

    record = oracle_record_from_run(run, herd_version=herd_version)
    return {
        "schema": ORACLE_REPORT_SCHEMA,
        "request": _request_payload(run.request),
        "source": asdict(run.source),
        "target": asdict(run.target),
        "oracle": record.model_dump(mode="json"),
        "complete": run.complete,
    }


def write_report(run: HerdOracleRun, *, herd_version: str, output: Path) -> None:
    """写入 evaluation artifact；不会修改 manifest 或任何 certificate。"""

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            report_payload(run, herd_version=herd_version),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=lambda value: value.value,
        )
        + "\n",
        encoding="utf-8",
    )


def _request_from_payload(payload: dict[str, Any]) -> HerdOracleRequest:
    request = payload.get("request")
    if not isinstance(request, dict):
        raise OracleToolError("oracle report has no request object")
    try:
        values = dict(request)
        values["source_input"] = Path(values["source_input"])
        values["target_input"] = Path(values["target_input"])
        values["extra_args"] = tuple(values.get("extra_args", ()))
        return HerdOracleRequest(**values)
    except (KeyError, TypeError, ValueError) as error:
        raise OracleToolError(f"invalid oracle request: {error}") from error


def replay_report(path: Path) -> tuple[HerdReplayStatus, tuple[str, ...]]:
    """重放一个 refresh 报告，并返回 herd 层 comparison。"""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != ORACLE_REPORT_SCHEMA:
            raise OracleToolError("unsupported oracle report schema")
        record = HerdOracleRecord.model_validate(payload.get("oracle"))
        request = _request_from_payload(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        if isinstance(error, OracleToolError):
            raise
        raise OracleToolError(f"invalid oracle report {path}: {error}") from error
    result = replay_herd_oracle(record, run_herd_oracle(request))
    return result.status, result.differences


def _sha256_argument(value: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise argparse.ArgumentTypeError("expected a lowercase SHA-256")
    return value


def _refresh(args: argparse.Namespace) -> int:
    request = HerdOracleRequest(
        source_input=args.source_input,
        target_input=args.target_input,
        source_model=args.source_model,
        target_model=args.target_model,
        contract_version=args.contract_version,
        contract_sha256=args.contract_sha256,
        elf_sha256=args.elf_sha256,
        herd_executable=args.herd_executable,
        timeout_seconds=args.timeout_seconds,
        extra_args=tuple(args.herd_arg),
        herd_version=args.herd_version,
    )
    run = run_herd_oracle(request)
    write_report(run, herd_version=args.herd_version, output=args.output)
    return 0 if run.complete else 2


def _replay(args: argparse.Namespace) -> int:
    status, differences = replay_report(args.report)
    if differences:
        print("\n".join(differences))
    return {
        HerdReplayStatus.MATCH: 0,
        HerdReplayStatus.MISMATCH: 1,
        HerdReplayStatus.UNKNOWN: 2,
    }[status]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bmo-check-litmus-oracle")
    subcommands = parser.add_subparsers(dest="command", required=True)
    refresh = subcommands.add_parser(
        "refresh",
        help="run herd for pre-generated source and contract-lowered target inputs",
    )
    refresh.add_argument("--source-input", type=Path, required=True)
    refresh.add_argument("--target-input", type=Path, required=True)
    refresh.add_argument("--source-model", required=True)
    refresh.add_argument("--target-model", required=True)
    refresh.add_argument("--contract-version", required=True)
    refresh.add_argument("--contract-sha256", type=_sha256_argument, required=True)
    refresh.add_argument("--elf-sha256", type=_sha256_argument, required=True)
    refresh.add_argument("--herd-version", required=True)
    refresh.add_argument("--herd-executable", default="herd7")
    refresh.add_argument("--timeout-seconds", type=float, default=30.0)
    refresh.add_argument("--herd-arg", action="append", default=[])
    refresh.add_argument("--output", type=Path, required=True)
    refresh.set_defaults(handler=_refresh)

    replay = subcommands.add_parser(
        "replay", help="rerun an oracle report and compare all bound hashes/results"
    )
    replay.add_argument("report", type=Path)
    replay.set_defaults(handler=_replay)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (OracleToolError, OSError, ValueError) as error:
        print(f"oracle input error: {error}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ORACLE_REPORT_SCHEMA",
    "OracleToolError",
    "oracle_record_from_run",
    "report_payload",
    "replay_report",
    "write_report",
]
