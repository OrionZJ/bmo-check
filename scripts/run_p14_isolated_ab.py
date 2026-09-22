"""Run P14 shadow modes in separate workers and collect per-process RSS.

This driver deliberately does not call the formal checker.  Each worker runs
one candidate-discovery mode with identical trace, certificate, and bounds;
the parent only aggregates the JSON reports and ``/usr/bin/time -v`` resource
measurements.  A timeout or worker error remains an explicit incomplete run.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path


_RSS_RE = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")
_USER_RE = re.compile(r"User time \(seconds\):\s*([0-9.]+)")
_SYS_RE = re.compile(r"System time \(seconds\):\s*([0-9.]+)")


def _number(pattern: re.Pattern[str], text: str) -> float | None:
    match = pattern.search(text)
    return float(match.group(1)) if match else None


def _run_one(args: argparse.Namespace, mode: str, output: Path) -> dict[str, object]:
    command = [
        "/usr/bin/time",
        "-v",
        sys.executable,
        "-m",
        "bmo_check_dynamic.cli",
        "cegar-ab",
        str(args.trace),
        "--dbt-contract",
        str(args.dbt_contract),
        "--reduction-certificate",
        str(args.reduction_certificate),
        "--output",
        str(output),
        "--fixture",
        args.fixture,
        "--max-window-events",
        str(args.max_window_events),
        "--max-cycle-length",
        str(args.max_cycle_length),
        "--max-search-states",
        str(args.max_search_states),
        "--max-local-queries",
        str(args.max_local_queries),
        "--local-timeout-ms",
        str(args.local_timeout_ms),
        "--local-max-symbolic-terms",
        str(args.local_max_symbolic_terms),
        "--only-mode",
        mode,
    ]
    if not args.execute_local_solver:
        command.append("--encoding-only")
    if args.discovery_only:
        command.append("--discovery-only")
    if args.max_in_memory_frontier is not None:
        command.extend(("--max-in-memory-frontier", str(args.max_in_memory_frontier)))
    if args.max_rss_mb is not None:
        command.extend(("--max-rss-mb", str(args.max_rss_mb)))
    if args.max_wall_time_ms is not None:
        command.extend(("--max-wall-time-ms", str(args.max_wall_time_ms)))
    if args.checkpoint_dir is not None:
        command.extend(
            (
                "--checkpoint",
                str(args.checkpoint_dir / f"{mode}.checkpoint.json"),
                "--progress",
                str(args.checkpoint_dir / f"{mode}.progress.json"),
            )
        )
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=args.cwd,
            text=True,
            capture_output=True,
            timeout=args.worker_timeout_s,
            check=False,
        )
        process_timeout = False
    except subprocess.TimeoutExpired as error:
        completed = None
        process_timeout = True
        stderr = str(error)
    else:
        stderr = completed.stderr
    wall_ms = int((time.perf_counter() - started) * 1000)
    resource = {
        "peak_rss_mb": (
            _number(_RSS_RE, stderr) / 1024.0 if _RSS_RE.search(stderr) else None
        ),
        "user_seconds": _number(_USER_RE, stderr),
        "system_seconds": _number(_SYS_RE, stderr),
        "wall_ms": wall_ms,
    }
    report = None
    if output.exists():
        try:
            report = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            report = None
    if report is not None and args.checkpoint_dir is not None:
        # Discovery 写入的 progress.json 在 worker 退出后补上局部查询结果，
        # 让长实验即使只留下进度文件也能区分 encoding/solver 状态。
        progress_path = args.checkpoint_dir / f"{mode}.progress.json"
        try:
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            progress = {}
        mode_report = (
            report.get("reports", [{}])[0].get("modes", [{}])[0]
            if isinstance(report, dict)
            else {}
        )
        progress.update(
            {
                "local_query_count": mode_report.get("local_queries", 0),
                "feasible": mode_report.get("feasible", 0),
                "infeasible": mode_report.get("infeasible", 0),
                "unknown": mode_report.get("unknown", 0),
                "not_run": mode_report.get("not_run", 0),
                "replay_accepted": mode_report.get("replay_accepted", 0),
                "replay_rejected": mode_report.get("replay_rejected", 0),
                "worker_finished": True,
            }
        )
        progress_path.parent.mkdir(parents=True, exist_ok=True)
        progress_path.write_text(json.dumps(progress, sort_keys=True), encoding="utf-8")
    return {
        "mode": mode,
        "returncode": None if completed is None else completed.returncode,
        "process_timeout": process_timeout,
        "resource": resource,
        "report": report,
        "stderr_tail": stderr[-2000:],
        "diagnostic_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--dbt-contract", type=Path, required=True)
    parser.add_argument("--reduction-certificate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--worker-timeout-s", type=int, default=600)
    parser.add_argument("--max-window-events", type=int, default=5000)
    parser.add_argument("--max-cycle-length", type=int, default=12)
    parser.add_argument("--max-search-states", type=int, default=10_000)
    parser.add_argument("--max-local-queries", type=int, default=100)
    parser.add_argument("--local-timeout-ms", type=int, default=1_000)
    parser.add_argument("--local-max-symbolic-terms", type=int, default=100_000)
    parser.add_argument("--discovery-only", action="store_true")
    parser.add_argument(
        "--execute-local-solver",
        action="store_true",
        help="run bounded local SMT; otherwise only build local encodings",
    )
    parser.add_argument("--max-in-memory-frontier", type=int, default=None)
    parser.add_argument("--max-rss-mb", type=float, default=None)
    parser.add_argument("--max-wall-time-ms", type=int, default=None)
    parser.add_argument("--checkpoint-dir", type=Path, default=None)
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=("P11_RAW", "P12_CANONICAL", "P12_CANONICAL_BLOCKING", "P14_STRUCTURED", "P15_BOUNDED_STRUCTURED"),
    )
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    runs = []
    modes = args.modes or (
        "P11_RAW",
        "P12_CANONICAL",
        "P12_CANONICAL_BLOCKING",
        "P14_STRUCTURED",
    )
    for mode in modes:
        worker_output = args.output.with_name(f"{args.output.stem}-{mode}.json")
        runs.append(_run_one(args, mode, worker_output))
    result = {
        "schema_version": "p14-isolated-comparison-v1",
        "fixture": args.fixture,
        "trace": str(args.trace),
        "max_search_states": args.max_search_states,
        "max_local_queries": args.max_local_queries,
        "runs": runs,
        "isolated_process": True,
        "diagnostic_only": True,
    }
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
