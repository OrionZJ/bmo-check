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
        "--encoding-only",
        "--only-mode",
        mode,
    ]
    if args.discovery_only:
        command.append("--discovery-only")
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
        "--modes",
        nargs="+",
        choices=("P11_RAW", "P12_CANONICAL", "P12_CANONICAL_BLOCKING", "P14_STRUCTURED"),
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
