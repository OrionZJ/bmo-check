"""PARSEC 单 benchmark worker 的最小进程入口。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .parsec import EvaluationApplicationError, ParsecEvaluationRequest, run_parsec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bmo-check-evaluation-worker")
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.request.read_text(encoding="utf-8"))
        request = ParsecEvaluationRequest.from_payload(payload).with_in_process(True)
        report = run_parsec(request)
        output = request.output_dir / "evaluation.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return 0
    except (OSError, ValueError, EvaluationApplicationError) as error:
        print(f"evaluation worker failed: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
