from __future__ import annotations

import argparse
from pathlib import Path

from bmo_check_static.analysis.escape_summary import prove_register_parameter_nocapture
from bmo_check_static.binary.angr_backend import load_cfg
from bmo_check_static.binary.dependency_closure import build_program_manifest
from bmo_check_static.controlflow import recover_control_flow
from bmo_check_static.model import ExecutionScope


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect one SysV register parameter nocapture proof"
    )
    parser.add_argument("binary", type=Path)
    parser.add_argument("function_pc", type=lambda value: int(value, 0))
    parser.add_argument("argument_index", type=int)
    parser.add_argument("--library-root", action="append", type=Path, default=[])
    parser.add_argument("--scalar-external", action="append", default=[])
    arguments = parser.parse_args()
    manifest = build_program_manifest(
        arguments.binary,
        tuple(arguments.library_root),
        ExecutionScope(),
        "probe-only",
        "probe-only",
    )
    if manifest.executable is None:
        raise SystemExit("executable closure is unavailable")
    control_flow = recover_control_flow(manifest.executable, manifest)
    context = load_cfg(manifest.executable)
    result = prove_register_parameter_nocapture(
        context,
        control_flow,
        arguments.function_pc,
        arguments.argument_index,
        frozenset(arguments.scalar_external),
    )
    print("PROVEN" if result.proven else "UNKNOWN")
    for item in result.evidence:
        print(item)
    return 0 if result.proven else 2


if __name__ == "__main__":
    raise SystemExit(main())
