from __future__ import annotations

import argparse
from pathlib import Path

from bmo_check_static.analysis.lifecycle_symbolic import prove_symbolic_lifecycle
from bmo_check_static.analysis.shared_state import _post_join_covers_pc
from bmo_check_static.binary.dependency_closure import build_program_manifest
from bmo_check_static.controlflow import recover_control_flow
from bmo_check_static.evaluation import load_evaluation_suite
from bmo_check_static.model import ExecutionScope


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", type=Path)
    parser.add_argument("benchmark")
    parser.add_argument("parsec_root", type=Path)
    parser.add_argument("pc", type=lambda value: int(value, 0))
    parser.add_argument("--library-root", action="append", type=Path, default=[])
    arguments = parser.parse_args()
    suite = load_evaluation_suite(arguments.suite)
    definition = next(
        item for item in suite.benchmarks if item.id == arguments.benchmark
    )
    executable = arguments.parsec_root / definition.executable
    manifest = build_program_manifest(
        executable,
        tuple(arguments.library_root),
        ExecutionScope(
            thread_count_min=definition.threads,
            thread_count_max=definition.threads,
        ),
        "probe",
        "probe",
    )
    assert manifest.executable is not None
    assert definition.lifecycle_hint is not None
    control_flow = recover_control_flow(manifest.executable, manifest)
    proof = prove_symbolic_lifecycle(
        manifest.executable, definition.lifecycle_hint, definition.threads
    )
    print(proof)
    print(
        f"post_join_covers=",
        _post_join_covers_pc(proof, arguments.pc, control_flow),
    )
    for block in control_flow.basic_blocks:
        if (
            block.location.pc <= definition.lifecycle_hint.post_join_pc
            < block.location.pc + block.size
            or block.location.pc <= arguments.pc < block.location.pc + block.size
        ):
            print(block)


if __name__ == "__main__":
    main()
