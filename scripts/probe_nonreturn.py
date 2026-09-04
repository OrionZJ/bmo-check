from __future__ import annotations

import argparse
import json
from pathlib import Path

from bmo_check_static.analysis.memory_events import (
    _blocks_reaching_return,
    _functions_only_called_from_nonreturning_paths,
    _role_functions,
)
from bmo_check_static.binary.capstone_backend import collect_instruction_facts
from bmo_check_static.binary.dependency_closure import build_program_manifest
from bmo_check_static.controlflow import recover_control_flow
from bmo_check_static.model import ExecutionScope
from bmo_check_static.threading import discover_pthread_threads


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--library-root", action="append", type=Path, required=True)
    parser.add_argument("--symbol", required=True)
    args = parser.parse_args()

    manifest = build_program_manifest(
        args.binary,
        tuple(args.library_root),
        ExecutionScope(thread_count_min=1, thread_count_max=64),
        "probe",
        "probe",
    )
    assert manifest.executable is not None
    module = manifest.executable
    cfg = recover_control_flow(module, manifest)
    threads = discover_pthread_threads(module, manifest, cfg)
    facts = collect_instruction_facts(module)
    return_blocks = _blocks_reaching_return(cfg, facts.facts)
    role_functions = _role_functions(cfg, threads)
    roots = {
        target.pc
        for role in threads.roles
        for target in role.start_targets.known_targets
        if target.module_sha256 == module.sha256
    }
    nonreturning = _functions_only_called_from_nonreturning_paths(
        cfg,
        return_blocks,
        roots,
        set().union(*role_functions.values()),
    )
    targets = {
        function.location.pc
        for function in cfg.functions
        if function.location.symbol == args.symbol
    }
    calls = [
        {
            "pc": call.location.pc,
            "block": call.block_pc,
            "caller": call.containing_function_pc,
            "block_reaches_return": call.block_pc in return_blocks,
            "complete": call.targets.complete,
        }
        for call in cfg.call_sites
        if any(target.pc in targets for target in call.targets.known_targets)
    ]
    print(
        json.dumps(
            {
                "targets": sorted(targets),
                "classified": sorted(targets & nonreturning),
                "calls": calls,
                "application_incomplete_indirects": [
                    site.location.pc
                    for site in cfg.indirect_sites
                    if not site.targets.complete
                    and site.containing_function_pc in set().union(
                        *role_functions.values()
                    )
                    and not next(
                        function
                        for function in cfg.functions
                        if function.location.pc == site.containing_function_pc
                    ).is_plt
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
