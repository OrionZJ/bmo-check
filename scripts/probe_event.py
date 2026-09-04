from __future__ import annotations

import argparse
import json
from pathlib import Path

from bmo_check.analysis import extract_memory_events
from bmo_check.analysis.address_provenance import recover_address_provenance
from bmo_check.binary.capstone_backend import collect_instruction_facts
from bmo_check.binary.dependency_closure import build_program_manifest
from bmo_check.config import load_function_effect_contract
from bmo_check.controlflow import recover_control_flow
from bmo_check.model import ExecutionScope
from bmo_check.threading import discover_pthread_threads


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--library-root", action="append", type=Path, required=True)
    parser.add_argument("--function-effects", type=Path, required=True)
    parser.add_argument("--pc", type=lambda value: int(value, 0), required=True)
    args = parser.parse_args()

    manifest = build_program_manifest(
        args.binary,
        tuple(args.library_root),
        ExecutionScope(thread_count_min=4, thread_count_max=4),
        "probe",
        "probe",
    )
    assert manifest.executable is not None
    module = manifest.executable
    cfg = recover_control_flow(module, manifest)
    threads = discover_pthread_threads(module, manifest, cfg)
    contract = load_function_effect_contract(args.function_effects)
    report = extract_memory_events(
        module,
        cfg,
        threads,
        function_effects=contract.effects,
        function_integer_arguments=contract.integer_arguments,
        function_internal_objects=contract.internal_objects,
    )
    event_payload = [
                event.model_dump(mode="json")
                for event in report.events
                if event.pc == args.pc
            ]
    event_blocks = {event.block_pc for event in report.events if event.pc == args.pc}
    instruction_report = collect_instruction_facts(module)
    allocation_calls = {
        call.location.pc: call.target_symbol
        for call in cfg.call_sites
        if call.target_symbol is not None
        and contract.effects.get(call.target_symbol) == "fresh_allocation"
    }
    provenance = recover_address_provenance(
        module,
        cfg,
        instruction_report.facts,
        allocation_calls,
    )
    print(
        json.dumps(
            {
                "events": event_payload,
                "blocks": [
                    block.model_dump(mode="json")
                    for block in cfg.basic_blocks
                    if block.location.pc in event_blocks
                    or any(successor in event_blocks for successor in block.successor_pcs)
                ],
                "preceding_facts": [
                    fact.model_dump(mode="json")
                    for fact in instruction_report.facts
                    if args.pc - 32 <= fact.pc <= args.pc
                ],
                "published_globals": {
                    key: value.model_dump(mode="json")
                    for key, value in provenance.published_globals.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
