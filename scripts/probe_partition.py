from __future__ import annotations

import argparse
from pathlib import Path

import angr
import claripy


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Symbolically recover a worker's half-open loop partition"
    )
    parser.add_argument("binary", type=Path)
    parser.add_argument("worker_pc", type=lambda value: int(value, 0))
    parser.add_argument("loop_pc", type=lambda value: int(value, 0))
    parser.add_argument("item_count_pc", type=lambda value: int(value, 0))
    parser.add_argument("thread_count_pc", type=lambda value: int(value, 0))
    parser.add_argument("start_offset", type=lambda value: int(value, 0))
    parser.add_argument("end_offset", type=lambda value: int(value, 0))
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--item-count", type=int)
    parser.add_argument("--thread-count", type=int)
    arguments = parser.parse_args()

    project = angr.Project(arguments.binary, auto_load_libs=False)
    base = int(project.loader.main_object.mapped_base)
    worker = base + arguments.worker_pc
    loop = base + arguments.loop_pc
    argument_address = 0x70000000
    tid = claripy.BVS("tid", 32)
    item_count = (
        claripy.BVV(arguments.item_count, 32)
        if arguments.item_count is not None
        else claripy.BVS("item_count", 32)
    )
    thread_count = (
        claripy.BVV(arguments.thread_count, 32)
        if arguments.thread_count is not None
        else claripy.BVS("thread_count", 32)
    )
    state = project.factory.call_state(worker, argument_address)
    state.memory.store(argument_address, tid, endness=project.arch.memory_endness)
    state.memory.store(
        base + arguments.item_count_pc,
        item_count,
        endness=project.arch.memory_endness,
    )
    state.memory.store(
        base + arguments.thread_count_pc,
        thread_count,
        endness=project.arch.memory_endness,
    )
    state.solver.add(claripy.SGT(thread_count, 0))
    state.solver.add(claripy.SGE(item_count, thread_count))
    state.solver.add(claripy.SGE(tid, 0), claripy.SLT(tid, thread_count))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=loop, num_find=8)
    if not manager.found:
        raise SystemExit("loop header was not reached")

    paths: list[tuple[tuple[object, ...], object, object]] = []
    for index, found in enumerate(manager.found):
        rbp = found.regs.rbp
        start = found.memory.load(
            rbp + arguments.start_offset,
            4,
            endness=project.arch.memory_endness,
        )
        end = found.memory.load(
            rbp + arguments.end_offset,
            4,
            endness=project.arch.memory_endness,
        )
        paths.append((tuple(found.solver.constraints), start, end))
        if arguments.verbose:
            print(f"path={index}")
            print(f"constraints={claripy.simplify(claripy.And(*found.solver.constraints))}")
            print(f"start={claripy.simplify(start)}")
            print(f"end={claripy.simplify(end)}")

    tid1 = claripy.BVS("proof_tid1", 32)
    tid2 = claripy.BVS("proof_tid2", 32)
    checked = 0
    for first_constraints, first_start, first_end in paths:
        for second_constraints, second_start, second_end in paths:
            solver = claripy.Solver()
            solver.add(
                claripy.And(
                    *(claripy.replace(item, tid, tid1) for item in first_constraints)
                )
            )
            solver.add(
                claripy.And(
                    *(claripy.replace(item, tid, tid2) for item in second_constraints)
                )
            )
            solver.add(claripy.SLT(tid1, tid2))
            solver.add(
                claripy.SLT(
                    claripy.replace(first_start, tid, tid1),
                    claripy.replace(second_end, tid, tid2),
                )
            )
            solver.add(
                claripy.SLT(
                    claripy.replace(second_start, tid, tid2),
                    claripy.replace(first_end, tid, tid1),
                )
            )
            checked += 1
            if solver.satisfiable():
                print("COUNTEREXAMPLE")
                print(f"tid1={solver.eval(tid1, 1)[0]} tid2={solver.eval(tid2, 1)[0]}")
                print(f"item_count={solver.eval(item_count, 1)[0]}")
                print(f"thread_count={solver.eval(thread_count, 1)[0]}")
                return 2
    print("PROVEN")
    print(f"paths={len(paths)} pair_checks={checked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
