from __future__ import annotations

import logging
from dataclasses import dataclass

from bmo_check_static.model import ModuleFingerprint, PartitionHint


@dataclass(frozen=True)
class SymbolicPartitionProof:
    # proven 只有在路径覆盖和任意两线程不重叠都为 UNSAT 时才为 true。
    proven: bool
    # object_base/index_term 将 proof 绑定到 MemoryEvent 的地址来源。
    object_base: str
    index_term: str
    # element_size 说明循环下标每前进一步跨过多少字节。
    element_size: int
    # item_count/thread_count 绑定本次执行范围，不能复用于另一组参数。
    item_count: int
    thread_count: int
    # evidence 记录路径覆盖、pair check 数和失败原因。
    evidence: tuple[str, ...]
    # worker_pc/loop_pc 防止同名 frame slot 的事实被套到另一个循环。
    worker_pc: int
    loop_pc: int


def prove_symbolic_partition(
    module: ModuleFingerprint,
    hint: PartitionHint,
    thread_count_value: int,
) -> SymbolicPartitionProof:
    try:
        logging.getLogger("angr").setLevel(logging.CRITICAL)
        logging.getLogger("cle").setLevel(logging.CRITICAL)
        import angr
        import claripy

        project = angr.Project(module.path, auto_load_libs=False)
        base = int(project.loader.main_object.mapped_base)
        argument_address = 0x70000000
        tid = claripy.BVS("partition_tid", 32)
        item_count = claripy.BVV(hint.item_count, 32)
        thread_count = claripy.BVV(thread_count_value, 32)
        state = project.factory.call_state(
            base + hint.worker_pc,
            argument_address,
        )
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        if hint.thread_id_register is not None:
            # helper 入口已经接收整数 tid；把 32 位符号扩展到完整 ABI
            # 寄存器，避免把一个指针参数误当成线程编号。
            setattr(state.regs, hint.thread_id_register, claripy.ZeroExt(32, tid))
        else:
            argument_offset = hint.thread_id_arg_offset or 0
            # pthread callback 通常收到参数结构体地址。只有显式给出字段
            # 偏移时才把 tid 放入该字段，缺失偏移仍兼容旧的裸 tid 约定。
            state.memory.store(
                argument_address + argument_offset,
                tid,
                endness=project.arch.memory_endness,
            )
        state.memory.store(
            base + hint.item_count_pc,
            item_count,
            endness=project.arch.memory_endness,
        )
        state.memory.store(
            base + hint.thread_count_pc,
            thread_count,
            endness=project.arch.memory_endness,
        )
        state.solver.add(claripy.SGE(tid, 0), claripy.SLT(tid, thread_count))
        manager = project.factory.simulation_manager(state)
        manager.explore(find=base + hint.loop_pc, num_find=16)
        if (
            not manager.found
            or len(manager.found) >= 16
            or manager.active
            or manager.errored
            or manager.unconstrained
        ):
            return SymbolicPartitionProof(
                proven=False,
                object_base=hint.object_base,
                index_term=f"frame@0x{hint.worker_pc:x}{hint.induction_offset:+d}",
                element_size=hint.element_size,
                item_count=hint.item_count,
                thread_count=thread_count_value,
                evidence=("symbolic execution did not close every path at the loop header",),
                worker_pc=hint.worker_pc,
                loop_pc=hint.loop_pc,
            )

        paths: list[tuple[tuple[object, ...], object, object]] = []
        for found in manager.found:
            rbp = found.regs.rbp
            start = found.memory.load(
                rbp + hint.start_offset,
                4,
                endness=project.arch.memory_endness,
            )
            end = found.memory.load(
                rbp + hint.end_offset,
                4,
                endness=project.arch.memory_endness,
            )
            paths.append((tuple(found.solver.constraints), start, end))

        coverage = claripy.Solver()
        coverage_tid = claripy.BVS("coverage_tid", 32)
        coverage.add(claripy.SGE(coverage_tid, 0))
        coverage.add(claripy.SLT(coverage_tid, thread_count))
        coverage.add(
            claripy.Not(
                claripy.Or(
                    *(
                        claripy.And(
                            *(
                                claripy.replace(item, tid, coverage_tid)
                                for item in constraints
                            )
                        )
                        for constraints, _, _ in paths
                    )
                )
            )
        )
        if coverage.satisfiable():
            return SymbolicPartitionProof(
                proven=False,
                object_base=hint.object_base,
                index_term=f"frame@0x{hint.worker_pc:x}{hint.induction_offset:+d}",
                element_size=hint.element_size,
                item_count=hint.item_count,
                thread_count=thread_count_value,
                evidence=("recovered loop-header paths do not cover every thread id",),
                worker_pc=hint.worker_pc,
                loop_pc=hint.loop_pc,
            )

        tid1 = claripy.BVS("partition_tid1", 32)
        tid2 = claripy.BVS("partition_tid2", 32)
        checked = 0
        for first_constraints, first_start, first_end in paths:
            for second_constraints, second_start, second_end in paths:
                solver = claripy.Solver()
                solver.add(
                    claripy.And(
                        *(
                            claripy.replace(item, tid, tid1)
                            for item in first_constraints
                        )
                    )
                )
                solver.add(
                    claripy.And(
                        *(
                            claripy.replace(item, tid, tid2)
                            for item in second_constraints
                        )
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
                    return SymbolicPartitionProof(
                        proven=False,
                        object_base=hint.object_base,
                        index_term=f"frame@0x{hint.worker_pc:x}{hint.induction_offset:+d}",
                        element_size=hint.element_size,
                        item_count=hint.item_count,
                        thread_count=thread_count_value,
                        evidence=("Z3 found overlapping worker loop intervals",),
                        worker_pc=hint.worker_pc,
                        loop_pc=hint.loop_pc,
                    )
        return SymbolicPartitionProof(
            proven=True,
            object_base=hint.object_base,
            index_term=f"frame@0x{hint.worker_pc:x}{hint.induction_offset:+d}",
            element_size=hint.element_size,
            item_count=hint.item_count,
            thread_count=thread_count_value,
            evidence=(
                f"all {thread_count_value} thread ids reach the loop header",
                f"Z3 rejected overlap across {checked} path pairs",
                f"machine-code paths={len(paths)} item_count={hint.item_count}",
            ),
            worker_pc=hint.worker_pc,
            loop_pc=hint.loop_pc,
        )
    except Exception as error:
        return SymbolicPartitionProof(
            proven=False,
            object_base=hint.object_base,
            index_term=f"frame@0x{hint.worker_pc:x}{hint.induction_offset:+d}",
            element_size=hint.element_size,
            item_count=hint.item_count,
            thread_count=thread_count_value,
            evidence=(f"symbolic partition proof failed: {error}",),
            worker_pc=hint.worker_pc,
            loop_pc=hint.loop_pc,
        )
