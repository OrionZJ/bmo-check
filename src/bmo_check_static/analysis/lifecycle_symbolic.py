from __future__ import annotations

import logging
from dataclasses import dataclass

from bmo_check_static.model import LifecycleHint, ModuleFingerprint


@dataclass(frozen=True)
class SymbolicLifecycleProof:
    # proven 只表示 create/join 数量、handle 对应和 post-join 路径已经闭合。
    # worker 参数是否互异另由 worker_argument_base 是否存在表示。
    proven: bool
    # start_pc/post_join_pc 把证明限制在本次检查的机器码区间。
    start_pc: int
    post_join_pc: int
    # thread_count 绑定证书的执行范围，线程数变化后必须重证。
    thread_count: int
    # created_handles/joined_handles 保存机器码实际传给 pthread API 的槽位。
    created_handles: tuple[int, ...]
    joined_handles: tuple[int, ...]
    # created_arguments 保存传给 worker 的第四实参；None 表示符号值未唯一化。
    created_arguments: tuple[int | None, ...]
    # worker_argument_base 给已证明互异的第四实参一个证书内对象名。
    # 若 suite 没提供 allocation site，就使用绑定 start_pc 的生命周期名称。
    worker_argument_base: str | None
    # worker_argument_alias_base 命名所有 worker 共享的第四实参。
    # 它只允许证明“主线程初始化后 worker 只读”，不能推出线程间不相交。
    worker_argument_alias_base: str | None
    # evidence 记录闭合条件或首个失败原因。
    evidence: tuple[str, ...]


def prove_symbolic_lifecycle(
    module: ModuleFingerprint,
    hint: LifecycleHint,
    thread_count: int,
) -> SymbolicLifecycleProof:
    def failure(reason: str) -> SymbolicLifecycleProof:
        return SymbolicLifecycleProof(
            proven=False,
            start_pc=hint.start_pc,
            post_join_pc=hint.post_join_pc,
            thread_count=thread_count,
            created_handles=(),
            joined_handles=(),
            created_arguments=(),
            worker_argument_base=hint.worker_argument_base,
            worker_argument_alias_base=hint.worker_argument_alias_base,
            evidence=(reason,),
        )

    if not hint.assume_success:
        return failure(
            "lifecycle proof requires an explicit successful pthread execution scope"
        )
    try:
        logging.getLogger("angr").setLevel(logging.CRITICAL)
        logging.getLogger("cle").setLevel(logging.CRITICAL)
        import angr

        project = angr.Project(module.path, auto_load_libs=False)
        base = int(project.loader.main_object.mapped_base)

        class CreateProcedure(angr.SimProcedure):
            def run(self):  # type: ignore[no-untyped-def]
                slot_values = self.state.solver.eval_upto(self.state.regs.rdi, 2)
                if len(slot_values) != 1:
                    raise ValueError("pthread_create handle slot is not uniquely recoverable")
                slot = slot_values[0]
                created = tuple(self.state.globals.get("created_handles", ()))
                arguments = tuple(self.state.globals.get("created_arguments", ()))
                argument_values = self.state.solver.eval_upto(
                    self.state.regs.rcx, 2
                )
                self.state.globals["created_handles"] = (*created, slot)
                self.state.globals["created_arguments"] = (
                    *arguments,
                    argument_values[0] if len(argument_values) == 1 else None,
                )
                # pthread_create 成功后会写入 handle。用槽位本身作为唯一 handle，
                # join 若读错槽或漏掉某次创建就无法通过集合比较。
                self.state.memory.store(
                    slot,
                    slot,
                    size=project.arch.bytes,
                    endness=project.arch.memory_endness,
                )
                return 0

        class JoinProcedure(angr.SimProcedure):
            def run(self):  # type: ignore[no-untyped-def]
                handle_values = self.state.solver.eval_upto(self.state.regs.rdi, 2)
                if len(handle_values) != 1:
                    raise ValueError("pthread_join handle is not uniquely recoverable")
                handle = handle_values[0]
                joined = tuple(self.state.globals.get("joined_handles", ()))
                self.state.globals["joined_handles"] = (*joined, handle)
                return 0

        project.hook(base + hint.create_pc, CreateProcedure(), replace=True)
        project.hook(base + hint.join_pc, JoinProcedure(), replace=True)
        frame = 0x70010000
        state = project.factory.blank_state(addr=base + hint.start_pc)
        state.regs.rbp = frame
        state.regs.rsp = frame - 0x1000
        thread_count_address = (
            frame + hint.thread_count_stack_offset
            if hint.thread_count_stack_offset is not None
            else base + hint.thread_count_pc
        )
        state.memory.store(
            thread_count_address,
            thread_count,
            size=4,
            endness=project.arch.memory_endness,
        )
        for index, offset in enumerate(hint.frame_pointer_offsets):
            state.memory.store(
                frame + offset,
                0x71000000 + index * 0x10000,
                size=project.arch.bytes,
                endness=project.arch.memory_endness,
            )
        for offset, value in hint.global_pointer_values:
            # 中途入口只允许使用清单明确绑定的初始化结果；否则全局指针
            # 会保持符号值，create/join 槽位无法证明唯一对应关系。
            state.memory.store(
                base + offset,
                value,
                size=project.arch.bytes,
                endness=project.arch.memory_endness,
            )
        for offset, value in hint.stack_scalar_values:
            state.memory.store(
                frame + offset,
                value,
                size=4,
                endness=project.arch.memory_endness,
            )
        manager = project.factory.simulation_manager(state)
        manager.explore(find=base + hint.post_join_pc, num_find=2)
        if len(manager.found) != 1 or manager.errored or manager.unconstrained:
            return failure(
                "symbolic execution did not reach one closed post-join path"
                f" (found={len(manager.found)}, active={len(manager.active)}, deadended={len(manager.deadended)},"
                f" errored={len(manager.errored)}, unconstrained={len(manager.unconstrained)},"
                f" unconstrained_pcs={[item.solver.eval_upto(item.regs._ip, 2) for item in manager.unconstrained]})"
            )

        found = manager.found[0]
        created = tuple(found.globals.get("created_handles", ()))
        joined = tuple(found.globals.get("joined_handles", ()))
        arguments = tuple(found.globals.get("created_arguments", ()))
        if len(created) != thread_count:
            return failure(
                f"machine code created {len(created)} workers, expected {thread_count}"
            )
        if len(joined) != thread_count or sorted(joined) != sorted(created):
            return failure("pthread_join handles do not exactly cover created handles")
        if len(set(created)) != len(created):
            return failure("pthread_create reused one handle slot")
        if len(arguments) != thread_count:
            return failure("pthread_create worker argument count is incomplete")
        distinct_arguments = (
            all(argument is not None for argument in arguments)
            and len(set(arguments)) == len(arguments)
        )
        return SymbolicLifecycleProof(
            proven=True,
            start_pc=hint.start_pc,
            post_join_pc=hint.post_join_pc,
            thread_count=thread_count,
            created_handles=created,
            joined_handles=joined,
            created_arguments=arguments,
            worker_argument_base=(
                (
                    hint.worker_argument_base
                    or f"lifecycle-worker-arguments@0x{hint.start_pc:x}"
                )
                if distinct_arguments
                else None
            ),
            worker_argument_alias_base=hint.worker_argument_alias_base,
            evidence=(
                f"machine code creates {len(created)} distinct worker handles",
                f"machine code joins all {len(joined)} created handles",
                (
                    f"machine code passes {len(arguments)} distinct worker arguments"
                    if distinct_arguments
                    else "machine code passes a shared worker argument; no disjoint partition proof is derived"
                ),
                "pthread_create and pthread_join returned success in the checked path",
                "suite scope explicitly excludes failed pthread_create/join calls",
            ),
        )
    except Exception as error:
        return failure(f"symbolic lifecycle proof failed: {error}")
