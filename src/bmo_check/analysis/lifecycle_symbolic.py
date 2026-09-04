from __future__ import annotations

import logging
from dataclasses import dataclass

from bmo_check.model import LifecycleHint, ModuleFingerprint


@dataclass(frozen=True)
class SymbolicLifecycleProof:
    # proven 只有在每个成功 create 的 handle 都被 join 且路径闭合时才为 true。
    proven: bool
    # start_pc/post_join_pc 把证明限制在本次检查的机器码区间。
    start_pc: int
    post_join_pc: int
    # thread_count 绑定证书的执行范围，线程数变化后必须重证。
    thread_count: int
    # created_handles/joined_handles 保存机器码实际传给 pthread API 的槽位。
    created_handles: tuple[int, ...]
    joined_handles: tuple[int, ...]
    # created_arguments 保存传给 worker 的第四实参，用于证明参数对象不重叠。
    created_arguments: tuple[int, ...]
    # worker_argument_base 给已证明互异的第四实参一个证书内对象名。
    # 若 suite 没提供 allocation site，就使用绑定 start_pc 的生命周期名称。
    worker_argument_base: str | None
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
                slot = self.state.solver.eval(self.state.regs.rdi)
                created = tuple(self.state.globals.get("created_handles", ()))
                arguments = tuple(self.state.globals.get("created_arguments", ()))
                self.state.globals["created_handles"] = (*created, slot)
                self.state.globals["created_arguments"] = (
                    *arguments,
                    self.state.solver.eval(self.state.regs.rcx),
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
                handle = self.state.solver.eval(self.state.regs.rdi)
                joined = tuple(self.state.globals.get("joined_handles", ()))
                self.state.globals["joined_handles"] = (*joined, handle)
                return 0

        project.hook(base + hint.create_pc, CreateProcedure(), replace=True)
        project.hook(base + hint.join_pc, JoinProcedure(), replace=True)
        frame = 0x70010000
        state = project.factory.blank_state(addr=base + hint.start_pc)
        state.regs.rbp = frame
        state.regs.rsp = frame - 0x1000
        state.memory.store(
            base + hint.thread_count_pc,
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
        manager = project.factory.simulation_manager(state)
        manager.explore(find=base + hint.post_join_pc, num_find=2)
        if len(manager.found) != 1 or manager.errored or manager.unconstrained:
            return failure("symbolic execution did not reach one closed post-join path")

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
        if len(arguments) != thread_count or len(set(arguments)) != len(arguments):
            return failure("pthread_create worker arguments are not pairwise distinct")
        return SymbolicLifecycleProof(
            proven=True,
            start_pc=hint.start_pc,
            post_join_pc=hint.post_join_pc,
            thread_count=thread_count,
            created_handles=created,
            joined_handles=joined,
            created_arguments=arguments,
            worker_argument_base=(
                hint.worker_argument_base
                or f"lifecycle-worker-arguments@0x{hint.start_pc:x}"
            ),
            evidence=(
                f"machine code creates {len(created)} distinct worker handles",
                f"machine code joins all {len(joined)} created handles",
                f"machine code passes {len(arguments)} distinct worker arguments",
                "pthread_create and pthread_join returned success in the checked path",
                "suite scope explicitly excludes failed pthread_create/join calls",
            ),
        )
    except Exception as error:
        return failure(f"symbolic lifecycle proof failed: {error}")
