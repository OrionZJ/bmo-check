from __future__ import annotations

from .manifest import StrictModel


class InstructionSiteEvidence(StrictModel):
    # module_path 把证据绑定到具体文件，防止同名符号混在一起。
    module_path: str
    # module_offset 不受 ASLR 影响，可直接和反汇编位置交叉核对。
    module_offset: int
    # 一个模块可能被重复映射；这里保留本次轨迹中实际检查过的运行时 PC。
    runtime_pcs: tuple[int, ...]
    # event_count 为零也有意义：它说明这条指令没有出现在该次轨迹中。
    event_count: int
    # thread_event_counts 区分初始化线程和 worker，防止把同址别名都当成发布操作。
    thread_event_counts: tuple[tuple[int, int], ...] = ()
    # thread_sequence_bounds 给出每个线程的执行阶段，便于和线程生命周期交叉核对。
    thread_sequence_bounds: tuple[tuple[int, int, int], ...] = ()
    # kind_counts 用来确认目标点实际是普通 Store，而不是追踪器识别出的原子访问。
    kind_counts: tuple[tuple[str, int], ...] = ()
    # size_counts 暴露访问宽度；宽度不符通常意味着 offset 或反汇编对应错了。
    size_counts: tuple[tuple[int, int], ...] = ()
    # flag_counts 保留 LOCK/XCHG 等原始分类，不能只凭助记符推断运行时事件。
    flag_counts: tuple[tuple[int, int], ...] = ()
