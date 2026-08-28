from __future__ import annotations

from .common import StrictModel
from .memory_event import MemoryEventReport
from .recovery import ProgramRecoveryReport
from .sharing import SharedMemorySlice, SharedStateReport
from .unknown import UnknownFact


class ProgramSliceReport(StrictModel):
    # recovery 保留生成事件时使用的 binary、CFG、thread 和 sync 输入。
    recovery: ProgramRecoveryReport
    # memory_events 是 backend-independent 的原始 effect 层。
    memory_events: MemoryEventReport | None = None
    # shared_state 保存对象分类和逐事件剪枝证明。
    shared_state: SharedStateReport | None = None
    # shared_slice 是 Milestone 2 的最终产物，不是 SAFE verdict。
    shared_slice: SharedMemorySlice | None = None
    # 顶层失败必须显式传播，不能输出空 slice 冒充成功。
    unknowns: tuple[UnknownFact, ...] = ()
