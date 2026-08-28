from __future__ import annotations

from .binary import ProgramManifest
from .common import StrictModel
from .controlflow import ControlFlowReport
from .sync import SynchronizationReport
from .thread import ThreadDiscoveryReport
from .unknown import UnknownFact


class ProgramRecoveryReport(StrictModel):
    # manifest 把后续结论绑定到同一组 executable、动态库和 DBT contract。
    manifest: ProgramManifest
    # ELF 不完整时没有可分析的主程序，不能用空 CFG 冒充“没有代码”。
    control_flow: ControlFlowReport | None = None
    # thread_roles 只描述二进制中能够恢复的 pthread 创建与 join 关系。
    thread_roles: ThreadDiscoveryReport | None = None
    # 一个进程可能从多个实际动态库取得同步 API，因此按库分别绑定摘要。
    synchronization: tuple[SynchronizationReport, ...] = ()
    # orchestration 自身的失败放在顶层，不能静默丢掉整层分析。
    unknowns: tuple[UnknownFact, ...] = ()
