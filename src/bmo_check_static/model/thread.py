from __future__ import annotations

from pydantic import model_validator

from .common import StrictModel
from .controlflow import CodeLocation, IndirectTargetSet
from .unknown import UnknownFact


class ThreadRole(StrictModel):
    # id 标识同一 create site 产生的一类动态线程，而不是一次具体运行。
    id: str
    # parent_role 记录谁执行 pthread_create；无法确定时不能猜测。
    parent_role: str | None = None
    # create_site 让未知 worker 能定位回原始调用点。
    create_site: CodeLocation | None = None
    # start_targets 分离已知 callback 与集合是否封闭。
    start_targets: IndirectTargetSet
    # argument_origin 解释第四实参来自哪条块内定义。
    argument_origin: str | None = None
    # complete 同时要求线程入口和角色归属没有未决缺口。
    complete: bool = False


class ThreadCreateFact(StrictModel):
    # call_site 指向 pthread_create 的 guest call 指令。
    call_site: CodeLocation
    # parent_role 是执行该调用的线程类。
    parent_role: str
    # child_role 连接 create 事实与新建的 ThreadRole。
    child_role: str
    # start_targets 未封闭时后续可达代码必须保持 Unknown。
    start_targets: IndirectTargetSet
    # argument_origin 仅用于解释，不证明参数指向私有内存。
    argument_origin: str | None = None


class ThreadJoinFact(StrictModel):
    # call_site 指向 pthread_join 的 guest call 指令。
    call_site: CodeLocation
    # parent_role 是执行 join 的线程类。
    parent_role: str
    # candidate_child_roles 允许过近似，不能漏掉可能被 join 的线程。
    candidate_child_roles: tuple[str, ...] = ()
    # complete 表示 handle 到角色的映射已经封闭。
    complete: bool
    # 映射不完整时记录阻止后续 lifetime 证明的原因。
    reason: str | None = None

    @model_validator(mode="after")
    def require_incomplete_reason(self) -> "ThreadJoinFact":
        if not self.complete and not self.reason:
            raise ValueError("incomplete join relation requires a reason")
        return self


class ThreadParallelFact(StrictModel):
    # call_site 指向 GOMP_parallel；返回前 runtime 会等待这个 worker 阶段。
    call_site: CodeLocation
    # parent_role 记录哪个静态线程角色进入并行区。
    parent_role: str
    # worker_role 绑定第一个参数指向的 OpenMP callback。
    worker_role: str
    # start_targets 保存 callback 的封闭目标集合。
    start_targets: IndirectTargetSet
    # complete=False 时不能用隐式 barrier 剪掉跨阶段通信。
    complete: bool


class ThreadDiscoveryReport(StrictModel):
    # schema_version 防止后续误读角色和 join 字段。
    schema_version: int = 1
    # roles 是动态线程类；同一 create site 的多次创建归为一个角色。
    roles: tuple[ThreadRole, ...] = ()
    # creates 和 joins 保存原始 pthread 调用关系。
    creates: tuple[ThreadCreateFact, ...] = ()
    joins: tuple[ThreadJoinFact, ...] = ()
    # parallel_regions 保存 OpenMP callback 与隐式 barrier 的关系；它们
    # 不进入 pthread handle 映射，但 slice builder 需要用它们连接阶段。
    parallel_regions: tuple[ThreadParallelFact, ...] = ()
    # unknowns 显式记录未封闭的 callback、parent 和 handle 映射。
    unknowns: tuple[UnknownFact, ...] = ()
    # single_thread_proven 只有在 main 可达调用图封闭且没有可达线程 API
    # 时为真；死代码中的 pthread_create 不会推翻这条局部证明。
    single_thread_proven: bool = False
    # single_thread_evidence 保存调用图根和排除线程入口的二进制事实。
    single_thread_evidence: tuple[str, ...] = ()
