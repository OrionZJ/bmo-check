"""把旧线程恢复报告转换成不完整的生命周期输入视图。

旧报告描述的是静态 role 和调用点，不包含一次运行中的 ThreadInstanceId、
pthread_t generation 或 START/END。适配器只保留可追踪字段并显式返回
INCOMPLETE，防止兼容读取被误当成新的生命周期证明。
"""

from __future__ import annotations

from bmo_check_core import (
    CompletenessState,
    CompletenessStatus,
    LifecycleJoinRelation,
    LifecycleKind,
    LifecycleLedger,
    LifecycleOperationId,
    ModuleId,
    ThreadLifecycleRecord,
    ThreadOrigin,
    ThreadRoleId,
)
from bmo_check_core.identity import InstructionId
from bmo_check_static.model import ModuleFingerprint, ThreadDiscoveryReport


def _incomplete(scope: str, reason: str) -> CompletenessState:
    return CompletenessState(CompletenessStatus.INCOMPLETE, scope, reason=reason)


def _role_ids(report: ThreadDiscoveryReport) -> dict[str, ThreadRoleId]:
    return {role.id: ThreadRoleId.from_legacy(role.id) for role in report.roles}


def _operation(
    subject: ModuleId,
    module: ModuleFingerprint,
    kind: LifecycleKind,
    pc: int,
    occurrence: str,
) -> LifecycleOperationId:
    site = InstructionId.from_parts(
        ModuleId.from_parts(module.sha256, module.role.value),
        pc,
    )
    return LifecycleOperationId.from_parts(subject, kind.value, site, None, occurrence)


def characterize_thread_discovery(
    report: ThreadDiscoveryReport,
    module: ModuleFingerprint,
    *,
    scope: str = "static.threading.legacy-lifecycle",
) -> LifecycleLedger:
    """返回旧静态线程报告的保守生命周期视图。

    ``ThreadDiscoveryReport.complete`` 只闭合 callback/parent 的静态事实；它
    不代表运行时线程已经有 START/END 或唯一 handle generation。因此即使
    role 和 join 候选已知，账本仍保持 INCOMPLETE。
    """

    subject = ModuleId.from_parts(module.sha256, module.role.value)
    role_ids = _role_ids(report)
    records: list[ThreadLifecycleRecord] = []
    for role in report.roles:
        thread_id = role_ids[role.id]
        parent = (
            role_ids.get(role.parent_role)
            if role.parent_role and role.parent_role != "unknown"
            else None
        )
        create_operation = (
            _operation(
                subject,
                module,
                LifecycleKind.CREATE,
                role.create_site.pc,
                f"legacy-role:{role.id}",
            )
            if role.create_site is not None
            else None
        )
        origin = (
            ThreadOrigin.ROOT
            if role.id == "main"
            else ThreadOrigin.CREATED
            if role.create_site is not None
            else ThreadOrigin.EXTERNAL
        )
        reason = "legacy static report has no runtime START/END identity"
        if not role.complete:
            reason += "; static role is incomplete"
        records.append(
            ThreadLifecycleRecord(
                thread_id=thread_id,
                origin=origin,
                parent_thread_id=parent,
                # 静态槽位不是带 generation 的 pthread_t；不能直接生成 handle 身份。
                handle_id=None,
                create_operation=create_operation,
                completeness=_incomplete(scope, reason),
            )
        )

    joins: list[LifecycleJoinRelation] = []
    for index, join in enumerate(report.joins):
        caller = role_ids.get(
            join.parent_role,
            ThreadRoleId.from_legacy(join.parent_role),
        )
        candidates = tuple(
            role_ids.get(candidate, ThreadRoleId.from_legacy(candidate))
            for candidate in join.candidate_child_roles
        )
        operation = _operation(
            subject,
            module,
            LifecycleKind.JOIN,
            join.call_site.pc,
            join.context_id or f"legacy-join:{index}",
        )
        reason = join.reason or (
            "legacy static join has no pthread_t generation or ThreadInstanceId"
        )
        joins.append(
            LifecycleJoinRelation(
                operation_id=operation,
                caller_thread_id=caller,
                # 静态 slot 名不能证明运行时句柄生命周期或唯一映射。
                handle_id=None,
                candidate_threads=candidates,
                target_thread=None,
                completeness=_incomplete(scope, reason),
            )
        )

    reason = "static report has no complete lifecycle event universe"
    if report.unknowns:
        reason += "; thread recovery contains unresolved facts"
    return LifecycleLedger(
        subject=subject,
        thread_universe=tuple(role_ids.values()),
        records=tuple(records),
        joins=tuple(joins),
        completeness=_incomplete(scope, reason),
    )


__all__ = ["characterize_thread_discovery"]
