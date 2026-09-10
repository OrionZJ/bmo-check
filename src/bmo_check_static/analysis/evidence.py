"""MemoryEvent producer 的 canonical evidence 旁路。"""

from __future__ import annotations

from dataclasses import dataclass

from bmo_check_core import (
    EvidenceId,
    EvidenceLedger,
    InstructionId,
    MemoryEventId,
    MemoryOperandId,
    ModuleId,
    ThreadRoleId,
    UnknownFact,
)
from bmo_check_static.model import (
    ControlFlowReport,
    MemoryEvent,
    MemoryEventReport,
    ModuleFingerprint,
    SynchronizationReport,
    ThreadDiscoveryReport,
)

from .memory_events import extract_memory_events


class MemoryEvidenceError(ValueError):
    """访存事件缺少稳定身份材料时拒绝生成旁路结果。"""


@dataclass(frozen=True, slots=True)
class MemoryEventIdentityLink:
    # legacy_id 让旧 report 中的事件能回查到 canonical MemoryEventId。
    legacy_id: str
    # canonical_id 绑定模块、PC、operand、线程角色和 effect 类型。
    canonical_id: MemoryEventId

    def __post_init__(self) -> None:
        if not isinstance(self.legacy_id, str) or not self.legacy_id:
            raise MemoryEvidenceError("legacy memory event id must be non-empty")
        if not isinstance(self.canonical_id, MemoryEventId):
            raise MemoryEvidenceError("memory event link must contain MemoryEventId")


@dataclass(frozen=True, slots=True)
class StaticMemoryEventEvidence:
    # report 保留现有 slicing/proof consumers 使用的事件和 Unknown 格式。
    report: MemoryEventReport
    # ledger 保存事件 producer 产生的 canonical UnknownFact。
    ledger: EvidenceLedger
    # event_links 显式记录旧字符串 ID 到稳定事件身份的映射。
    event_links: tuple[MemoryEventIdentityLink, ...] = ()

    @property
    def event_ids(self) -> tuple[MemoryEventId, ...]:
        return tuple(
            sorted(
                {link.canonical_id for link in self.event_links},
                key=lambda item: item.value,
            )
        )

    @property
    def unknown_ids(self) -> tuple[EvidenceId, ...]:
        return tuple(
            sorted(
                {
                    node.id
                    for node in self.ledger.nodes()
                    if isinstance(node, UnknownFact)
                },
                key=lambda item: item.value,
            )
        )


def memory_event_identity(module: ModuleFingerprint, event: MemoryEvent) -> MemoryEventId:
    if not event.id:
        raise MemoryEvidenceError("memory events require a non-empty legacy id")
    if event.module != module.path or event.module_sha256 != module.sha256:
        raise MemoryEvidenceError(
            f"memory event {event.id!r} is not bound to the extracted module"
        )
    if event.pc < 0:
        raise MemoryEvidenceError(f"memory event {event.id!r} has a negative PC")
    operand_index = event.operand_index
    if operand_index is None:
        operand_index = 0
        effect_discriminator = f"{event.kind.value}:implicit"
    elif operand_index < 0:
        # Capstone 用 -1 标记 call/push 等隐式访问；身份类型只接受非负索引，
        # 因此把“隐式”放入 discriminator，避免和显式 operand 0 混淆。
        operand_index = 0
        effect_discriminator = f"{event.kind.value}:implicit"
    else:
        effect_discriminator = event.kind.value
    module_id = ModuleId.from_parts(module.sha256, module.role.value)
    instruction = InstructionId.from_parts(module_id, event.pc)
    operand = MemoryOperandId.from_parts(
        instruction,
        operand_index,
        effect_discriminator,
    )
    role = ThreadRoleId.from_legacy(event.thread_role or "legacy-unknown-thread-role")
    return MemoryEventId.from_parts(
        operand,
        role,
        event.kind.value,
        event.id,
    )


def extract_memory_events_with_evidence(
    module: ModuleFingerprint,
    control_flow: ControlFlowReport,
    threads: ThreadDiscoveryReport,
    synchronization: tuple[SynchronizationReport, ...] = (),
    *,
    function_effects: dict[str, str] | None = None,
    function_integer_arguments: dict[str, tuple[int, ...]] | None = None,
    function_memory_arguments: dict[str, tuple[tuple[int, str], ...]] | None = None,
    function_internal_objects: dict[str, str] | None = None,
    worker_argument_base: str | None = None,
    worker_argument_alias_base: str | None = None,
    scope: str = "static.memory",
) -> StaticMemoryEventEvidence:
    """运行同一访存 producer，并返回旧报告、事件身份和 canonical Unknown。"""

    ledger = EvidenceLedger()
    report = extract_memory_events(
        module,
        control_flow,
        threads,
        synchronization,
        function_effects=function_effects,
        function_integer_arguments=function_integer_arguments,
        function_memory_arguments=function_memory_arguments,
        function_internal_objects=function_internal_objects,
        worker_argument_base=worker_argument_base,
        worker_argument_alias_base=worker_argument_alias_base,
        canonical_ledger=ledger,
        canonical_scope=scope,
    )
    links = tuple(
        MemoryEventIdentityLink(event.id, memory_event_identity(module, event))
        for event in sorted(report.events, key=lambda item: item.id)
    )
    return StaticMemoryEventEvidence(report=report, ledger=ledger, event_links=links)


__all__ = [
    "MemoryEvidenceError",
    "MemoryEventIdentityLink",
    "StaticMemoryEventEvidence",
    "extract_memory_events_with_evidence",
    "memory_event_identity",
]
