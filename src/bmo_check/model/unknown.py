from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field

from .common import StrictModel


class UnknownKind(str, Enum):
    MISSING_EXECUTABLE = "MissingExecutable"
    INVALID_ELF = "InvalidElf"
    UNSUPPORTED_ARCHITECTURE = "UnsupportedArchitecture"
    MISSING_INTERPRETER = "MissingInterpreter"
    MISSING_LIBRARY = "MissingLibrary"
    AMBIGUOUS_LIBRARY = "AmbiguousLibrary"
    ELF_BACKEND_FAILURE = "ElfBackendFailure"
    DISASSEMBLY_FAILURE = "DisassemblyFailure"
    INCOMPLETE_INSTRUCTION = "IncompleteInstructionFact"
    UNRESOLVED_INDIRECT_CALL = "UnresolvedIndirectCall"
    UNKNOWN_THREAD_ENTRY = "UnknownThreadEntry"
    UNKNOWN_MEMORY_EFFECT = "UnknownMemoryEffect"
    UNKNOWN_SHARED_ADDRESS = "UnknownSharedAddress"
    UNKNOWN_ESCAPE = "UnknownEscape"
    UNKNOWN_SYNCHRONIZATION = "UnknownSynchronization"
    UNSUPPORTED_DYNAMIC_CODE = "UnsupportedDynamicCode"
    PORTABILITY_CHECK_INCOMPLETE = "PortabilityCheckIncomplete"
    MISSING_DBT_REVISION = "MissingDbtRevision"
    INVALID_DBT_CONTRACT = "InvalidDbtContract"
    # angr 后端失败后没有可用 CFG，不能解释成零个可达函数。
    CFG_BACKEND_FAILURE = "CfgBackendFailure"
    # 间接目标只有候选但缺少封闭证据。
    INCOMPLETE_INDIRECT_TARGET = "IncompleteIndirectTarget"
    # API 存在但实际 ELF 中没有可绑定的函数体。
    MISSING_SYMBOL_IMPLEMENTATION = "MissingSymbolImplementation"
    # 调用实参或线程父角色的定义无法唯一恢复。
    REACHING_DEFINITION_FAILURE = "ReachingDefinitionFailure"
    # pthread handle 无法唯一映射到已恢复的 child role。
    UNKNOWN_JOIN_RELATION = "UnknownJoinRelation"
    # 事件提取失败后不能用空事件集继续剪枝。
    MEMORY_EVENT_RECOVERY_FAILURE = "MemoryEventRecoveryFailure"
    # 一个函数可由零个或多个线程角色到达，事件归属无法唯一确定。
    UNKNOWN_THREAD_ROLE = "UnknownThreadRole"
    # 地址已恢复为仿射式，但缺少线程或循环 bounds。
    UNKNOWN_AFFINE_BOUNDS = "UnknownAffineBounds"
    # checker 不支持该事件、地址形态或执行结构。
    UNSUPPORTED_PORTABILITY_INPUT = "UnsupportedPortabilityInput"
    # solver 或整个有限执行搜索超过显式时间上限。
    PORTABILITY_CHECK_TIMEOUT = "PortabilityCheckTimeout"
    # target 执行枚举达到上限，剩余关系尚未检查。
    PORTABILITY_CHECK_BOUND = "PortabilityCheckBound"
    # certificate 的 binary、DBT 或 config 指纹与当前输入不同。
    STALE_CERTIFICATE = "StaleCertificate"


class UnknownFact(StrictModel):
    kind: UnknownKind
    reason: str
    impact: str
    module: str | None = None
    pc: int | None = None
    function: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
