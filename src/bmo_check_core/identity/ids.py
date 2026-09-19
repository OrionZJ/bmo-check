from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Iterable, TypeVar


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IdT = TypeVar("_IdT", bound="StableId")


class IdentityMaterialError(ValueError):
    """身份字段不具备稳定语义时抛出的输入错误。"""


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise IdentityMaterialError(f"{name} must be a non-empty string without NUL")
    return value


def _sha256(name: str, value: str) -> str:
    value = _text(name, value).lower()
    if not _HEX64.fullmatch(value):
        raise IdentityMaterialError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _offset(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise IdentityMaterialError(f"{name} must be a non-negative integer")
    return value


def _canonical(material: object) -> bytes:
    try:
        encoded = json.dumps(
            material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise IdentityMaterialError("identity material is not canonical JSON") from error
    return encoded.encode("utf-8")


def _digest(prefix: str, material: object) -> str:
    # 把类型前缀放进摘要，避免同一组字段在不同身份类型间发生碰撞。
    payload = prefix.encode("ascii") + b"\0" + _canonical(material)
    return hashlib.sha256(payload).hexdigest()


def _sorted_strings(name: str, values: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(_text(name, value) for value in values)
    return tuple(sorted(normalized))


def _ordered_strings(name: str, values: Iterable[str]) -> tuple[str, ...]:
    """校验有方向的 identity terms，但不把 source/target 排序。"""

    return tuple(_text(name, value) for value in values)


def _sorted_module_refs(
    modules: Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    normalized = tuple(
        (_text("module role", role), _sha256("module hash", module_sha256))
        for role, module_sha256 in modules
    )
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class StableId:
    """所有语义 ID 的共同值对象；只保存摘要，防止调用者修改身份材料。"""

    # digest 是规范化语义材料的摘要，不是进程内计数器或对象地址。
    digest: str
    prefix: ClassVar[str] = "id"

    def __post_init__(self) -> None:
        if not _ID_DIGEST.fullmatch(self.digest):
            raise IdentityMaterialError("identity digest must be 64 lowercase hex digits")

    @property
    def value(self) -> str:
        return f"{self.prefix}:{self.digest}"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_value(cls: type[_IdT], value: str) -> _IdT:
        value = _text("identity value", value)
        expected_prefix = f"{cls.prefix}:"
        if not value.startswith(expected_prefix):
            raise IdentityMaterialError(
                f"identity value must start with {expected_prefix!r}"
            )
        digest = value[len(expected_prefix) :]
        if not _ID_DIGEST.fullmatch(digest):
            raise IdentityMaterialError("identity value has an invalid digest")
        return cls(digest)


@dataclass(frozen=True, slots=True)
class ModuleId(StableId):
    prefix: ClassVar[str] = "module"

    @classmethod
    def from_parts(cls, module_sha256: str, role: str) -> "ModuleId":
        material = {
            "module_sha256": _sha256("module hash", module_sha256),
            "role": _text("module role", role),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class BinaryClosureId(StableId):
    prefix: ClassVar[str] = "closure"

    @classmethod
    def from_parts(
        cls,
        executable_sha256: str,
        modules: Iterable[tuple[str, str]],
        abi: str,
    ) -> "BinaryClosureId":
        material = {
            "abi": _text("ABI", abi),
            "executable_sha256": _sha256("executable hash", executable_sha256),
            # module closure 是集合；排序让 ELF/loader 遍历顺序不改变证书绑定。
            "modules": _sorted_module_refs(modules),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class FunctionId(StableId):
    prefix: ClassVar[str] = "function"

    @classmethod
    def from_parts(cls, module: ModuleId, entry_offset: int) -> "FunctionId":
        material = {
            "entry_offset": _offset("function entry offset", entry_offset),
            "module": module.value,
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class BasicBlockId(StableId):
    prefix: ClassVar[str] = "block"

    @classmethod
    def from_parts(cls, function: FunctionId, block_offset: int) -> "BasicBlockId":
        material = {
            "block_offset": _offset("basic-block offset", block_offset),
            "function": function.value,
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class InstructionId(StableId):
    prefix: ClassVar[str] = "instruction"

    @classmethod
    def from_parts(
        cls, module: ModuleId, instruction_offset: int
    ) -> "InstructionId":
        material = {
            "instruction_offset": _offset("instruction offset", instruction_offset),
            "module": module.value,
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class MemoryOperandId(StableId):
    prefix: ClassVar[str] = "operand"

    @classmethod
    def from_parts(
        cls,
        instruction: InstructionId,
        operand_index: int,
        effect_discriminator: str,
    ) -> "MemoryOperandId":
        material = {
            "effect_discriminator": _text(
                "effect discriminator", effect_discriminator
            ),
            "instruction": instruction.value,
            "operand_index": _offset("memory operand index", operand_index),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class ThreadRoleId(StableId):
    prefix: ClassVar[str] = "thread-role"

    @classmethod
    def from_legacy(cls, role: str) -> "ThreadRoleId":
        """为尚未迁移的静态角色保留稳定身份。

        这个入口只供兼容适配器使用。新分析器必须从父角色、创建点和入口集合
        计算角色，不能把可读标签当成完整的线程证明。
        """

        return cls(_digest(cls.prefix, {"legacy_role": _text("legacy role", role)}))

    @classmethod
    def from_parts(
        cls,
        parent_role: "ThreadRoleId | None",
        creation_site: InstructionId | None,
        start_targets: Iterable[FunctionId],
    ) -> "ThreadRoleId":
        if parent_role is not None and not isinstance(parent_role, ThreadRoleId):
            raise IdentityMaterialError("parent role must be a ThreadRoleId")
        if creation_site is not None and not isinstance(creation_site, InstructionId):
            raise IdentityMaterialError("creation site must be an InstructionId")
        targets: list[str] = []
        for target in start_targets:
            if not isinstance(target, FunctionId):
                raise IdentityMaterialError("thread start target must be a FunctionId")
            targets.append(target.value)
        material = {
            "creation_site": creation_site.value if creation_site else None,
            "parent_role": parent_role.value if parent_role else None,
            "start_targets": tuple(sorted(targets)),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class MemoryEventId(StableId):
    prefix: ClassVar[str] = "event"

    @classmethod
    def from_parts(
        cls,
        operand: MemoryOperandId,
        thread_role: ThreadRoleId,
        event_kind: str,
        summary_discriminator: str,
    ) -> "MemoryEventId":
        material = {
            "event_kind": _text("event kind", event_kind),
            "operand": operand.value,
            "summary_discriminator": _text(
                "summary discriminator", summary_discriminator
            ),
            "thread_role": thread_role.value,
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class RelationId(StableId):
    """一个有稳定端点的程序关系身份。"""

    prefix: ClassVar[str] = "relation"

    @classmethod
    def from_parts(
        cls,
        kind: str,
        subjects: Iterable[StableId],
        *,
        symmetric: bool = False,
        discriminator: str = "",
    ) -> "RelationId":
        if not isinstance(symmetric, bool):
            raise IdentityMaterialError("relation symmetry must be boolean")
        values = tuple(subjects)
        if not values or any(not isinstance(item, StableId) for item in values):
            raise IdentityMaterialError("relation subjects must be non-empty StableId values")
        normalized = tuple(sorted(item.value for item in values)) if symmetric else tuple(
            item.value for item in values
        )
        material = {
            "discriminator": _text("relation discriminator", discriminator)
            if discriminator
            else None,
            "kind": _text("relation kind", kind),
            "subjects": normalized,
            "symmetric": symmetric,
        }
        return cls(_digest(cls.prefix, material))


class ObjectOrigin(StrEnum):
    # GLOBAL 表示 ELF 全局对象或符号来源。
    GLOBAL = "global"
    # TLS 表示每个线程独立的 TLS 槽位。
    TLS = "tls"
    # FRAME 表示函数栈帧及其来源位置。
    FRAME = "frame"
    # ALLOCATION 表示带 allocation-site 身份的堆对象。
    ALLOCATION = "allocation"
    # MAPPING 表示 mmap 等映射生命周期创建的对象。
    MAPPING = "mapping"


@dataclass(frozen=True, slots=True)
class AbstractObjectId(StableId):
    prefix: ClassVar[str] = "object"

    @classmethod
    def from_parts(
        cls, origin: ObjectOrigin, origin_identity: str
    ) -> "AbstractObjectId":
        if not isinstance(origin, ObjectOrigin):
            raise IdentityMaterialError("object origin must be an ObjectOrigin")
        material = {
            "origin": origin.value,
            "origin_identity": _text("object origin identity", origin_identity),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class TraceId(StableId):
    prefix: ClassVar[str] = "trace"

    @classmethod
    def from_parts(
        cls,
        trace_format_version: str,
        manifest_digest: str,
        modules: Iterable[ModuleId],
        markers: Iterable[str],
        records_digest: str,
    ) -> "TraceId":
        normalized_modules: list[str] = []
        for module in modules:
            if not isinstance(module, ModuleId):
                raise IdentityMaterialError("trace module must be a ModuleId")
            normalized_modules.append(module.value)
        material = {
            "manifest_digest": _sha256("manifest digest", manifest_digest),
            "markers": _sorted_strings("trace marker", markers),
            "modules": tuple(sorted(normalized_modules)),
            "records_digest": _sha256("records digest", records_digest),
            "trace_format_version": _text(
                "trace format version", trace_format_version
            ),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class ThreadInstanceId(StableId):
    prefix: ClassVar[str] = "thread-instance"

    @classmethod
    def from_parts(
        cls, trace: TraceId, tracer_thread_instance: str | int
    ) -> "ThreadInstanceId":
        if not isinstance(trace, TraceId):
            raise IdentityMaterialError("thread instance trace must be a TraceId")
        if isinstance(tracer_thread_instance, bool):
            raise IdentityMaterialError("tracer thread instance cannot be boolean")
        if isinstance(tracer_thread_instance, int):
            identity: str | int = _offset(
                "tracer thread instance", tracer_thread_instance
            )
        else:
            identity = _text("tracer thread instance", tracer_thread_instance)
        return cls(_digest(cls.prefix, {"instance": identity, "trace": trace.value}))


@dataclass(frozen=True, slots=True)
class ThreadHandleId(StableId):
    """把 pthread_t/句柄值绑定到一个 subject 和明确的生命周期代数。"""

    prefix: ClassVar[str] = "thread-handle"

    @classmethod
    def from_parts(
        cls,
        subject: StableId,
        token: str,
        generation: int,
    ) -> "ThreadHandleId":
        # 句柄数值会被复用；没有 subject 和 generation，两个生命周期会被误连。
        if not isinstance(subject, StableId):
            raise IdentityMaterialError("thread handle subject must be a StableId")
        material = {
            "generation": _offset("thread handle generation", generation),
            "subject": subject.value,
            "token": _text("thread handle token", token),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class LifecycleContextId(StableId):
    """标识一个 caller/call-site/callback 组合，避免合并不同上下文。"""

    prefix: ClassVar[str] = "lifecycle-context"

    @classmethod
    def from_parts(
        cls,
        caller: FunctionId,
        call_site: InstructionId,
        target_functions: Iterable[FunctionId] = (),
    ) -> "LifecycleContextId":
        if not isinstance(caller, FunctionId):
            raise IdentityMaterialError("lifecycle caller must be a FunctionId")
        if not isinstance(call_site, InstructionId):
            raise IdentityMaterialError("lifecycle call site must be an InstructionId")
        targets: list[str] = []
        for target in target_functions:
            if not isinstance(target, FunctionId):
                raise IdentityMaterialError(
                    "lifecycle target must be a FunctionId"
                )
            targets.append(target.value)
        return cls(
            _digest(
                cls.prefix,
                {
                    "call_site": call_site.value,
                    "caller": caller.value,
                    "target_functions": tuple(sorted(targets)),
                },
            )
        )


@dataclass(frozen=True, slots=True)
class LifecycleOperationId(StableId):
    """标识一次有明确位置和上下文的生命周期/同步操作。"""

    prefix: ClassVar[str] = "lifecycle-operation"

    @classmethod
    def from_parts(
        cls,
        subject: StableId,
        operation_kind: str,
        site: StableId,
        context: LifecycleContextId | None,
        occurrence: str,
    ) -> "LifecycleOperationId":
        # occurrence 必须由 producer 提供稳定身份；不能用调度 ticket 或遍历序号猜测。
        if not isinstance(subject, StableId):
            raise IdentityMaterialError("lifecycle subject must be a StableId")
        if not isinstance(site, StableId):
            raise IdentityMaterialError("lifecycle site must be a StableId")
        if context is not None and not isinstance(context, LifecycleContextId):
            raise IdentityMaterialError("lifecycle context must be typed")
        return cls(
            _digest(
                cls.prefix,
                {
                    "context": context.value if context else None,
                    "kind": _text("lifecycle operation kind", operation_kind),
                    "occurrence": _text("lifecycle operation occurrence", occurrence),
                    "site": site.value,
                    "subject": subject.value,
                },
            )
        )


@dataclass(frozen=True, slots=True)
class PropositionId(StableId):
    prefix: ClassVar[str] = "proposition"

    @classmethod
    def from_parts(cls, kind: str, terms: Iterable[str]) -> "PropositionId":
        """为有方向的命题绑定 kind 和端点参数，保持 source/target 顺序。"""

        material = {
            "kind": _text("proposition kind", kind),
            "terms": _ordered_strings("proposition term", terms),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class ObligationId(StableId):
    prefix: ClassVar[str] = "obligation"

    @classmethod
    def from_parts(
        cls,
        kind: str,
        scope: str,
        subjects: Iterable[str],
    ) -> "ObligationId":
        """为 proof obligation 绑定 scope 和 subject 集合，不使用遍历编号。"""

        material = {
            "kind": _text("obligation kind", kind),
            "scope": _text("obligation scope", scope),
            "subjects": _sorted_strings("obligation subject", subjects),
        }
        return cls(_digest(cls.prefix, material))


@dataclass(frozen=True, slots=True)
class EvidenceId(StableId):
    prefix: ClassVar[str] = "evidence"

    @classmethod
    def from_parts(
        cls,
        category: str,
        schema_version: str,
        producer: str,
        subject: StableId | str,
        premises: Iterable["EvidenceId"],
        content_discriminator: str = "",
    ) -> "EvidenceId":
        if isinstance(subject, StableId):
            subject_value = subject.value
        else:
            subject_value = _text("evidence subject", subject)
        normalized_premises: list[str] = []
        for premise in premises:
            if not isinstance(premise, EvidenceId):
                raise IdentityMaterialError("evidence premise must be an EvidenceId")
            normalized_premises.append(premise.value)
        material = {
            "category": _text("evidence category", category),
            "content_discriminator": _text(
                "content discriminator", content_discriminator
            )
            if content_discriminator
            else None,
            "premises": tuple(sorted(normalized_premises)),
            "producer": _text("evidence producer", producer),
            "schema_version": _text("evidence schema version", schema_version),
            "subject": subject_value,
        }
        return cls(_digest(cls.prefix, material))


__all__ = [
    "AbstractObjectId",
    "BasicBlockId",
    "BinaryClosureId",
    "EvidenceId",
    "FunctionId",
    "IdentityMaterialError",
    "InstructionId",
    "LifecycleContextId",
    "LifecycleOperationId",
    "MemoryEventId",
    "MemoryOperandId",
    "ModuleId",
    "ObjectOrigin",
    "ObligationId",
    "PropositionId",
    "RelationId",
    "StableId",
    "ThreadHandleId",
    "ThreadInstanceId",
    "ThreadRoleId",
    "TraceId",
]
