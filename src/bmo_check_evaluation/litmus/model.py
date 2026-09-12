"""严格的 E2.5 fixture/oracle wire model。

这些类型只描述可复现的验证输入。它们不会变成静态证明证据，也不携带
任何按测试名称选择内存模型的分支。
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class LitmusFixtureError(ValueError):
    """fixture 缺少绑定或关系引用不完整时抛出。"""


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class FixtureEventKind(StrEnum):
    """fixture 中允许描述的 x86 critical operation。"""

    LOAD = "Load"  # 普通 load 的稳定事件种类。
    STORE = "Store"  # 普通 store 的稳定事件种类。
    ATOMIC_RMW = "AtomicRMW"  # LOCK/XCHG 等不可拆分的读改写事件。
    LFENCE = "LFENCE"  # x86 读屏障指令。
    SFENCE = "SFENCE"  # x86 写屏障指令。
    MFENCE = "MFENCE"  # x86 读写屏障指令。


class HerdOutcome(StrEnum):
    """外部 herd 对一个 exists outcome 的结论。"""

    ALLOWED = "Allowed"  # 外部模型允许该 outcome。
    FORBIDDEN = "Forbidden"  # 外部模型禁止该 outcome。
    UNSUPPORTED = "Unsupported"  # 外部工具没有覆盖该输入或模型。


class RelationKind(StrEnum):
    PO = "po"  # 同一线程内的 program-order 关系。
    RF = "rf"  # load 从哪一个 store 读取。
    CO = "co"  # 同一对象上的写入 coherence 顺序。
    FR = "fr"  # load 到后续 coherence 写入的 from-read 关系。


def _sha256(value: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
    return value


def _relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError("corpus paths must be non-empty relative POSIX paths")
    return value


class BinaryBinding(_StrictModel):
    """把 case 绑定到生成源、ELF 和可复现构建输入。"""

    source_litmus: str = Field(description="仓库内原始 .litmus 文件的相对路径")
    source_sha256: str = Field(description="原始 .litmus 文件的 SHA-256")
    elf_relative_path: str = Field(description="对应 x86-64 ELF 的相对路径")
    elf_sha256: str = Field(description="真实 ELF 文件的 SHA-256")
    corpus_revision: str = Field(description="生成该 ELF 的 corpus 版本")
    build_recipe: str = Field(description="可复现生成 ELF 的命令摘要")

    @model_validator(mode="after")
    def validate_binding(self) -> "BinaryBinding":
        _relative_path(self.source_litmus)
        _relative_path(self.elf_relative_path)
        _sha256(self.source_sha256)
        _sha256(self.elf_sha256)
        if not self.corpus_revision:
            raise ValueError("corpus_revision must be non-empty")
        if not self.build_recipe:
            raise ValueError("build_recipe must be non-empty")
        return self


class CriticalEvent(_StrictModel):
    """预期从真实 ELF 恢复的 critical instruction，仅用于 conformance。"""

    label: str = Field(description="fixture 内稳定且唯一的事件标签")
    thread: int = Field(description="事件所属的 litmus 线程编号")
    ordinal: int = Field(description="该线程内 critical event 的顺序号")
    kind: FixtureEventKind = Field(description="x86 critical operation 种类")
    object_label: str | None = Field(default=None, description="事件访问的抽象对象标签")
    width: int | None = Field(default=None, description="访存宽度，单位为字节")
    instruction_pc: int | None = Field(default=None, description="ELF 中指令 PC")
    operand_index: int | None = Field(default=None, description="指令内 memory operand 编号")
    thread_entry_pc: int | None = Field(
        default=None,
        description="该线程入口在 ELF 中的 PC；用于跨恢复报告稳定绑定线程角色",
    )

    @model_validator(mode="after")
    def validate_event(self) -> "CriticalEvent":
        if not self.label:
            raise ValueError("critical event label must be non-empty")
        if self.thread < 0 or self.ordinal < 0:
            raise ValueError("thread and ordinal must be non-negative")
        if self.kind in {
            FixtureEventKind.LOAD,
            FixtureEventKind.STORE,
            FixtureEventKind.ATOMIC_RMW,
        }:
            if self.width not in {1, 2, 4, 8}:
                raise ValueError("memory critical events need a 1/2/4/8-byte width")
            if self.object_label is None or not self.object_label:
                raise ValueError("memory critical events need an object label")
        elif self.width is not None or self.object_label is not None:
            raise ValueError("fence critical events cannot carry memory object fields")
        if self.instruction_pc is not None and self.instruction_pc < 0:
            raise ValueError("instruction_pc must be non-negative")
        if self.operand_index is not None and self.operand_index < 0:
            raise ValueError("operand_index must be non-negative")
        if self.thread_entry_pc is not None and self.thread_entry_pc < 0:
            raise ValueError("thread_entry_pc must be non-negative")
        return self


class ProgramOrderEdge(_StrictModel):
    """一个 thread 内 critical event 的 source program-order 边。"""

    source: str = Field(description="边的起始事件标签")
    target: str = Field(description="边的结束事件标签")
    relation: RelationKind = Field(default=RelationKind.PO)

    @model_validator(mode="after")
    def validate_kind(self) -> "ProgramOrderEdge":
        if self.relation != RelationKind.PO:
            raise ValueError("program_order entries must use relation 'po'")
        if not self.source or not self.target or self.source == self.target:
            raise ValueError("program-order edges need two distinct event labels")
        return self


class ReadFromChoice(_StrictModel):
    """一个 load 的 rf 选择；None 表示初始写。"""

    load: str = Field(description="被赋值的 load 事件标签")
    store: str | None = Field(default=None, description="提供值的 store 标签，空值表示初始写")
    relation: RelationKind = Field(default=RelationKind.RF)

    @model_validator(mode="after")
    def validate_kind(self) -> "ReadFromChoice":
        if self.relation != RelationKind.RF:
            raise ValueError("read_from entries must use relation 'rf'")
        if not self.load:
            raise ValueError("read-from load label must be non-empty")
        if self.store == self.load:
            raise ValueError("a load cannot read from itself")
        return self


class CoherencePair(_StrictModel):
    """一个 object 上的 coherence 方向。"""

    object_label: str = Field(description="coherence 所属的抽象对象")
    before: str = Field(description="coherence 中较早的写事件")
    after: str = Field(description="coherence 中较晚的写事件")
    relation: RelationKind = Field(default=RelationKind.CO)

    @model_validator(mode="after")
    def validate_kind(self) -> "CoherencePair":
        if self.relation != RelationKind.CO:
            raise ValueError("coherence entries must use relation 'co'")
        if not self.object_label or not self.before or not self.after:
            raise ValueError("coherence entries need object and event labels")
        if self.before == self.after:
            raise ValueError("coherence cannot relate an event to itself")
        return self


class FromReadEdge(_StrictModel):
    """显式记录某个 load 与后续 coherence 写之间的 fr 边。"""

    source: str = Field(description="fr 起始的 load 事件")
    target: str = Field(description="fr 终止的后续写事件")
    object_label: str = Field(description="fr 所属的抽象对象")
    relation: RelationKind = Field(default=RelationKind.FR)

    @model_validator(mode="after")
    def validate_kind(self) -> "FromReadEdge":
        if self.relation != RelationKind.FR:
            raise ValueError("from_read entries must use relation 'fr'")
        if not self.source or not self.target or not self.object_label:
            raise ValueError("from-read edges need object and event labels")
        if self.source == self.target:
            raise ValueError("from-read cannot relate an event to itself")
        return self


class ExecutionAssignment(_StrictModel):
    """一个待分别送入 source/target legality facade 的关系赋值。"""

    assignment_id: str = Field(description="该关系赋值的稳定标识")
    read_from: tuple[ReadFromChoice, ...] = Field(default=(), description="该执行的 rf 选择")
    coherence: tuple[CoherencePair, ...] = Field(default=(), description="该执行的 co 方向")
    from_read: tuple[FromReadEdge, ...] = Field(default=(), description="该执行的 fr 边")

    @model_validator(mode="after")
    def validate_id(self) -> "ExecutionAssignment":
        if not self.assignment_id:
            raise ValueError("assignment_id must be non-empty")
        return self


class HerdOracleRecord(_StrictModel):
    """source 与 contract-lowered target 的独立 herd 结果。"""

    herd_version: str = Field(description="产生该记录的 herdtools7 版本")
    source_model: str = Field(description="source outcome 使用的 herd 模型")
    target_model: str = Field(description="contract lowering 后 target 使用的模型")
    outcome: str | None = Field(
        default=None,
        description="原始 litmus 的 exists/final-state 谓词，供报告解释",
    )
    source_outcome: HerdOutcome = Field(description="source 模型对 outcome 的判断")
    target_outcome: HerdOutcome = Field(description="target 模型对 outcome 的判断")
    source_input_sha256: str = Field(description="source herd 输入的 SHA-256")
    target_input_sha256: str = Field(description="target herd 输入的 SHA-256")
    elf_sha256: str = Field(description="该 oracle 绑定的原始 ELF SHA-256")
    contract_version: str = Field(description="DBT lowering contract 版本")
    contract_sha256: str = Field(description="DBT lowering contract 的 SHA-256")
    raw_output_sha256: str = Field(description="herd 原始输出的 SHA-256")

    @model_validator(mode="after")
    def validate_oracle(self) -> "HerdOracleRecord":
        if not self.herd_version or not self.source_model or not self.target_model:
            raise ValueError("herd version and model names must be non-empty")
        if self.outcome is not None and not self.outcome:
            raise ValueError("oracle outcome must be non-empty when present")
        if not self.contract_version:
            raise ValueError("contract_version must be non-empty")
        for value in (
            self.source_input_sha256,
            self.target_input_sha256,
            self.elf_sha256,
            self.contract_sha256,
            self.raw_output_sha256,
        ):
            _sha256(value)
        return self


class LitmusCase(_StrictModel):
    """一个真实 ELF case 的 source/critical relation/oracle 绑定。"""

    case_id: str
    binding: BinaryBinding
    critical_events: tuple[CriticalEvent, ...]
    program_order: tuple[ProgramOrderEdge, ...]
    executions: tuple[ExecutionAssignment, ...]
    oracle: HerdOracleRecord

    @model_validator(mode="after")
    def validate_relations(self) -> "LitmusCase":
        if not self.case_id:
            raise ValueError("case_id must be non-empty")
        labels = [event.label for event in self.critical_events]
        if len(labels) != len(set(labels)):
            raise ValueError("critical event labels must be unique")
        known = set(labels)
        for edge in self.program_order:
            if edge.source not in known or edge.target not in known:
                raise ValueError("program-order edge references an unknown event")
        for assignment in self.executions:
            for choice in assignment.read_from:
                if choice.load not in known or (
                    choice.store is not None and choice.store not in known
                ):
                    raise ValueError("read-from choice references an unknown event")
            for pair in assignment.coherence:
                if pair.before not in known or pair.after not in known:
                    raise ValueError("coherence pair references an unknown event")
            for edge in assignment.from_read:
                if edge.source not in known or edge.target not in known:
                    raise ValueError("from-read edge references an unknown event")
        if not self.executions:
            raise ValueError("a litmus case needs at least one execution assignment")
        if self.oracle.source_input_sha256 != self.binding.source_sha256:
            raise ValueError("source oracle hash does not match the case binding")
        if self.oracle.elf_sha256 != self.binding.elf_sha256:
            raise ValueError("oracle ELF hash does not match the case binding")
        return self


class LitmusManifest(_StrictModel):
    """版本化 E2.5 manifest；case ID 只用于 evaluation 展示。"""

    schema_version: int = Field(alias="schema", description="manifest wire schema 版本")
    corpus_name: str = Field(description="该 fixture corpus 的稳定名称")
    corpus_revision: str = Field(description="该 corpus 的版本标识")
    cases: tuple[LitmusCase, ...] = Field(description="纳入回归的 litmus case")

    @model_validator(mode="after")
    def validate_manifest(self) -> "LitmusManifest":
        if self.schema_version < 1:
            raise ValueError("schema must be positive")
        if not self.corpus_name or not self.corpus_revision:
            raise ValueError("corpus_name and corpus_revision must be non-empty")
        ids = [case.case_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("case_id values must be unique")
        if any(case.binding.corpus_revision != self.corpus_revision for case in self.cases):
            raise ValueError("case bindings must use the manifest corpus revision")
        return self


def load_manifest(path: Any) -> LitmusManifest:
    """在 evaluation 边界一次性读取并严格校验 manifest。"""

    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        return LitmusManifest.model_validate(payload)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as error:
        raise LitmusFixtureError(f"invalid litmus manifest {path}: {error}") from error


__all__ = [
    "BinaryBinding",
    "CoherencePair",
    "CriticalEvent",
    "ExecutionAssignment",
    "FixtureEventKind",
    "FromReadEdge",
    "HerdOutcome",
    "HerdOracleRecord",
    "LitmusCase",
    "LitmusFixtureError",
    "LitmusManifest",
    "ProgramOrderEdge",
    "ReadFromChoice",
    "RelationKind",
    "load_manifest",
]
