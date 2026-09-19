"""TraceStore 导入边界使用的 subject 和分层完整性契约。

这里不读取 DuckDB，也不决定 TRACE_SAFE。它只描述导入结果必须绑定哪些
稳定身份；缺少任一层时，调用者只能保留不完整状态，不能把空表解释成没有事件。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from .identity import TraceId


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty string without NUL")
    return value


class TraceImportState(StrEnum):
    """一次导入事务当前是否能够被后续 verifier 使用。"""

    # 仍在写入或核对层级，不能被分析器当作完整 trace。
    CREATING = "CREATING"
    # 所有必需层已对账，且 subject/config 都已固定。
    COMPLETE = "COMPLETE"
    # 导入遇到错误；保留原因，禁止复用为完整 store。
    FAILED = "FAILED"
    # 输入或中间层缺失；它与 FAILED 都不能生成确定 verdict。
    INCOMPLETE = "INCOMPLETE"


class TraceImportLayer(StrEnum):
    """导入账本必须分别核对的输入/派生层。"""

    MANIFEST = "manifest"
    RAW_CHUNK = "raw_chunk"
    DECODED_EVENT = "decoded_event"
    OBJECT_INVENTORY = "object_inventory"
    THREAD_INVENTORY = "thread_inventory"


_REQUIRED_LAYERS = frozenset(TraceImportLayer)


@dataclass(frozen=True, slots=True)
class TraceChunkRecord:
    """一个原始事件 chunk 的稳定摘要和解码计数。"""

    name: str
    sha256: str
    byte_count: int
    event_count: int

    def __post_init__(self) -> None:
        _text("chunk name", self.name)
        _digest("chunk sha256", self.sha256)
        if not isinstance(self.byte_count, int) or isinstance(self.byte_count, bool):
            raise ValueError("chunk byte_count must be an integer")
        if not isinstance(self.event_count, int) or isinstance(self.event_count, bool):
            raise ValueError("chunk event_count must be an integer")
        if self.byte_count < 0 or self.event_count < 0:
            raise ValueError("chunk counts cannot be negative")


@dataclass(frozen=True, slots=True)
class TraceLayerRecord:
    """一个导入层的数量/摘要对账记录。"""

    layer: TraceImportLayer
    count: int
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.layer, TraceImportLayer):
            raise ValueError("layer must be a TraceImportLayer")
        if not isinstance(self.count, int) or isinstance(self.count, bool) or self.count < 0:
            raise ValueError("layer count must be a non-negative integer")
        _digest("layer sha256", self.sha256)


@dataclass(frozen=True, slots=True)
class TraceImportLedger:
    """把一次 TraceStore 导入绑定到单一 subject 和完整层级账本。"""

    # subject 是 trace 内容/manifest 的稳定身份，不是数据库路径或当前进程。
    subject: TraceId
    # trace_digest 绑定原始 manifest、module 和 event chunk 的实际内容。
    trace_digest: str
    # schema/config 变化时必须拒绝复用旧 store，而不能静默追加事件。
    schema_version: str
    config_digest: str
    state: TraceImportState
    chunks: tuple[TraceChunkRecord, ...] = ()
    layers: tuple[TraceLayerRecord, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.subject, TraceId):
            raise ValueError("subject must be a TraceId")
        _digest("trace digest", self.trace_digest)
        _text("schema version", self.schema_version)
        _digest("config digest", self.config_digest)
        if not isinstance(self.state, TraceImportState):
            raise ValueError("state must be a TraceImportState")

        chunks = tuple(sorted(self.chunks, key=lambda item: item.name))
        if any(not isinstance(item, TraceChunkRecord) for item in chunks):
            raise ValueError("chunks must contain TraceChunkRecord values")
        if len({item.name for item in chunks}) != len(chunks):
            raise ValueError("chunks contain duplicate names")
        object.__setattr__(self, "chunks", chunks)

        layers = tuple(sorted(self.layers, key=lambda item: item.layer.value))
        if any(not isinstance(item, TraceLayerRecord) for item in layers):
            raise ValueError("layers must contain TraceLayerRecord values")
        layer_names = tuple(item.layer for item in layers)
        if len(set(layer_names)) != len(layer_names):
            raise ValueError("layers contain duplicate identities")
        object.__setattr__(self, "layers", layers)

        if self.state is TraceImportState.COMPLETE:
            if self.reason is not None:
                raise ValueError("complete import cannot carry a failure reason")
            if not chunks:
                raise ValueError("complete import requires at least one raw chunk")
            if set(layer_names) != _REQUIRED_LAYERS:
                raise ValueError("complete import must account for every required layer")
        elif self.state is TraceImportState.CREATING:
            if self.reason is not None:
                raise ValueError("creating import cannot carry a failure reason")
        elif not isinstance(self.reason, str) or not self.reason or "\x00" in self.reason:
            raise ValueError("failed or incomplete import requires a reason")

    @property
    def missing_layers(self) -> tuple[TraceImportLayer, ...]:
        """返回没有进入账本的层；非空时不能形成完整导入证明。"""

        present = {item.layer for item in self.layers}
        return tuple(layer for layer in TraceImportLayer if layer not in present)

    def matches(
        self,
        *,
        subject: TraceId,
        schema_version: str,
        config_digest: str,
    ) -> bool:
        """只有同一 subject、schema 和 config 才允许复用 store。"""

        return (
            self.state is TraceImportState.COMPLETE
            and self.subject == subject
            and self.schema_version == schema_version
            and self.config_digest == config_digest
        )


__all__ = [
    "TraceChunkRecord",
    "TraceImportLayer",
    "TraceImportLedger",
    "TraceImportState",
    "TraceLayerRecord",
]
