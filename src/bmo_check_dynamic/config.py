from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class DynamicConfig:
    """动态分析的资源边界；越界必须返回 UNKNOWN，不能丢事件后继续证明。"""

    max_window_events: int = 64
    max_executions: int = 20_000
    max_communication_edges: int = 100_000
    # 通信扫描按页维护活动集合；先检查最热页，避免排序前就占满内存。
    max_communication_active_events: int = 600_000
    # 对象 generation 的 UPDATE 会在 DuckDB 中建立地址范围连接；超过预算
    # 时直接返回 UNKNOWN，不能让一次分析把进程内存耗尽。
    max_object_events: int = 5_000_000
    max_pages_per_access: int = 16
    batch_size: int = 50_000
    solver_timeout_ms: int = 10_000
    # Z3 AST 主要占 Python 进程内存，不受 DuckDB memory_limit 约束。
    max_symbolic_terms: int = 100_000
    # 限制 DuckDB 缓存，防止大轨迹与 Python batch 一起耗尽系统内存。
    database_memory_limit_mb: int = 512
    database_path: Path | None = None
    # application_only 只证明主程序发出的普通访存；运行库访问必须由已知
    # LOCK/XCHG、Fence 和 pthread 契约承担，不能把这个结果写成库本身安全。
    application_only: bool = False

    def validate(self) -> None:
        values = (
            self.max_window_events,
            self.max_executions,
            self.max_communication_edges,
            self.max_communication_active_events,
            self.max_object_events,
            self.max_pages_per_access,
            self.batch_size,
            self.solver_timeout_ms,
            self.max_symbolic_terms,
            self.database_memory_limit_mb,
        )
        if any(value <= 0 for value in values):
            raise ValueError("dynamic analysis limits must be positive")


def semantic_config_digest(config: DynamicConfig) -> str:
    """摘要会影响分析结果的配置字段。

    database_path 只是落盘位置，不应让同一条 trace 在不同目录重放时
    得到不同的语义身份。其余字段都属于资源边界或作用域，必须绑定到
    certificate；否则用更宽的预算重放旧证书可能把 UNKNOWN 变成确定结论。
    """

    if not isinstance(config, DynamicConfig):
        raise TypeError("semantic_config_digest expects DynamicConfig")
    material = {
        field.name: (
            str(value) if isinstance(value, Path) else value
        )
        for field in config.__dataclass_fields__.values()
        if field.name != "database_path"
        for value in (getattr(config, field.name),)
    }
    return hashlib.sha256(
        json.dumps(
            material,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


__all__ = ["DynamicConfig", "semantic_config_digest"]
