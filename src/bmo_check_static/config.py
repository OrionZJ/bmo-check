from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from bmo_check_core import ContractError, MemoryOrderContract

from bmo_check_static.model import UnknownFact, UnknownKind


@dataclass(frozen=True)
class ContractLoadResult:
    version: str
    # canonical 只有完整 YAML 通过字段校验后才存在；旧入口仍可只读取版本。
    canonical: MemoryOrderContract | None = None
    # sha256 把实际送入 checker 的 contract 内容绑定到结果。
    sha256: str | None = None
    unknown: UnknownFact | None = None


@dataclass(frozen=True)
class FunctionEffectContract:
    # version 让报告说明使用了哪版外部函数 effect 约束。
    version: str
    # sha256 把证书绑定到完整 YAML，防止同版本内容被静默替换。
    sha256: str
    # effects 只保存通过校验的 symbol -> effect 映射。
    effects: dict[str, str]
    # integer_arguments 列出函数实际读取的 SysV 整数参数位置；空元组表示纯标量浮点 ABI。
    integer_arguments: dict[str, tuple[int, ...]]
    # memory_arguments 列出已知会被函数访问的指针参数和方向。
    # 只为参数地址可恢复时生成普通 MemoryEvent；缺失地址仍保留 Unknown。
    memory_arguments: dict[str, tuple[tuple[int, str], ...]]
    # internal_objects 只给 runtime 自己的封装状态命名。
    # 调用仍保留 Unknown，但它不再假定能改写任意应用数组。
    internal_objects: dict[str, str]
    # preserve_heap_fields 列出经过机器码审计、不会改写调用者指针字段的
    # helper。它只允许地址传播跨过调用，不会把 helper 的其他内存访问
    # 从 MemoryEvent 中删除。
    preserve_heap_fields: frozenset[str]
    # unknown 非空时调用方必须停止使用 effects，并传播配置错误。
    unknown: UnknownFact | None = None


def load_contract_version(path: Path) -> ContractLoadResult:
    try:
        payload: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("contract root must be a mapping")
        version = payload.get("contract_version")
        if not isinstance(version, str) or not version:
            raise ValueError("contract_version must be a non-empty string")
        canonical, _ = _parse_canonical_contract(payload)
        return ContractLoadResult(
            version=version,
            canonical=canonical,
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    except (OSError, ValueError, yaml.YAMLError) as error:
        return ContractLoadResult(
            version="unknown",
            unknown=UnknownFact(
                kind=UnknownKind.INVALID_DBT_CONTRACT,
                reason=f"cannot load DBT contract {path}: {error}",
                impact="binary facts cannot be bound to one DBT lowering contract",
                module=str(path),
            ),
        )


def _mapping(payload: Any, field: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError(f"{field} must be a mapping")
    return payload


def _text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _parse_canonical_contract(
    payload: dict[str, Any],
) -> tuple[MemoryOrderContract | None, str | None]:
    """把静态 contract 的 wire 结构交给 core，而不是只信版本字符串。"""

    try:
        schema = payload.get("schema")
        if not isinstance(schema, int) or isinstance(schema, bool):
            raise ValueError("schema must be an integer")
        version = _text(payload, "contract_version")
        guest = _mapping(payload.get("guest"), "guest")
        host = _mapping(payload.get("host"), "host")
        translation = _mapping(payload.get("translation"), "translation")
        guest_arch = _text(guest, "arch")
        guest_model = _text(guest, "memory_model")
        host_arch = _text(host, "arch")
        host_model = _text(host, "memory_model")

        def nested_text(name: str, key: str) -> str:
            return _text(_mapping(translation.get(name), f"translation.{name}"), key)

        canonical = MemoryOrderContract.from_wire(
            schema_version=schema,
            contract_version=version,
            guest_arch=guest_arch,
            guest_memory_model=guest_model,
            host_arch=host_arch,
            host_memory_model=host_model,
            plain_load=nested_text("plain_load", "target_ordering"),
            plain_store=nested_text("plain_store", "target_ordering"),
            lock_rmw=nested_text("lock_rmw", "target_ordering"),
            memory_xchg=nested_text("memory_xchg", "target_ordering"),
            lfence=nested_text("lfence", "target_fence"),
            sfence=nested_text("sfence", "target_fence"),
            mfence=nested_text("mfence", "target_fence"),
            syscall=(
                _text(_mapping(translation["syscall"], "translation.syscall"), "target_ordering")
                if "syscall" in translation
                else "unknown"
            ),
        )
        issue = canonical.unsupported_field()
        if issue is not None:
            return canonical, issue.render()
        return canonical, None
    except (ContractError, ValueError, TypeError, KeyError) as error:
        return None, str(error)


def load_canonical_contract(path: Path) -> ContractLoadResult:
    """严格读取供 E2.5 使用的 static DBT lowering contract。"""

    try:
        raw = path.read_bytes()
        payload: Any = yaml.safe_load(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("contract root must be a mapping")
        version = payload.get("contract_version")
        if not isinstance(version, str) or not version:
            raise ValueError("contract_version must be a non-empty string")
        canonical, error = _parse_canonical_contract(payload)
        if error is not None:
            return ContractLoadResult(
                version=version,
                canonical=canonical,
                sha256=hashlib.sha256(raw).hexdigest(),
                unknown=UnknownFact(
                    kind=UnknownKind.INVALID_DBT_CONTRACT,
                    reason=f"cannot load canonical DBT contract {path}: {error}",
                    impact=(
                        "E2.5 execution legality cannot bind to one DBT lowering contract"
                    ),
                    module=str(path),
                ),
            )
        return ContractLoadResult(
            version=version,
            canonical=canonical,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        return ContractLoadResult(
            version="unknown",
            unknown=UnknownFact(
                kind=UnknownKind.INVALID_DBT_CONTRACT,
                reason=f"cannot load canonical DBT contract {path}: {error}",
                impact="E2.5 execution legality cannot bind to one DBT lowering contract",
                module=str(path),
            ),
        )


def load_function_effect_contract(path: Path) -> FunctionEffectContract:
    try:
        raw = path.read_bytes()
        payload: Any = yaml.safe_load(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("contract root must be a mapping")
        version = payload.get("contract_version")
        if not isinstance(version, str) or not version:
            raise ValueError("contract_version must be a non-empty string")
        entries = payload.get("functions", {})
        if not isinstance(entries, dict):
            raise ValueError("functions must be a mapping")
        effects: dict[str, str] = {}
        integer_arguments: dict[str, tuple[int, ...]] = {}
        memory_arguments: dict[str, tuple[tuple[int, str], ...]] = {}
        internal_objects: dict[str, str] = {}
        preserve_heap_fields: set[str] = set()
        for symbol, entry in entries.items():
            if not isinstance(symbol, str) or not isinstance(entry, dict):
                raise ValueError("each function entry must be a symbol mapping")
            effect = entry.get("effect")
            if effect not in {
                "thread_local",
                "fresh_allocation",
                "runtime_internal",
                "argument_access",
                "field_preserving",
            }:
                raise ValueError(f"unsupported effect for {symbol!r}: {effect!r}")
            effects[symbol] = str(effect)
            if entry.get("preserve_heap_fields", False) is not False:
                if entry.get("preserve_heap_fields") is not True:
                    raise ValueError(
                        f"preserve_heap_fields must be boolean for {symbol!r}"
                    )
                if effect != "field_preserving":
                    raise ValueError(
                        f"preserve_heap_fields requires field_preserving for {symbol!r}"
                    )
                preserve_heap_fields.add(symbol)
            raw_arguments = entry.get("integer_arguments")
            if not isinstance(raw_arguments, list) or any(
                not isinstance(item, int) or not 0 <= item < 6 for item in raw_arguments
            ):
                raise ValueError(f"invalid integer_arguments for {symbol!r}")
            integer_arguments[symbol] = tuple(raw_arguments)
            raw_memory_arguments = entry.get("memory_arguments", [])
            if not isinstance(raw_memory_arguments, list):
                raise ValueError(f"invalid memory_arguments for {symbol!r}")
            parsed_memory_arguments: list[tuple[int, str]] = []
            for item in raw_memory_arguments:
                if not isinstance(item, dict):
                    raise ValueError(f"invalid memory argument for {symbol!r}")
                index = item.get("index")
                mode = item.get("mode")
                if (
                    not isinstance(index, int)
                    or not 0 <= index < 6
                    or index not in raw_arguments
                    or mode not in {"read", "write"}
                ):
                    raise ValueError(f"invalid memory argument for {symbol!r}")
                parsed_memory_arguments.append((index, str(mode)))
            if effect == "argument_access" and not parsed_memory_arguments:
                raise ValueError(
                    f"argument_access requires memory_arguments for {symbol!r}"
                )
            if effect != "argument_access" and parsed_memory_arguments:
                raise ValueError(
                    f"memory_arguments are only valid for argument_access: {symbol!r}"
                )
            memory_arguments[symbol] = tuple(parsed_memory_arguments)
            internal_object = entry.get("internal_object")
            if internal_object is not None:
                if not isinstance(internal_object, str) or not internal_object:
                    raise ValueError(f"invalid internal_object for {symbol!r}")
                if effect not in {
                    "fresh_allocation",
                    "runtime_internal",
                    "argument_access",
                }:
                    raise ValueError(
                        f"internal_object is not valid for effect {effect!r}"
                    )
                internal_objects[symbol] = internal_object
        return FunctionEffectContract(
            version=version,
            sha256=hashlib.sha256(raw).hexdigest(),
            effects=effects,
            integer_arguments=integer_arguments,
            memory_arguments=memory_arguments,
            internal_objects=internal_objects,
            preserve_heap_fields=frozenset(preserve_heap_fields),
        )
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        return FunctionEffectContract(
            version="unknown",
            sha256="",
            effects={},
            integer_arguments={},
            memory_arguments={},
            internal_objects={},
            preserve_heap_fields=frozenset(),
            unknown=UnknownFact(
                kind=UnknownKind.INVALID_FUNCTION_EFFECT_CONTRACT,
                reason=f"cannot load function effect contract {path}: {error}",
                impact="external calls cannot use semantic memory-effect summaries",
                module=str(path),
            ),
        )


__all__ = [
    "ContractLoadResult",
    "FunctionEffectContract",
    "load_canonical_contract",
    "load_contract_version",
    "load_function_effect_contract",
]
