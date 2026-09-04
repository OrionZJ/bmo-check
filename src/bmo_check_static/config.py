from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from bmo_check_static.model import UnknownFact, UnknownKind


@dataclass(frozen=True)
class ContractLoadResult:
    version: str
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
    # internal_objects 只给 runtime 自己的封装状态命名。
    # 调用仍保留 Unknown，但它不再假定能改写任意应用数组。
    internal_objects: dict[str, str]
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
        return ContractLoadResult(version=version)
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
        internal_objects: dict[str, str] = {}
        for symbol, entry in entries.items():
            if not isinstance(symbol, str) or not isinstance(entry, dict):
                raise ValueError("each function entry must be a symbol mapping")
            effect = entry.get("effect")
            if effect not in {
                "thread_local",
                "fresh_allocation",
                "runtime_internal",
            }:
                raise ValueError(f"unsupported effect for {symbol!r}: {effect!r}")
            effects[symbol] = str(effect)
            raw_arguments = entry.get("integer_arguments")
            if not isinstance(raw_arguments, list) or any(
                not isinstance(item, int) or not 0 <= item < 6 for item in raw_arguments
            ):
                raise ValueError(f"invalid integer_arguments for {symbol!r}")
            integer_arguments[symbol] = tuple(raw_arguments)
            internal_object = entry.get("internal_object")
            if internal_object is not None:
                if not isinstance(internal_object, str) or not internal_object:
                    raise ValueError(f"invalid internal_object for {symbol!r}")
                if effect not in {"fresh_allocation", "runtime_internal"}:
                    raise ValueError(
                        f"internal_object is not valid for effect {effect!r}"
                    )
                internal_objects[symbol] = internal_object
        return FunctionEffectContract(
            version=version,
            sha256=hashlib.sha256(raw).hexdigest(),
            effects=effects,
            integer_arguments=integer_arguments,
            internal_objects=internal_objects,
        )
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        return FunctionEffectContract(
            version="unknown",
            sha256="",
            effects={},
            integer_arguments={},
            internal_objects={},
            unknown=UnknownFact(
                kind=UnknownKind.INVALID_FUNCTION_EFFECT_CONTRACT,
                reason=f"cannot load function effect contract {path}: {error}",
                impact="external calls cannot use semantic memory-effect summaries",
                module=str(path),
            ),
        )
