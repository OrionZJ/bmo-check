from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from bmo_check.model import UnknownFact, UnknownKind


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
        for symbol, entry in entries.items():
            if not isinstance(symbol, str) or not isinstance(entry, dict):
                raise ValueError("each function entry must be a symbol mapping")
            effect = entry.get("effect")
            if effect not in {"thread_local"}:
                raise ValueError(f"unsupported effect for {symbol!r}: {effect!r}")
            effects[symbol] = str(effect)
        return FunctionEffectContract(
            version=version,
            sha256=hashlib.sha256(raw).hexdigest(),
            effects=effects,
        )
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        return FunctionEffectContract(
            version="unknown",
            sha256="",
            effects={},
            unknown=UnknownFact(
                kind=UnknownKind.INVALID_FUNCTION_EFFECT_CONTRACT,
                reason=f"cannot load function effect contract {path}: {error}",
                impact="external calls cannot use semantic memory-effect summaries",
                module=str(path),
            ),
        )
