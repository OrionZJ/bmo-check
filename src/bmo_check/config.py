from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from bmo_check.model import UnknownFact, UnknownKind


@dataclass(frozen=True)
class ContractLoadResult:
    version: str
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
