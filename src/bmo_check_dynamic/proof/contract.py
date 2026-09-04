from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)


class _Arch(_Strict):
    arch: str
    memory_model: str


class _Ordering(_Strict):
    target_ordering: str


class _Fence(_Strict):
    target_fence: str


class _Translation(_Strict):
    plain_load: _Ordering
    plain_store: _Ordering
    lock_rmw: _Ordering
    memory_xchg: _Ordering
    lfence: _Fence
    sfence: _Fence
    mfence: _Fence


class DbtContract(_Strict):
    schema_version: int = Field(alias="schema")
    contract_version: str
    guest: _Arch
    host: _Arch
    translation: _Translation


def load_supported_contract(path: Path) -> tuple[DbtContract | None, str | None]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        contract = DbtContract.model_validate(payload)
    except (OSError, ValueError, yaml.YAMLError) as error:
        return None, f"invalid DBT contract: {error}"
    expected = {
        "guest": (contract.guest.arch, contract.guest.memory_model, "x86_64", "x86_tso"),
        "host": (contract.host.arch, contract.host.memory_model, "riscv64", "rvwmo"),
        "plain_load": (contract.translation.plain_load.target_ordering, "relaxed"),
        "plain_store": (contract.translation.plain_store.target_ordering, "relaxed"),
        "lock_rmw": (contract.translation.lock_rmw.target_ordering, "acq_rel"),
        "memory_xchg": (contract.translation.memory_xchg.target_ordering, "acq_rel"),
        "lfence": (contract.translation.lfence.target_fence, "r,r"),
        "sfence": (contract.translation.sfence.target_fence, "w,w"),
        "mfence": (contract.translation.mfence.target_fence, "rw,rw"),
    }
    for name, values in expected.items():
        if len(values) == 4:
            actual = values[:2]
            wanted = values[2:]
        else:
            actual = values[:1]
            wanted = values[1:]
        if actual != wanted:
            return contract, f"unsupported DBT contract field {name}: {actual} != {wanted}"
    return contract, None
