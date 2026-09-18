from __future__ import annotations

from pathlib import Path

import yaml
from bmo_check_core import ContractError, MemoryOrderContract
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
    # syscall ordering 必须显式出现在 immutable contract；缺失时保持 unknown。
    syscall: _Ordering | None = None


class DbtContract(_Strict):
    schema_version: int = Field(alias="schema")
    contract_version: str
    guest: _Arch
    host: _Arch
    translation: _Translation


def to_core_contract(contract: DbtContract) -> MemoryOrderContract:
    """把动态 YAML 模型转换成唯一的 canonical contract 解释。"""

    translation = contract.translation
    try:
        return MemoryOrderContract.from_wire(
            schema_version=contract.schema_version,
            contract_version=contract.contract_version,
            guest_arch=contract.guest.arch,
            guest_memory_model=contract.guest.memory_model,
            host_arch=contract.host.arch,
            host_memory_model=contract.host.memory_model,
            plain_load=translation.plain_load.target_ordering,
            plain_store=translation.plain_store.target_ordering,
            lock_rmw=translation.lock_rmw.target_ordering,
            memory_xchg=translation.memory_xchg.target_ordering,
            lfence=translation.lfence.target_fence,
            sfence=translation.sfence.target_fence,
            mfence=translation.mfence.target_fence,
            syscall=getattr(
                getattr(translation, "syscall", None),
                "target_ordering",
                "unknown",
            ),
        )
    except (AttributeError, ContractError) as error:
        raise ContractError(f"invalid DBT contract shape: {error}") from error


def load_supported_contract(path: Path) -> tuple[DbtContract | None, str | None]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        contract = DbtContract.model_validate(payload)
    except (OSError, ValueError, yaml.YAMLError) as error:
        return None, f"invalid DBT contract: {error}"
    try:
        canonical = to_core_contract(contract)
    except ContractError as error:
        return contract, str(error)
    issue = canonical.unsupported_field()
    if issue is not None:
        return contract, issue.render()
    return contract, None
