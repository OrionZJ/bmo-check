from __future__ import annotations

import pytest

from bmo_check_core import (
    ContractError,
    MemoryOrderContract,
    TargetFence,
    TargetOrdering,
    TranslationContract,
)


def _contract(**overrides):
    values = {
        "schema_version": 1,
        "contract_version": "dbt6-mo-off-v2",
        "guest_arch": "x86_64",
        "guest_memory_model": "x86_tso",
        "host_arch": "riscv64",
        "host_memory_model": "rvwmo",
        "plain_load": "relaxed",
        "plain_store": "relaxed",
        "lock_rmw": "acq_rel",
        "memory_xchg": "acq_rel",
        "lfence": "r,r",
        "sfence": "w,w",
        "mfence": "rw,rw",
    }
    values.update(overrides)
    return MemoryOrderContract.from_wire(**values)


def test_mo_off_contract_is_normalized_once() -> None:
    contract = _contract()

    assert contract.translation.plain_load == TargetOrdering.RELAXED
    assert contract.translation.lock_rmw == TargetOrdering.ACQ_REL
    assert contract.translation.mfence == TargetFence.RWRW
    assert contract.unsupported_field() is None


def test_contract_reports_canonical_field_for_unsupported_lowering() -> None:
    contract = _contract(plain_store="release")

    issue = contract.unsupported_field()
    assert issue is not None
    assert issue.field == "translation.plain_store"
    assert issue.render() == (
        "unsupported DBT contract field translation.plain_store: "
        "'release' != 'relaxed'"
    )


def test_unknown_wire_value_is_rejected_instead_of_becoming_relaxed() -> None:
    with pytest.raises(ContractError, match="translation.plain_load"):
        _contract(plain_load="future-mode")


def test_translation_contract_rejects_untyped_fields() -> None:
    with pytest.raises(ContractError, match="plain_load must be a TargetOrdering"):
        TranslationContract(
            plain_load="relaxed",  # type: ignore[arg-type]
            plain_store=TargetOrdering.RELAXED,
            lock_rmw=TargetOrdering.ACQ_REL,
            memory_xchg=TargetOrdering.ACQ_REL,
            lfence=TargetFence.RR,
            sfence=TargetFence.WW,
            mfence=TargetFence.RWRW,
        )
