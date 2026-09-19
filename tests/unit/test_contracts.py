from __future__ import annotations

import pytest

from bmo_check_core import (
    ContractError,
    FenceOperation,
    LoweringOperation,
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


def test_contract_queries_keep_all_lowering_rules_on_one_typed_boundary() -> None:
    contract = _contract(syscall="unknown")

    assert contract.translation.ordering_for(LoweringOperation.PLAIN_LOAD) == (
        TargetOrdering.RELAXED
    )
    assert contract.translation.ordering_for(LoweringOperation.PLAIN_STORE) == (
        TargetOrdering.RELAXED
    )
    assert contract.translation.ordering_for(LoweringOperation.LOCK_RMW) == (
        TargetOrdering.ACQ_REL
    )
    assert contract.translation.ordering_for(LoweringOperation.MEMORY_XCHG) == (
        TargetOrdering.ACQ_REL
    )
    # 未描述 syscall 的 contract 不能被调用方猜成 acquire/release/full。
    assert contract.translation.ordering_for(LoweringOperation.SYSCALL) == (
        TargetOrdering.UNKNOWN
    )
    assert contract.translation.fence_for(FenceOperation.LFENCE) == TargetFence.RR
    assert contract.translation.fence_for(FenceOperation.SFENCE) == TargetFence.WW
    assert contract.translation.fence_for(FenceOperation.MFENCE) == TargetFence.RWRW


def test_contract_queries_reject_raw_names() -> None:
    contract = _contract()

    with pytest.raises(ContractError, match="LoweringOperation"):
        contract.translation.ordering_for("plain_load")  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="FenceOperation"):
        contract.translation.fence_for("mfence")  # type: ignore[arg-type]


def test_semantic_digest_binds_contract_content_not_yaml_formatting() -> None:
    contract = _contract()

    assert len(contract.semantic_digest()) == 64
    assert contract.semantic_digest() == _contract().semantic_digest()
    assert contract.semantic_digest() != _contract(contract_version="dbt6-mo-off-v3").semantic_digest()
    assert contract.semantic_digest() != _contract(syscall="full").semantic_digest()
