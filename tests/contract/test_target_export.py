from __future__ import annotations

from pathlib import Path

import pytest

from bmo_check_core.contracts import MemoryOrderContract
from bmo_check_evaluation.litmus import TargetExportError, export_contract_target, load_manifest


def _contract() -> MemoryOrderContract:
    from bmo_check_static.config import load_canonical_contract

    result = load_canonical_contract(
        Path(__file__).resolve().parents[2] / "specs" / "static" / "dbt6-mo-off.yaml"
    )
    assert result.canonical is not None
    return result.canonical


def test_target_export_maps_plain_operations_and_fence_through_contract() -> None:
    manifest = load_manifest(
        Path(__file__).resolve().parents[2] / "specs" / "litmus" / "e2-5-representative.yaml"
    )
    text = export_contract_target(
        next(case for case in manifest.cases if case.case_id == "MP+mfence+po"),
        _contract(),
    )

    assert text.startswith("RISCV MP_mfence_po\n")
    assert "sd x5,0(x6)" in text
    assert "fence rw,rw" in text
    assert "ld x10,0(x6)" in text or "ld x10,0(x7)" in text
    assert "exists (1:rax=1 /\\ 1:rbx=0)" in text


def test_target_export_rejects_noncanonical_contract() -> None:
    manifest = load_manifest(
        Path(__file__).resolve().parents[2] / "specs" / "litmus" / "e2-5-representative.yaml"
    )
    contract = _contract()
    from dataclasses import replace
    from bmo_check_core.contracts import TargetOrdering

    bad = replace(
        contract,
        translation=replace(contract.translation, plain_load=TargetOrdering.ACQUIRE),
    )
    with pytest.raises(TargetExportError):
        export_contract_target(manifest.cases[0], bad)
