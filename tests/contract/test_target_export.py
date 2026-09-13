from __future__ import annotations

from pathlib import Path

import pytest

from bmo_check_core.contracts import MemoryOrderContract
from bmo_check_evaluation.litmus import (
    FixtureEventKind,
    TargetExportError,
    export_contract_target,
    load_manifest,
)


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
    assert "exists (1:x10=1 /\\ 1:x11=0)" in text


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


def test_target_export_rejects_missing_store_value() -> None:
    manifest = load_manifest(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "litmus"
        / "e2-5-representative.yaml"
    )
    case = manifest.cases[0].model_copy(
        update={
            "critical_events": tuple(
                event.model_copy(update={"value": None})
                if event.kind.value == "Store"
                else event
                for event in manifest.cases[0].critical_events
            )
        }
    )
    with pytest.raises(TargetExportError):
        export_contract_target(case, _contract())


def test_target_export_rejects_underspecified_atomic_rmw() -> None:
    manifest = load_manifest(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "litmus"
        / "e2-5-representative.yaml"
    )
    case = manifest.cases[0].model_copy(
        update={
            "critical_events": tuple(
                event.model_copy(
                    update={
                        "kind": FixtureEventKind.ATOMIC_RMW,
                        "value": None,
                    }
                )
                if event.label == "p0-w-x"
                else event
                for event in manifest.cases[0].critical_events
            )
        }
    )
    with pytest.raises(TargetExportError, match="explicit operation/value"):
        export_contract_target(case, _contract())


@pytest.mark.parametrize(
    ("case_id", "condition"),
    [
        ("SB", "exists (0:x10=0 /\\ 1:x10=0)"),
        ("MP", "exists (1:x10=1 /\\ 1:x11=0)"),
        ("LB", "exists (0:x10=1 /\\ 1:x10=1)"),
        ("2+2W", "exists (x=2 /\\ y=2)"),
        ("CoWW", "exists (not (x=2))"),
        ("MP+mfence+po", "exists (1:x10=1 /\\ 1:x11=0)"),
    ],
)
def test_each_representative_target_condition_is_explicit(
    case_id: str, condition: str
) -> None:
    manifest = load_manifest(
        Path(__file__).resolve().parents[2]
        / "specs"
        / "litmus"
        / "e2-5-representative.yaml"
    )
    case = next(item for item in manifest.cases if item.case_id == case_id)
    text = export_contract_target(case, _contract())
    assert condition in text
    if case_id in {"2+2W", "CoWW"}:
        assert "addi x5,x0,2" in text
