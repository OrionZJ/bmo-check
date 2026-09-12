from __future__ import annotations

from pathlib import Path

from bmo_check_core import TargetFence, TargetOrdering
from bmo_check_static.config import load_canonical_contract, load_contract_version


ROOT = Path(__file__).resolve().parents[2]


def test_static_loader_binds_all_mo_off_fields_to_core_contract() -> None:
    path = ROOT / "specs" / "static" / "dbt6-mo-off.yaml"
    result = load_canonical_contract(path)

    assert result.unknown is None
    assert result.canonical is not None
    assert result.canonical.translation.plain_load is TargetOrdering.RELAXED
    assert result.canonical.translation.lock_rmw is TargetOrdering.ACQ_REL
    assert result.canonical.translation.mfence is TargetFence.RWRW
    assert result.sha256


def test_legacy_version_reader_does_not_hide_full_contract_binding() -> None:
    path = ROOT / "specs" / "static" / "dbt6-mo-off.yaml"
    result = load_contract_version(path)

    assert result.version == "dbt6-mo-off-v2"
    assert result.canonical is not None
    assert result.unknown is None


def test_canonical_loader_rejects_changed_lowering_instead_of_relaxing(
    tmp_path: Path,
) -> None:
    source = (ROOT / "specs" / "static" / "dbt6-mo-off.yaml").read_text(
        encoding="utf-8"
    )
    path = tmp_path / "contract.yaml"
    path.write_text(
        source.replace(
            "plain_store:\n    target_ordering: relaxed",
            "plain_store:\n    target_ordering: release",
        ),
        encoding="utf-8",
    )

    result = load_canonical_contract(path)

    assert result.canonical is not None
    assert result.unknown is not None
    assert "translation.plain_store" in result.unknown.reason


def test_legacy_minimal_contract_remains_compatible_but_has_no_canonical_model(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.yaml"
    path.write_text("schema: 1\ncontract_version: test-v1\n", encoding="utf-8")

    legacy = load_contract_version(path)
    strict = load_canonical_contract(path)

    assert legacy.version == "test-v1"
    assert legacy.unknown is None
    assert legacy.canonical is None
    assert strict.unknown is not None
