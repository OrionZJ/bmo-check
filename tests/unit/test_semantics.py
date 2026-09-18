from __future__ import annotations

import pytest

from bmo_check_core import SemanticPrimitive, SemanticPrimitiveRef


def test_primitive_reference_keeps_model_and_contract_identity() -> None:
    reference = SemanticPrimitiveRef(
        primitive=SemanticPrimitive.PPO,
        source_model="x86-tso",
        target_model="rvwmo",
        contract_version="dbt6-mo-off-v2",
    )

    assert reference.primitive is SemanticPrimitive.PPO
    assert reference.source_model == "x86-tso"
    assert reference.target_model == "rvwmo"
    assert reference.contract_version == "dbt6-mo-off-v2"
    assert reference != SemanticPrimitiveRef(
        primitive=SemanticPrimitive.PPO,
        source_model="x86-tso",
        target_model="rvwmo",
        contract_version="dbt6-mo-off-v3",
    )


@pytest.mark.parametrize("field", ["source_model", "target_model", "contract_version"])
def test_primitive_reference_rejects_missing_identity(field: str) -> None:
    values = {
        "primitive": SemanticPrimitive.READ_FROM,
        "source_model": "x86-tso",
        "target_model": "rvwmo",
        "contract_version": "dbt6-mo-off-v2",
    }
    values[field] = ""

    with pytest.raises(ValueError, match=field):
        SemanticPrimitiveRef(**values)
