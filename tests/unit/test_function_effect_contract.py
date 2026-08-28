from __future__ import annotations

from pathlib import Path

from bmo_check.config import load_function_effect_contract
from bmo_check.model import UnknownKind


def test_effect_contract_is_content_addressed() -> None:
    path = Path(__file__).parents[2] / "specs" / "library-effects.yaml"
    contract = load_function_effect_contract(path)

    assert contract.unknown is None
    assert contract.version == "linux-libm-thread-effects-v2"
    assert {
        name for name, effect in contract.effects.items() if effect == "thread_local"
    } == {"exp", "expf", "log", "logf", "sqrt", "sqrtf"}
    assert len(contract.sha256) == 64


def test_invalid_effect_contract_cannot_supply_summaries(tmp_path: Path) -> None:
    path = tmp_path / "invalid-effects.yaml"
    path.write_text(
        "contract_version: test\nfunctions:\n  helper:\n    effect: arbitrary\n",
        encoding="utf-8",
    )

    contract = load_function_effect_contract(path)

    assert not contract.effects
    assert contract.unknown is not None
    assert contract.unknown.kind == UnknownKind.INVALID_FUNCTION_EFFECT_CONTRACT
