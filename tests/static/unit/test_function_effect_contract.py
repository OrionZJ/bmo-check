from __future__ import annotations

from pathlib import Path

from bmo_check_static.config import load_function_effect_contract
from bmo_check_static.model import UnknownKind


def test_effect_contract_is_content_addressed() -> None:
    path = Path(__file__).parents[3] / "specs" / "static" / "library-effects.yaml"
    contract = load_function_effect_contract(path)

    assert contract.unknown is None
    assert contract.version == "linux-runtime-effects-v4"
    assert {
        name for name, effect in contract.effects.items() if effect == "thread_local"
    } == {
        "exp",
        "expf",
        "log",
        "logf",
        "sqrt",
        "sqrtf",
        "pow",
        "powf",
    }
    assert contract.effects["malloc"] == "fresh_allocation"
    assert contract.integer_arguments["malloc"] == (0,)
    assert contract.effects["free"] == "runtime_internal"
    assert contract.internal_objects["malloc"] == "runtime:allocator"
    assert contract.internal_objects["free"] == "runtime:allocator"
    assert contract.memory_arguments["memcpy"] == ((0, "write"), (1, "read"))
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
