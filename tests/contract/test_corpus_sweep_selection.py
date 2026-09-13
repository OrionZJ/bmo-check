from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


_SCRIPT = Path(__file__).parents[2] / "scripts" / "run_e2_5_corpus_sweep.py"
_SPEC = importlib.util.spec_from_file_location("e2_5_sweep", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)
CorpusCase = _MODULE.CorpusCase
select_cases = _MODULE.select_cases


def _cases(count: int) -> tuple[CorpusCase, ...]:
    return tuple(
        CorpusCase(
            source=Path(f"source-{index}.litmus"),
            elf=Path(f"elf-{index}.exe"),
            source_relative=f"source-{index}.litmus",
            elf_relative=f"elf-{index}.exe",
        )
        for index in range(count)
    )


def test_sample_selection_is_stable_and_preserves_corpus_order() -> None:
    cases = _cases(20)

    first = select_cases(cases, sample_size=6, sample_seed=20260913)
    second = select_cases(cases, sample_size=6, sample_seed=20260913)

    assert first == second
    assert tuple(case for case in cases if case in first) == first


def test_sample_selection_rejects_empty_or_oversized_sample() -> None:
    cases = _cases(3)

    with pytest.raises(ValueError):
        select_cases(cases, sample_size=0)
    with pytest.raises(ValueError):
        select_cases(cases, sample_size=4)
