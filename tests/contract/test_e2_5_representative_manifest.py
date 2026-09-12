from __future__ import annotations

from pathlib import Path

from bmo_check_evaluation.litmus import HerdOutcome, load_manifest


def test_representative_manifest_pins_real_elf_dimensions_without_vendoring_corpus() -> None:
    path = Path(__file__).resolve().parents[2] / "specs" / "litmus" / "e2-5-representative.yaml"
    manifest = load_manifest(path)

    assert manifest.corpus_name == "litmus-tests-x86"
    assert {case.case_id for case in manifest.cases} == {
        "SB",
        "MP",
        "LB",
        "2+2W",
        "CoWW",
        "MP+mfence+po",
    }
    assert all(case.binding.elf_relative_path.startswith("elf-tests/") for case in manifest.cases)
    assert all(
        case.oracle.source_outcome is HerdOutcome.UNSUPPORTED
        and case.oracle.target_outcome is HerdOutcome.UNSUPPORTED
        and case.oracle.herd_version == "not-run-local-herd"
        for case in manifest.cases
    )
    assert any(
        event.kind.value == "MFENCE"
        for case in manifest.cases
        for event in case.critical_events
    )
    assert any(
        any(pair.object_label == "x" for pair in execution.coherence)
        for case in manifest.cases
        for execution in case.executions
    )
