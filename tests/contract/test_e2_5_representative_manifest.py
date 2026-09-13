from __future__ import annotations

from pathlib import Path

from bmo_check_evaluation.litmus import ExecutionLegality, HerdOutcome, load_manifest


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
        case.oracle.target_condition
        and all(
            event.value is not None
            for event in case.critical_events
            if event.kind.value == "Store"
        )
        for case in manifest.cases
    )
    expected_oracles = {
        "SB": (HerdOutcome.ALLOWED, HerdOutcome.ALLOWED),
        "MP": (HerdOutcome.FORBIDDEN, HerdOutcome.ALLOWED),
        "LB": (HerdOutcome.FORBIDDEN, HerdOutcome.ALLOWED),
        "2+2W": (HerdOutcome.FORBIDDEN, HerdOutcome.ALLOWED),
        "CoWW": (HerdOutcome.FORBIDDEN, HerdOutcome.FORBIDDEN),
        "MP+mfence+po": (HerdOutcome.FORBIDDEN, HerdOutcome.ALLOWED),
    }
    assert all(
        (case.oracle.source_outcome, case.oracle.target_outcome)
        == expected_oracles[case.case_id]
        and case.oracle.source_model == "x86tso-mixed.cat"
        and case.oracle.target_model == "riscv.cat"
        and case.oracle.herd_version == "7.58, Rev: exported"
        and not case.oracle.target_input_sha256.startswith("a")
        and not case.oracle.raw_output_sha256.startswith("a")
        for case in manifest.cases
    )
    assert all(
        assignment.expected_source is not None
        for case in manifest.cases
        for assignment in case.executions
    )
    assert any(
        assignment.expected_target is None
        for case in manifest.cases
        for assignment in case.executions
    )
    assert next(
        case for case in manifest.cases if case.case_id == "MP"
    ).executions[0].expected_target is ExecutionLegality.ALLOWED
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
