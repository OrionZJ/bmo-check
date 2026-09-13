from __future__ import annotations

import os
from pathlib import Path

import pytest

from bmo_check_evaluation.litmus.conformance import ConformanceStatus
from bmo_check_evaluation.litmus.service import (
    LitmusConformanceRequest,
    run_litmus_conformance,
)
from bmo_check_evaluation.litmus.model import load_manifest


pytestmark = pytest.mark.litmus_elf


def _corpus_root(request: pytest.FixtureRequest) -> Path:
    configured = request.config.getoption("--litmus-elf-root") or os.environ.get(
        "BMO_CHECK_LITMUS_ROOT"
    )
    if not configured:
        if request.config.getoption("--require-litmus-elf"):
            pytest.fail(
                "the litmus ELF profile requires --litmus-elf-root or "
                "BMO_CHECK_LITMUS_ROOT"
            )
        pytest.skip(
            "opt-in real ELF profile; pass --litmus-elf-root to run it"
        )
    root = Path(configured)
    if not root.is_dir():
        pytest.fail(f"litmus ELF corpus root does not exist: {root}")
    return root


def test_representative_real_elves_enter_normal_static_pipeline(
    request: pytest.FixtureRequest,
) -> None:
    corpus_root = _corpus_root(request)
    repository = Path(__file__).resolve().parents[3]
    manifest_path = repository / "specs" / "litmus" / "e2-5-representative.yaml"
    contract = repository / "specs" / "static" / "dbt6-mo-off.yaml"
    pthread_spec = repository / "specs" / "static" / "pthread-api.yaml"
    function_effects = repository / "specs" / "static" / "library-effects.yaml"
    library_roots = tuple(
        Path(value)
        for value in request.config.getoption("--litmus-library-root")
    )

    manifest = load_manifest(manifest_path)
    report = run_litmus_conformance(
        LitmusConformanceRequest(
            manifest=manifest_path,
            corpus_root=corpus_root,
            dbt_contract=contract,
            pthread_spec=pthread_spec,
            function_effects=function_effects,
            library_roots=library_roots,
            scope="application",
            provenance_instruction_limit=256,
        )
    )

    assert report.corpus_revision == manifest.corpus_revision
    assert {case.case_id for case in report.cases} == {
        case.case_id for case in manifest.cases
    }
    assert any(
        case.conformance is not None and case.conformance.extra_event_count > 0
        for case in report.cases
    )
    for case in report.cases:
        assert case.conformance is not None, case.errors
        assert case.static_verdict in {"SAFE", "COUNTEREXAMPLE", "UNKNOWN"}
        assert case.static_checker_conclusion
        conformance = case.conformance
        # 关键 PC/线程/程序序必须能单独对齐；对象缺口可以让最终 case
        # 保持 UNKNOWN，但不能阻止我们检查底层 fixed execution。
        assert conformance.critical_events_aligned, conformance.reasons
        assert not conformance.missing_labels
        assert not conformance.ambiguous_labels
        assert not conformance.ordering_errors
        assert len(case.executions) == len(
            next(item for item in manifest.cases if item.case_id == case.case_id).executions
        )
        assert all(
            execution.source_status in {"allowed", "forbidden"}
            and execution.target_status in {"allowed", "forbidden"}
            for execution in case.executions
        ), case.errors
    # 对象/生命周期 Unknown 仍然必须影响 conformance 总状态，不能被下层
    # legality 记录冒充为整个真实 ELF 已经 proof-complete。
    if any(case.errors for case in report.cases):
        assert report.status is ConformanceStatus.UNKNOWN
