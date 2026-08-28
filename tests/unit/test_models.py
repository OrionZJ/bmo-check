from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from bmo_check.model import (
    AnalysisCoverage,
    CertificateScope,
    CodeLocation,
    ExecutionScope,
    FingerprintReport,
    IndirectTargetSet,
    ProgramManifest,
    UnknownFact,
    UnknownKind,
    Verdict,
)


def test_unknown_fact_round_trip() -> None:
    fact = UnknownFact(
        kind=UnknownKind.MISSING_LIBRARY,
        module="app",
        pc=0x401000,
        reason="libmissing.so was not found",
        impact="dependency closure is incomplete",
    )
    assert UnknownFact.model_validate_json(fact.model_dump_json()) == fact


def test_incomplete_target_set_requires_reason() -> None:
    with pytest.raises(ValidationError):
        IndirectTargetSet(complete=False)

    target_set = IndirectTargetSet(
        known_targets=(
            CodeLocation(
                module_path="app",
                module_sha256="a" * 64,
                pc=0x401000,
            ),
        ),
        complete=False,
        reason="function pointer value is not closed",
    )
    assert target_set.known_targets[0].pc == 0x401000


def test_manifest_and_coverage_round_trip() -> None:
    manifest = ProgramManifest(
        executable=None,
        library_roots=("/guest/lib",),
        execution=ExecutionScope(argv=("app", "4"), thread_count_min=4),
        dbt_contract_version="test-v1",
        dbt_revision=None,
        closure_complete=False,
        unknowns=(
            UnknownFact(
                kind=UnknownKind.MISSING_EXECUTABLE,
                reason="missing",
                impact="cannot inspect program",
            ),
        ),
    )
    report = FingerprintReport(manifest=manifest)
    assert FingerprintReport.model_validate_json(report.model_dump_json()) == report

    coverage = AnalysisCoverage(modules=2, instructions=10)
    assert AnalysisCoverage.model_validate_json(coverage.model_dump_json()) == coverage


def test_certificate_scope_and_verdict_serialization() -> None:
    scope = CertificateScope(
        executable_sha256="a" * 64,
        library_sha256=("b" * 64,),
        dbt_contract_version="dbt6-mo-off-v1",
        dbt_revision="c" * 40,
        argv=("app",),
    )
    assert CertificateScope.model_validate_json(scope.model_dump_json()) == scope
    assert Verdict.SAFE.value == "SAFE"


def test_model_layer_has_no_analysis_backend_imports() -> None:
    model_root = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "bmo_check"
        / "model"
    )
    forbidden = {"angr", "capstone", "elftools", "z3"}
    imported: set[str] = set()
    for path in model_root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
    assert imported.isdisjoint(forbidden)
