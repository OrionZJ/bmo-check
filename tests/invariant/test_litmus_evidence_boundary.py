from __future__ import annotations

import ast
from pathlib import Path


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(item.name for item in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module)
    return result


def test_litmus_models_do_not_depend_on_proof_or_verdict_routes() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "bmo_check_evaluation" / "litmus"
    forbidden_prefixes = (
        "bmo_check_static",
        "bmo_check_dynamic",
        "bmo_check_core.certificate",
        "bmo_check_core.evidence",
    )
    # model.py 是 wire/domain schema；conformance.py/service.py 属于 evaluation
    # 编排，可以在边界上调用静态 recovery，但不能让 schema 反向依赖它们。
    for path in (root / "model.py",):
        assert all(
            not imported.startswith(prefix)
            for imported in _imports(path)
            for prefix in forbidden_prefixes
        ), path


def test_fixture_schema_has_no_verdict_or_proof_fields() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "bmo_check_evaluation"
        / "litmus"
        / "model.py"
    ).read_text(encoding="utf-8")
    assert "ProofFact" not in source
    assert "Verdict" not in source
