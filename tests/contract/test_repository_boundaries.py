from __future__ import annotations

import ast
from pathlib import Path


BENCHMARK_NAMES = {
    "blackscholes",
    "swaptions",
    "ferret",
    "facesim",
    "freqmine",
    "fluidanimate",
    "streamcluster",
    "canneal",
    "bodytrack",
    "raytrace",
    "dedup",
    "vips",
}


def _package_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def _semantic_roots(root: Path) -> tuple[Path, ...]:
    return (
        root / "bmo_check_static" / name
        for name in (
            "analysis",
            "binary",
            "controlflow",
            "model",
            "proof",
            "pruning",
            "slicing",
            "synchronization",
            "threading",
        )
    )


def test_static_and_dynamic_routes_have_no_cross_route_imports() -> None:
    src = Path(__file__).resolve().parents[2] / "src"
    for path in (src / "bmo_check_static").rglob("*.py"):
        assert all(
            not imported.startswith("bmo_check_dynamic")
            and not imported.startswith("bmo_check_diagnostics")
            for imported in _package_imports(path)
        ), path
    for path in (src / "bmo_check_dynamic").rglob("*.py"):
        assert all(
            not imported.startswith("bmo_check_static")
            and not imported.startswith("bmo_check_diagnostics")
            for imported in _package_imports(path)
        ), path
    for path in (src / "bmo_check_core").rglob("*.py"):
        assert all(
            not imported.startswith("bmo_check_static")
            and not imported.startswith("bmo_check_dynamic")
            and not imported.startswith("bmo_check_diagnostics")
            and not imported.startswith("bmo_check_evaluation")
            and not imported.startswith("bmo_check_cli")
            for imported in _package_imports(path)
        ), path


def test_semantic_routes_do_not_branch_on_benchmark_names() -> None:
    src = Path(__file__).resolve().parents[2] / "src"
    offenders: list[Path] = []
    for directory in _semantic_roots(src):
        for path in directory.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            literals = {
                node.value.lower()
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
            }
            if any(name in literal for literal in literals for name in BENCHMARK_NAMES):
                offenders.append(path)
    assert offenders == []


def test_static_model_layer_has_no_backend_or_route_imports() -> None:
    model_root = Path(__file__).resolve().parents[2] / "src" / "bmo_check_static" / "model"
    forbidden = {
        "angr",
        "capstone",
        "elftools",
        "z3",
        "bmo_check_dynamic",
        "bmo_check_diagnostics",
    }
    imported: set[str] = set()
    for path in model_root.glob("*.py"):
        imported.update(
            item.split(".", 1)[0]
            for item in _package_imports(path)
        )
    assert imported.isdisjoint(forbidden)
