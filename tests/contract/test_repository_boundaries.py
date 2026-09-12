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


def _semantic_python_files(root: Path) -> tuple[Path, ...]:
    """Return reusable route modules without the legacy CLI adapter."""

    return tuple(path for path in root.rglob("*.py") if path.name != "cli.py")


def test_static_and_dynamic_routes_have_no_cross_route_imports() -> None:
    src = Path(__file__).resolve().parents[2] / "src"
    # CLI 目前仍是历史入口，负责调用 evaluation service；这里先约束
    # 可复用的静态/动态语义模块，避免 fixture schema 反向进入证明实现。
    for path in _semantic_python_files(src / "bmo_check_static"):
        assert all(
            not imported.startswith("bmo_check_dynamic")
            and not imported.startswith("bmo_check_diagnostics")
            and not imported.startswith("bmo_check_evaluation")
            for imported in _package_imports(path)
        ), path
    for path in _semantic_python_files(src / "bmo_check_dynamic"):
        assert all(
            not imported.startswith("bmo_check_static")
            and not imported.startswith("bmo_check_diagnostics")
            and not imported.startswith("bmo_check_evaluation")
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


def test_evaluation_service_does_not_import_route_cli() -> None:
    src = Path(__file__).resolve().parents[2] / "src"
    forbidden = {
        "bmo_check_static.cli",
        "bmo_check_dynamic.cli",
        "bmo_check_cli",
    }
    for path in (src / "bmo_check_evaluation").rglob("*.py"):
        assert _package_imports(path).isdisjoint(forbidden), path


def test_static_cli_does_not_own_parsec_evaluation_policy() -> None:
    src = Path(__file__).resolve().parents[2] / "src"
    imports = _package_imports(src / "bmo_check_static" / "cli.py")
    assert "bmo_check_static.evaluation" not in imports


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
