from __future__ import annotations

from pathlib import Path

from bmo_check.binary.dependency_closure import build_program_manifest
from bmo_check.binary.elf import inspect_elf
from bmo_check.model import ExecutionScope, ModuleRole, UnknownKind


def _manifest(executable: Path, roots: tuple[Path, ...]):
    return build_program_manifest(
        executable,
        roots,
        ExecutionScope(argv=(str(executable),), thread_count_min=1, thread_count_max=1),
        "test-contract-v1",
        "a" * 40,
    )


def test_inspect_elf_fingerprint(elf_fixture) -> None:
    module = inspect_elf(elf_fixture.executable, ModuleRole.EXECUTABLE)
    assert module.elf.machine == "EM_X86_64"
    assert module.elf.elf_class == 64
    assert "libsample.so" in module.elf.needed
    assert len(module.sha256) == 64


def test_dependency_closure_is_complete(elf_fixture) -> None:
    roots = (elf_fixture.library_root,) + elf_fixture.system_roots
    manifest = _manifest(elf_fixture.executable, roots)
    assert manifest.closure_complete, manifest.unknowns
    assert any(
        library.elf.soname == "libsample.so" for library in manifest.libraries
    )
    assert manifest.interpreter is not None


def test_missing_library_is_explicit_unknown(elf_fixture) -> None:
    manifest = _manifest(elf_fixture.executable, elf_fixture.system_roots)
    assert not manifest.closure_complete
    assert any(
        unknown.kind == UnknownKind.MISSING_LIBRARY
        and unknown.details.get("name") == "libsample.so"
        for unknown in manifest.unknowns
    )


def test_same_soname_different_binary_changes_manifest(elf_fixture) -> None:
    first = _manifest(
        elf_fixture.executable,
        (elf_fixture.library_root,) + elf_fixture.system_roots,
    )
    second = _manifest(
        elf_fixture.executable,
        (elf_fixture.alternate_library_root,) + elf_fixture.system_roots,
    )
    first_sample = next(
        item for item in first.libraries if item.elf.soname == "libsample.so"
    )
    second_sample = next(
        item for item in second.libraries if item.elf.soname == "libsample.so"
    )
    assert first_sample.sha256 != second_sample.sha256


def test_missing_executable_is_explicit_unknown(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path / "missing-app", ())
    assert not manifest.closure_complete
    assert manifest.executable is None
    assert any(
        unknown.kind == UnknownKind.MISSING_EXECUTABLE
        for unknown in manifest.unknowns
    )


def test_missing_dbt_revision_blocks_complete_manifest(elf_fixture) -> None:
    roots = (elf_fixture.library_root,) + elf_fixture.system_roots
    manifest = build_program_manifest(
        elf_fixture.executable,
        roots,
        ExecutionScope(),
        "test-contract-v1",
        None,
    )
    assert not manifest.closure_complete
    assert any(
        unknown.kind == UnknownKind.MISSING_DBT_REVISION
        for unknown in manifest.unknowns
    )
