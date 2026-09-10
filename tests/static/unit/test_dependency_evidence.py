from __future__ import annotations

from pathlib import Path

from bmo_check_core import ObservedFact, UnknownFact as CanonicalUnknownFact
from bmo_check_core.evidence import DiagnosticHint
from bmo_check_core.evidence import UnknownKind as CanonicalUnknownKind
from bmo_check_static.binary.dependency_closure import (
    build_program_manifest,
    build_program_manifest_with_evidence,
)
from bmo_check_static.model import ExecutionScope, UnknownKind


def _arguments(executable: Path) -> tuple[Path, tuple[Path, ...], ExecutionScope]:
    roots = (executable.parent,)
    return executable, roots, ExecutionScope(argv=(str(executable),), thread_count_min=1)


def test_dependency_evidence_is_opt_in_and_legacy_manifest_is_unchanged(
    elf_fixture,
) -> None:
    executable, roots, execution = _arguments(elf_fixture.executable)
    legacy = build_program_manifest(
        executable,
        (elf_fixture.library_root,) + elf_fixture.system_roots,
        execution,
        "test-contract-v1",
        "a" * 40,
    )
    snapshot = build_program_manifest_with_evidence(
        executable,
        (elf_fixture.library_root,) + elf_fixture.system_roots,
        execution,
        "test-contract-v1",
        "a" * 40,
    )

    assert snapshot.manifest == legacy
    assert snapshot.unknown_ids == ()
    assert all(
        isinstance(node, CanonicalUnknownFact)
        for node in snapshot.ledger.nodes()
    )


def test_dependency_unknown_is_emitted_to_canonical_ledger_without_observations(
    elf_fixture,
) -> None:
    executable, _, execution = _arguments(elf_fixture.executable)
    snapshot = build_program_manifest_with_evidence(
        executable,
        elf_fixture.system_roots,
        execution,
        "test-contract-v1",
        None,
        scope="recovery-fixture",
    )

    assert any(
        unknown.kind == UnknownKind.MISSING_LIBRARY
        for unknown in snapshot.manifest.unknowns
    )
    canonical_kinds = {
        node.kind
        for node in snapshot.ledger.nodes()
        if isinstance(node, CanonicalUnknownFact)
    }
    assert CanonicalUnknownKind.MISSING_LIBRARY in canonical_kinds
    assert CanonicalUnknownKind.MISSING_DBT_REVISION in canonical_kinds
    assert all(
        not isinstance(node, (ObservedFact, DiagnosticHint))
        for node in snapshot.ledger.nodes()
    )


def test_dependency_unknown_ids_bind_scope_and_are_deterministic(tmp_path: Path) -> None:
    executable = tmp_path / "missing-app"
    execution = ExecutionScope(argv=(str(executable),), thread_count_min=1)
    first = build_program_manifest_with_evidence(
        executable,
        (),
        execution,
        "test-contract-v1",
        None,
        scope="scope-a",
    )
    second = build_program_manifest_with_evidence(
        executable,
        (),
        execution,
        "test-contract-v1",
        None,
        scope="scope-a",
    )
    other_scope = build_program_manifest_with_evidence(
        executable,
        (),
        execution,
        "test-contract-v1",
        None,
        scope="scope-b",
    )

    assert first.unknown_ids == second.unknown_ids
    assert first.unknown_ids != other_scope.unknown_ids
    assert any(
        node.kind == CanonicalUnknownKind.MISSING_EXECUTABLE
        for node in first.ledger.nodes()
        if isinstance(node, CanonicalUnknownFact)
    )
