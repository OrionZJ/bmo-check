from __future__ import annotations

from collections import deque
from pathlib import Path

from bmo_check_core import EvidenceLedger
from bmo_check_static.model import (
    ExecutionScope,
    ModuleFingerprint,
    ModuleRole,
    ProgramManifest,
    UnknownFact,
    UnknownKind,
)

from .elf import ElfInspectionError, inspect_elf, sha256_file
from .evidence import StaticRecoveryEvidence, emit_static_unknown


SUPPORTED_MACHINE = "EM_X86_64"


def _unknown(
    kind: UnknownKind,
    reason: str,
    impact: str,
    *,
    module: str | None = None,
    details: dict[str, object] | None = None,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.recovery",
) -> UnknownFact:
    return emit_static_unknown(
        kind,
        reason,
        impact,
        module=module,
        details=details,
        canonical_ledger=canonical_ledger,
        canonical_scope=canonical_scope,
    )


def _candidate_paths(
    name: str, requester: Path | None, roots: tuple[Path, ...]
) -> tuple[Path, ...]:
    candidates: list[Path] = []
    search_dirs = ([requester.parent] if requester is not None else []) + list(roots)
    for directory in search_dirs:
        candidate = directory / name
        if candidate.is_file():
            resolved = candidate.resolve()
            if resolved not in candidates:
                candidates.append(resolved)
    return tuple(candidates)


def _resolve_module(
    name: str,
    requester: Path | None,
    roots: tuple[Path, ...],
    *,
    missing_kind: UnknownKind,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.recovery",
) -> tuple[Path | None, UnknownFact | None]:
    candidates = _candidate_paths(name, requester, roots)
    if not candidates:
        return None, _unknown(
            missing_kind,
            f"cannot resolve {name!r} in configured library roots",
            "binary dependency closure is incomplete",
            module=str(requester) if requester else None,
            details={"name": name, "roots": [str(root) for root in roots]},
            canonical_ledger=canonical_ledger,
            canonical_scope=canonical_scope,
        )

    hashes = {sha256_file(path) for path in candidates}
    if len(hashes) > 1:
        return None, _unknown(
            UnknownKind.AMBIGUOUS_LIBRARY,
            f"multiple different files can satisfy {name!r}",
            "the analyzer cannot bind synchronization semantics to one implementation",
            module=str(requester) if requester else None,
            details={"name": name, "candidates": [str(path) for path in candidates]},
            canonical_ledger=canonical_ledger,
            canonical_scope=canonical_scope,
        )
    return candidates[0], None


def _validate_module(
    module: ModuleFingerprint,
    unknowns: list[UnknownFact],
    *,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.recovery",
) -> bool:
    valid = True
    if module.elf.elf_class != 64 or module.elf.machine != SUPPORTED_MACHINE:
        unknowns.append(
            _unknown(
                UnknownKind.UNSUPPORTED_ARCHITECTURE,
                f"expected ELF64 {SUPPORTED_MACHINE}, got ELF{module.elf.elf_class} {module.elf.machine}",
                "Milestone 0 only models x86-64 binaries",
                module=module.path,
                canonical_ledger=canonical_ledger,
                canonical_scope=canonical_scope,
            )
        )
        valid = False
    return valid


def build_program_manifest(
    executable_path: Path,
    library_roots: tuple[Path, ...],
    execution: ExecutionScope,
    dbt_contract_version: str,
    dbt_revision: str | None,
    *,
    canonical_ledger: EvidenceLedger | None = None,
    canonical_scope: str = "static.recovery",
) -> ProgramManifest:
    roots = tuple(root.resolve() for root in library_roots)
    unknowns: list[UnknownFact] = []
    executable: ModuleFingerprint | None = None
    interpreter: ModuleFingerprint | None = None
    libraries: list[ModuleFingerprint] = []

    try:
        executable = inspect_elf(executable_path, ModuleRole.EXECUTABLE)
        _validate_module(
            executable,
            unknowns,
            canonical_ledger=canonical_ledger,
            canonical_scope=canonical_scope,
        )
    except FileNotFoundError:
        unknowns.append(
            _unknown(
                UnknownKind.MISSING_EXECUTABLE,
                f"executable does not exist: {executable_path}",
                "there is no binary to analyze",
                module=str(executable_path),
                canonical_ledger=canonical_ledger,
                canonical_scope=canonical_scope,
            )
        )
    except ElfInspectionError as error:
        unknowns.append(
            _unknown(
                UnknownKind.INVALID_ELF,
                str(error),
                "the executable fingerprint and dependencies are unavailable",
                module=str(executable_path),
                canonical_ledger=canonical_ledger,
                canonical_scope=canonical_scope,
            )
        )

    if dbt_revision is None:
        unknowns.append(
            _unknown(
                UnknownKind.MISSING_DBT_REVISION,
                "DBT revision was not supplied",
                "a future SAFE certificate cannot be bound to one lowering implementation",
                canonical_ledger=canonical_ledger,
                canonical_scope=canonical_scope,
            )
        )

    queue: deque[ModuleFingerprint] = deque()
    seen_paths: set[str] = set()
    if executable is not None:
        queue.append(executable)
        seen_paths.add(executable.path)

        if executable.elf.interpreter:
            interpreter_name = Path(executable.elf.interpreter).name
            path, failure = _resolve_module(
                interpreter_name,
                Path(executable.path),
                roots,
                missing_kind=UnknownKind.MISSING_INTERPRETER,
                canonical_ledger=canonical_ledger,
                canonical_scope=canonical_scope,
            )
            if failure:
                unknowns.append(failure)
            elif path is not None:
                try:
                    interpreter = inspect_elf(path, ModuleRole.INTERPRETER)
                    _validate_module(
                        interpreter,
                        unknowns,
                        canonical_ledger=canonical_ledger,
                        canonical_scope=canonical_scope,
                    )
                    seen_paths.add(interpreter.path)
                except (FileNotFoundError, ElfInspectionError) as error:
                    unknowns.append(
                        _unknown(
                            UnknownKind.ELF_BACKEND_FAILURE,
                            str(error),
                            "the concrete interpreter implementation is unavailable",
                            module=str(path),
                            canonical_ledger=canonical_ledger,
                            canonical_scope=canonical_scope,
                        )
                    )

    while queue:
        requester = queue.popleft()
        for needed in requester.elf.needed:
            path, failure = _resolve_module(
                needed,
                Path(requester.path),
                roots,
                missing_kind=UnknownKind.MISSING_LIBRARY,
                canonical_ledger=canonical_ledger,
                canonical_scope=canonical_scope,
            )
            if failure:
                unknowns.append(failure)
                continue
            assert path is not None
            resolved_key = str(path.resolve())
            if resolved_key in seen_paths:
                continue
            try:
                library = inspect_elf(path, ModuleRole.SHARED_LIBRARY)
                _validate_module(
                    library,
                    unknowns,
                    canonical_ledger=canonical_ledger,
                    canonical_scope=canonical_scope,
                )
            except (FileNotFoundError, ElfInspectionError) as error:
                unknowns.append(
                    _unknown(
                        UnknownKind.ELF_BACKEND_FAILURE,
                        str(error),
                        "a required library implementation could not be inspected",
                        module=str(path),
                        canonical_ledger=canonical_ledger,
                        canonical_scope=canonical_scope,
                    )
                )
                continue
            seen_paths.add(library.path)
            libraries.append(library)
            queue.append(library)

    return ProgramManifest(
        executable=executable,
        interpreter=interpreter,
        libraries=tuple(libraries),
        library_roots=tuple(str(root) for root in roots),
        execution=execution,
        dbt_contract_version=dbt_contract_version,
        dbt_revision=dbt_revision,
        closure_complete=not unknowns,
        unknowns=tuple(unknowns),
    )


def build_program_manifest_with_evidence(
    executable_path: Path,
    library_roots: tuple[Path, ...],
    execution: ExecutionScope,
    dbt_contract_version: str,
    dbt_revision: str | None,
    *,
    scope: str = "static.recovery",
) -> StaticRecoveryEvidence:
    """以 opt-in 方式运行依赖闭包 producer，并保存 canonical Unknown。"""

    ledger = EvidenceLedger()
    manifest = build_program_manifest(
        executable_path,
        library_roots,
        execution,
        dbt_contract_version,
        dbt_revision,
        canonical_ledger=ledger,
        canonical_scope=scope,
    )
    return StaticRecoveryEvidence(manifest=manifest, ledger=ledger)
