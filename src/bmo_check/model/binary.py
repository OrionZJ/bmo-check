from __future__ import annotations

from enum import Enum

from pydantic import Field

from .common import StrictModel
from .unknown import UnknownFact


class ModuleRole(str, Enum):
    EXECUTABLE = "executable"
    INTERPRETER = "interpreter"
    SHARED_LIBRARY = "shared_library"


class ElfMetadata(StrictModel):
    elf_class: int
    little_endian: bool
    machine: str
    elf_type: str
    interpreter: str | None = None
    soname: str | None = None
    needed: tuple[str, ...] = ()
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()


class ModuleFingerprint(StrictModel):
    path: str
    role: ModuleRole
    size: int
    sha256: str
    build_id: str | None = None
    elf: ElfMetadata


class ExecutionScope(StrictModel):
    argv: tuple[str, ...] = ()
    thread_count_min: int | None = None
    thread_count_max: int | None = None
    environment: dict[str, str] = Field(default_factory=dict)


class ProgramManifest(StrictModel):
    schema_version: int = 1
    executable: ModuleFingerprint | None = None
    interpreter: ModuleFingerprint | None = None
    libraries: tuple[ModuleFingerprint, ...] = ()
    library_roots: tuple[str, ...] = ()
    execution: ExecutionScope = Field(default_factory=ExecutionScope)
    dbt_contract_version: str
    dbt_revision: str | None = None
    closure_complete: bool
    unknowns: tuple[UnknownFact, ...] = ()


class FingerprintReport(StrictModel):
    schema_version: int = 1
    manifest: ProgramManifest
