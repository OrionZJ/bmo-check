from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.constants import SH_FLAGS
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

from bmo_check.model import ElfMetadata, ModuleFingerprint, ModuleRole


class ElfInspectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutableSegment:
    name: str
    virtual_address: int
    file_offset: int
    data: bytes


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalize_build_id(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    text = str(value).strip()
    return text.lower() or None


def _read_build_id(elf: ELFFile) -> str | None:
    for section in elf.iter_sections():
        if not isinstance(section, NoteSection):
            continue
        for note in section.iter_notes():
            if note.get("n_type") == "NT_GNU_BUILD_ID":
                return _normalize_build_id(note.get("n_desc"))
    return None


def _read_dynamic_metadata(
    elf: ELFFile,
) -> tuple[str | None, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    soname: str | None = None
    needed: list[str] = []
    rpath: list[str] = []
    runpath: list[str] = []
    for segment in elf.iter_segments():
        if not isinstance(segment, DynamicSegment):
            continue
        for tag in segment.iter_tags():
            kind = tag.entry.d_tag
            if kind == "DT_NEEDED":
                needed.append(tag.needed)
            elif kind == "DT_SONAME":
                soname = tag.soname
            elif kind == "DT_RPATH":
                rpath.extend(filter(None, tag.rpath.split(":")))
            elif kind == "DT_RUNPATH":
                runpath.extend(filter(None, tag.runpath.split(":")))
    return soname, tuple(needed), tuple(rpath), tuple(runpath)


def _read_interpreter(elf: ELFFile) -> str | None:
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_INTERP":
            return segment.get_interp_name()
    return None


def inspect_elf(path: Path, role: ModuleRole) -> ModuleFingerprint:
    resolved = path.resolve(strict=True)
    try:
        with resolved.open("rb") as stream:
            elf = ELFFile(stream)
            soname, needed, rpath, runpath = _read_dynamic_metadata(elf)
            metadata = ElfMetadata(
                elf_class=elf.elfclass,
                little_endian=elf.little_endian,
                machine=str(elf.header.e_machine),
                elf_type=str(elf.header.e_type),
                interpreter=_read_interpreter(elf),
                soname=soname,
                needed=needed,
                rpath=rpath,
                runpath=runpath,
            )
            build_id = _read_build_id(elf)
    except (OSError, ValueError, TypeError, ELFError) as error:
        raise ElfInspectionError(f"cannot inspect ELF {resolved}: {error}") from error

    return ModuleFingerprint(
        path=str(resolved),
        role=role,
        size=resolved.stat().st_size,
        sha256=sha256_file(resolved),
        build_id=build_id,
        elf=metadata,
    )


def executable_segments(path: Path) -> tuple[ExecutableSegment, ...]:
    resolved = path.resolve(strict=True)
    try:
        with resolved.open("rb") as stream:
            elf = ELFFile(stream)
            segments = [
                ExecutableSegment(
                    name=section.name,
                    virtual_address=int(section.header.sh_addr),
                    file_offset=int(section.header.sh_offset),
                    data=section.data(),
                )
                for section in elf.iter_sections()
                if int(section.header.sh_flags) & SH_FLAGS.SHF_EXECINSTR
                and section.header.sh_type != "SHT_NOBITS"
                and int(section.header.sh_size) > 0
            ]
    except (OSError, ValueError, TypeError, ELFError) as error:
        raise ElfInspectionError(
            f"cannot read executable segments from {resolved}: {error}"
        ) from error
    return tuple(segments)
