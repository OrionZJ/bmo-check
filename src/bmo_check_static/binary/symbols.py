from __future__ import annotations

import struct
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from bmo_check_static.model import (
    FunctionSymbolFact,
    ModuleFingerprint,
    ProgramManifest,
    RelocationFact,
)


class SymbolInspectionError(RuntimeError):
    pass


def function_symbols(
    module: ModuleFingerprint,
) -> tuple[FunctionSymbolFact, ...]:
    selected: dict[tuple[str, int], FunctionSymbolFact] = {}
    try:
        with Path(module.path).open("rb") as stream:
            elf = ELFFile(stream)
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in section.iter_symbols():
                    entry = symbol.entry
                    if (
                        entry.st_info.type != "STT_FUNC"
                        or entry.st_shndx == "SHN_UNDEF"
                        or not symbol.name
                    ):
                        continue
                    fact = FunctionSymbolFact(
                        module_path=module.path,
                        module_sha256=module.sha256,
                        name=symbol.name,
                        pc=int(entry.st_value),
                        size=int(entry.st_size),
                        binding=str(entry.st_info.bind),
                        visibility=str(entry.st_other.visibility),
                        table=section.name,
                    )
                    key = (fact.name, fact.pc)
                    previous = selected.get(key)
                    if previous is None or (
                        previous.table == ".dynsym" and fact.table == ".symtab"
                    ):
                        selected[key] = fact
    except (OSError, ValueError, TypeError, ELFError) as error:
        raise SymbolInspectionError(
            f"cannot recover function symbols from {module.path}: {error}"
        ) from error
    return tuple(sorted(selected.values(), key=lambda item: (item.pc, item.name)))


def relocations(module: ModuleFingerprint) -> tuple[RelocationFact, ...]:
    facts: list[RelocationFact] = []
    try:
        with Path(module.path).open("rb") as stream:
            elf = ELFFile(stream)
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue
                symbol_table = elf.get_section(section.header.sh_link)
                for relocation in section.iter_relocations():
                    symbol_index = int(relocation.entry.r_info_sym)
                    if symbol_index == 0:
                        continue
                    symbol = symbol_table.get_symbol(symbol_index)
                    if not symbol.name:
                        continue
                    facts.append(
                        RelocationFact(
                            module_path=module.path,
                            module_sha256=module.sha256,
                            offset=int(relocation.entry.r_offset),
                            symbol_name=symbol.name,
                            relocation_type=int(relocation.entry.r_info_type),
                            section=section.name,
                            binding=str(symbol.entry.st_info.bind),
                            undefined=symbol.entry.st_shndx == "SHN_UNDEF",
                        )
                    )
    except (OSError, ValueError, TypeError, ELFError) as error:
        raise SymbolInspectionError(
            f"cannot recover relocations from {module.path}: {error}"
        ) from error
    return tuple(sorted(facts, key=lambda item: (item.offset, item.symbol_name)))


def resolve_function_symbol(
    manifest: ProgramManifest, name: str
) -> tuple[FunctionSymbolFact, ...]:
    definitions: list[FunctionSymbolFact] = []
    for module in manifest.libraries:
        definitions.extend(
            symbol for symbol in function_symbols(module) if symbol.name == name
        )
        if definitions:
            break
    return tuple(definitions)


def function_pointer_sections(
    module: ModuleFingerprint,
    names: tuple[str, ...],
) -> dict[str, tuple[int, ...]]:
    result: dict[str, tuple[int, ...]] = {}
    try:
        with Path(module.path).open("rb") as stream:
            elf = ELFFile(stream)
            byte_order = "<" if elf.little_endian else ">"
            pointer_format = byte_order + ("Q" if elf.elfclass == 64 else "I")
            pointer_size = 8 if elf.elfclass == 64 else 4
            for name in names:
                section = elf.get_section_by_name(name)
                if section is None:
                    continue
                data = section.data()
                values = tuple(
                    int(struct.unpack_from(pointer_format, data, offset)[0])
                    for offset in range(0, len(data) - pointer_size + 1, pointer_size)
                    if int(struct.unpack_from(pointer_format, data, offset)[0]) != 0
                )
                result[name] = values
    except (OSError, ValueError, TypeError, ELFError, struct.error) as error:
        raise SymbolInspectionError(
            f"cannot recover function-pointer sections from {module.path}: {error}"
        ) from error
    return result
