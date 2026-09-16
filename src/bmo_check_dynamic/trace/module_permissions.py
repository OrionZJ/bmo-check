from __future__ import annotations

import hashlib
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from bmo_check_dynamic.model import TraceManifest

from .syscalls import SyscallObservation


PAGE_SIZE = 4096
PF_W = 0x2
PF_R = 0x4
PROT_WRITE = 0x2


def read_only_module_ranges(
    modules_path: Path,
    manifest: TraceManifest,
    syscalls: tuple[SyscallObservation, ...],
) -> tuple[tuple[int, int], ...]:
    """返回 ELF 已证明只读、且 trace 中没有改成可写或卸载的映射范围。"""

    fingerprints = {
        item.path: item.sha256.lower()
        for item in (manifest.executable, *manifest.libraries)
    }
    mapped_ranges: list[tuple[int, int]] = []
    try:
        lines = modules_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ()

    for line in lines:
        fields = line.split("\t", 2)
        if len(fields) != 3:
            continue
        try:
            module_start, module_end = (int(fields[index], 16) for index in (0, 1))
        except ValueError:
            continue
        expected_hash = fingerprints.get(fields[2])
        if expected_hash is None or module_end <= module_start:
            continue
        mapped_ranges.extend(
            _verified_read_only_segments(
                Path(fields[2]), expected_hash, module_start, module_end
            )
        )

    mutable_ranges = _mapping_mutations(syscalls)
    return _subtract_ranges(_merge_ranges(mapped_ranges), mutable_ranges)


def _verified_read_only_segments(
    path: Path,
    expected_hash: str,
    module_start: int,
    module_end: int,
) -> tuple[tuple[int, int], ...]:
    if _file_sha256(path) != expected_hash:
        return ()
    try:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.elfclass != 64 or elf.header["e_machine"] != "EM_X86_64":
                return ()
            segments = [
                (int(item["p_vaddr"]), int(item["p_memsz"]), int(item["p_flags"]))
                for item in elf.iter_segments()
                if item["p_type"] == "PT_LOAD" and int(item["p_memsz"]) > 0
            ]
    except (OSError, ELFError, KeyError, ValueError):
        return ()
    if not segments:
        return ()

    lowest_page = min(_align_down(address) for address, _size, _flags in segments)
    load_bias = module_start - lowest_page
    if load_bias < 0 or load_bias % PAGE_SIZE:
        return ()

    readable: list[tuple[int, int]] = []
    writable: list[tuple[int, int]] = []
    for address, size, flags in segments:
        start = max(module_start, _align_down(load_bias + address))
        end = min(module_end, _align_up(load_bias + address + size))
        if end <= start:
            continue
        if flags & PF_R:
            readable.append((start, end))
        if flags & PF_W:
            writable.append((start, end))
    return _subtract_ranges(_merge_ranges(readable), _merge_ranges(writable))


def _mapping_mutations(
    syscalls: tuple[SyscallObservation, ...],
) -> tuple[tuple[int, int], ...]:
    mutations: list[tuple[int, int]] = []
    for call in syscalls:
        if len(call.arguments) != 6 or not _succeeded(call.result):
            continue
        if call.number == 10 and call.arguments[2] & PROT_WRITE:
            address, size = call.arguments[0], call.arguments[1]
        elif call.number == 11:
            address, size = call.arguments[0], call.arguments[1]
        else:
            continue
        if size > 0 and address + size <= 1 << 64:
            # 内核按页改权限或解除映射；只扣除字节范围会把同一页剩余部分误认为只读。
            mutations.append((_align_down(address), _align_up(address + size)))
    return _merge_ranges(mutations)


def _file_sha256(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _merge_ranges(ranges: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if end <= start:
            continue
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else:
            result.append((start, end))
    return tuple(result)


def _subtract_ranges(
    ranges: tuple[tuple[int, int], ...], exclusions: tuple[tuple[int, int], ...]
) -> tuple[tuple[int, int], ...]:
    if not exclusions:
        return ranges
    result: list[tuple[int, int]] = []
    for start, end in ranges:
        cursor = start
        for excluded_start, excluded_end in exclusions:
            if excluded_end <= cursor:
                continue
            if excluded_start >= end:
                break
            if excluded_start > cursor:
                result.append((cursor, excluded_start))
            cursor = max(cursor, excluded_end)
            if cursor >= end:
                break
        if cursor < end:
            result.append((cursor, end))
    return tuple(result)


def _align_down(value: int) -> int:
    return value & -PAGE_SIZE


def _align_up(value: int) -> int:
    return (value + PAGE_SIZE - 1) & -PAGE_SIZE


def _succeeded(result: int | None) -> bool:
    return result is not None and result < (1 << 63)
