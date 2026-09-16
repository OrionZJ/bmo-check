from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from bmo_check_dynamic.model import BinaryFingerprint, TraceManifest
from bmo_check_dynamic.trace.module_permissions import read_only_module_ranges
from bmo_check_dynamic.trace.syscalls import SyscallObservation


def _elf_module_fixture(tmp_path: Path) -> tuple[Path, TraceManifest, int, int]:
    module_path = Path(sys.executable)
    try:
        with module_path.open("rb") as stream:
            elf = ELFFile(stream)
            assert elf.elfclass == 64
            assert elf.header["e_machine"] == "EM_X86_64"
            segments = [
                (int(item["p_vaddr"]), int(item["p_memsz"]))
                for item in elf.iter_segments()
                if item["p_type"] == "PT_LOAD" and int(item["p_memsz"]) > 0
            ]
    except (OSError, ELFError, AssertionError):
        pytest.skip("the current Python executable is not a 64-bit x86 ELF")
    if not segments:
        pytest.skip("the current Python executable has no loadable ELF segments")

    page_mask = ~0xFFF
    lowest_page = min(address & page_mask for address, _size in segments)
    highest_page = max((address + size + 0xFFF) & page_mask for address, size in segments)
    module_start = 0x700000000000 + lowest_page
    module_end = 0x700000000000 + highest_page
    modules_path = tmp_path / "modules.tsv"
    modules_path.write_text(
        f"{module_start:x}\t{module_end:x}\t{module_path}\n", encoding="utf-8"
    )
    digest = hashlib.sha256(module_path.read_bytes()).hexdigest()
    manifest = TraceManifest(
        trace_id="permission-test",
        platform="Linux-test-x86_64",
        command=(str(module_path),),
        working_directory=str(tmp_path),
        executable=BinaryFingerprint(path=str(module_path), sha256=digest),
    )
    return modules_path, manifest, module_start, module_end


def test_only_hash_bound_readonly_elf_load_segments_are_returned(
    tmp_path: Path,
) -> None:
    modules_path, manifest, module_start, module_end = _elf_module_fixture(tmp_path)
    ranges = read_only_module_ranges(modules_path, manifest, ())

    assert ranges
    assert all(module_start <= start < end <= module_end for start, end in ranges)
    assert all(start % 4096 == 0 and end % 4096 == 0 for start, end in ranges)


def test_writable_protection_change_invalidates_readonly_module_pages(
    tmp_path: Path,
) -> None:
    modules_path, manifest, module_start, module_end = _elf_module_fixture(tmp_path)
    mprotect = SyscallObservation(
        thread_id=1,
        ticket=1,
        number=10,
        arguments=(module_start, module_end - module_start, 0x3, 0, 0, 0),
        result=0,
    )

    assert read_only_module_ranges(modules_path, manifest, (mprotect,)) == ()


def test_partial_page_protection_change_invalidates_the_whole_page(
    tmp_path: Path,
) -> None:
    modules_path, manifest, _module_start, _module_end = _elf_module_fixture(tmp_path)
    page_start = next(
        start for start, _end in read_only_module_ranges(modules_path, manifest, ())
    )
    mprotect = SyscallObservation(
        thread_id=1,
        ticket=1,
        number=10,
        arguments=(page_start, 8, 0x3, 0, 0, 0),
        result=0,
    )

    remaining = read_only_module_ranges(modules_path, manifest, (mprotect,))

    assert all(
        start >= page_start + 4096 or end <= page_start
        for start, end in remaining
    )


def test_partial_page_unmap_invalidates_the_whole_page(tmp_path: Path) -> None:
    modules_path, manifest, _module_start, _module_end = _elf_module_fixture(tmp_path)
    page_start = next(
        start for start, _end in read_only_module_ranges(modules_path, manifest, ())
    )
    munmap = SyscallObservation(
        thread_id=1,
        ticket=1,
        number=11,
        arguments=(page_start, 8, 0, 0, 0, 0),
        result=0,
    )

    remaining = read_only_module_ranges(modules_path, manifest, (munmap,))

    assert all(
        start >= page_start + 4096 or end <= page_start
        for start, end in remaining
    )


def test_changed_module_file_does_not_provide_readonly_ranges(tmp_path: Path) -> None:
    modules_path, manifest, _module_start, _module_end = _elf_module_fixture(tmp_path)
    stale_manifest = manifest.model_copy(
        update={
            "executable": manifest.executable.model_copy(
                update={"sha256": "0" * 64}
            )
        }
    )

    assert read_only_module_ranges(modules_path, stale_manifest, ()) == ()
