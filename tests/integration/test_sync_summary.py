from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from bmo_check.binary.elf import inspect_elf
from bmo_check.model import ModuleRole, Ordering, UnknownKind
from bmo_check.synchronization import analyze_pthread_synchronization


def _compile_sync_library(tmp_path: Path) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.fail("gcc is required for synchronization integration tests")
    source = tmp_path / "sync.S"
    source.write_text(
        ".text\n"
        ".globl pthread_spin_lock\n"
        ".type pthread_spin_lock,@function\n"
        "pthread_spin_lock:\n"
        "  mov $1, %eax\n"
        "1: lock cmpxchg %edx, (%rdi)\n"
        "  jne 1b\n"
        "  ret\n"
        ".size pthread_spin_lock, .-pthread_spin_lock\n"
        ".globl pthread_spin_unlock\n"
        ".type pthread_spin_unlock,@function\n"
        "pthread_spin_unlock:\n"
        "  movl $1, (%rdi)\n"
        "  ret\n"
        ".size pthread_spin_unlock, .-pthread_spin_unlock\n",
        encoding="utf-8",
    )
    library = tmp_path / "libpthread-fixture.so"
    subprocess.run(
        [gcc, "-shared", "-fPIC", "-o", str(library), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    return library


def test_summary_uses_actual_lock_and_plain_store_instructions(tmp_path: Path) -> None:
    library = inspect_elf(_compile_sync_library(tmp_path), ModuleRole.SHARED_LIBRARY)
    project_root = Path(__file__).parents[2]
    report = analyze_pthread_synchronization(
        library,
        project_root / "specs" / "pthread-api.yaml",
        project_root / "specs" / "dbt6-mo-off.yaml",
    )
    by_api = {summary.api: summary for summary in report.summaries}

    spin_lock = by_api["pthread_spin_lock"]
    assert spin_lock.complete
    assert spin_lock.target_ordering == Ordering.ACQ_REL
    assert any(item.has_lock_prefix for item in spin_lock.evidence)

    spin_unlock = by_api["pthread_spin_unlock"]
    assert spin_unlock.complete
    assert spin_unlock.required_ordering == Ordering.RELEASE
    assert spin_unlock.target_ordering == Ordering.RELAXED
    assert any(item.memory_access is not None for item in spin_unlock.evidence)
    assert any(item.kind == UnknownKind.MISSING_SYMBOL_IMPLEMENTATION for item in report.unknowns)
