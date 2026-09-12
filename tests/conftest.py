from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """为外部 litmus ELF profile 提供显式输入边界。"""

    parser.addoption(
        "--litmus-elf-root",
        action="store",
        default=None,
        help="external litmus-tests-x86 corpus root for the opt-in profile",
    )
    parser.addoption(
        "--litmus-library-root",
        action="append",
        default=[],
        help="concrete guest library root used by the opt-in ELF profile",
    )
    parser.addoption(
        "--require-litmus-elf",
        action="store_true",
        default=False,
        help="fail instead of skipping when the opt-in ELF corpus is absent",
    )


@dataclass(frozen=True)
class ElfFixture:
    executable: Path
    library_root: Path
    alternate_library_root: Path
    system_roots: tuple[Path, ...]


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True, capture_output=True, text=True)


@pytest.fixture()
def elf_fixture(tmp_path: Path) -> ElfFixture:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.fail("gcc is required for Milestone 0 ELF integration tests")

    source = tmp_path / "sample.c"
    source.write_text("int sample(void) { return 42; }\n", encoding="utf-8")
    alternate_source = tmp_path / "sample-alt.c"
    alternate_source.write_text(
        "int sample(void) { return 7; }\n", encoding="utf-8"
    )
    main_source = tmp_path / "main.c"
    main_source.write_text(
        "extern int sample(void);\n"
        "int main(void) { return sample() == 42 ? 0 : 1; }\n",
        encoding="utf-8",
    )

    library_root = tmp_path / "lib-a"
    alternate_root = tmp_path / "lib-b"
    library_root.mkdir()
    alternate_root.mkdir()
    library_a = library_root / "libsample.so"
    library_b = alternate_root / "libsample.so"
    executable = tmp_path / "sample-app"

    _run(
        [
            gcc,
            "-fPIC",
            "-shared",
            "-Wl,-soname,libsample.so",
            "-o",
            str(library_a),
            str(source),
        ]
    )
    _run(
        [
            gcc,
            "-fPIC",
            "-shared",
            "-Wl,-soname,libsample.so",
            "-o",
            str(library_b),
            str(alternate_source),
        ]
    )
    _run(
        [
            gcc,
            "-o",
            str(executable),
            str(main_source),
            f"-L{library_root}",
            "-lsample",
        ]
    )

    system_roots = tuple(
        path
        for path in (
            Path("/lib64"),
            Path("/lib/x86_64-linux-gnu"),
            Path("/usr/lib/x86_64-linux-gnu"),
        )
        if path.is_dir()
    )
    return ElfFixture(
        executable=executable,
        library_root=library_root,
        alternate_library_root=alternate_root,
        system_roots=system_roots,
    )
