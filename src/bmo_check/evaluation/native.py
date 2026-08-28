from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from time import monotonic

from bmo_check.model import (
    BenchmarkDefinition,
    NativeRunMeasurement,
    OutputArtifactCheck,
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_native_benchmark(
    definition: BenchmarkDefinition,
    parsec_root: Path,
    argv: tuple[str, ...],
    timeout_seconds: int,
) -> NativeRunMeasurement:
    executable = (parsec_root / definition.executable).resolve()
    source_directory = (parsec_root / definition.run_directory).resolve()
    started = monotonic()
    with tempfile.TemporaryDirectory(prefix="bmo-check-native-") as temporary:
        workdir = Path(temporary)
        try:
            for relative in definition.input_files:
                source = source_directory / relative
                target = workdir / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if not source.is_file():
                    raise FileNotFoundError(f"missing native input: {source}")
                try:
                    os.symlink(source, target)
                except OSError:
                    shutil.copy2(source, target)
            completed = subprocess.run(
                [str(executable), *argv],
                cwd=workdir,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            return NativeRunMeasurement(
                attempted=True,
                timed_out=True,
                error=f"native execution exceeded {timeout_seconds} seconds",
                duration_seconds=monotonic() - started,
                stdout_sha256=_sha256_bytes(stdout),
                stderr_sha256=_sha256_bytes(stderr),
            )
        except OSError as error:
            return NativeRunMeasurement(
                attempted=True,
                error=str(error),
                duration_seconds=monotonic() - started,
            )

        outputs = []
        for relative in definition.output_files:
            path = workdir / relative
            expected = definition.expected_output_sha256.get(relative)
            actual = _sha256_file(path) if path.is_file() else None
            outputs.append(
                OutputArtifactCheck(
                    path=relative,
                    exists=path.is_file(),
                    sha256=actual,
                    expected_sha256=expected,
                    matches_expected=(actual == expected if expected is not None else None),
                )
            )
        return NativeRunMeasurement(
            attempted=True,
            exit_code=completed.returncode,
            duration_seconds=monotonic() - started,
            stdout_sha256=_sha256_bytes(completed.stdout),
            stderr_sha256=_sha256_bytes(completed.stderr),
            outputs=tuple(outputs),
        )
