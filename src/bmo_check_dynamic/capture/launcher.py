from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
import uuid
from pathlib import Path

from bmo_check_dynamic.model import BinaryFingerprint, TraceManifest


class CaptureError(RuntimeError):
    pass


def dynamorio_version(home: Path) -> str:
    version_file = home / "cmake" / "DynamoRIOConfigVersion.cmake"
    try:
        content = version_file.read_text(encoding="utf-8")
    except OSError:
        return "unknown"
    match = re.search(r"set\(PACKAGE_VERSION\s+\"?([^\s\")]+)", content)
    return match.group(1) if match else "unknown"


def fingerprint(path: Path) -> BinaryFingerprint:
    resolved = path.resolve(strict=True)
    digest = hashlib.sha256()
    with resolved.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return BinaryFingerprint(path=str(resolved), sha256=digest.hexdigest())


def dependency_fingerprints(executable: Path) -> tuple[BinaryFingerprint, ...]:
    result = subprocess.run(
        ["ldd", str(executable)], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise CaptureError(f"ldd failed: {result.stderr.strip()}")
    paths: set[Path] = set()
    for line in result.stdout.splitlines():
        match = re.search(r"(?:=>\s*)?(/[^\s]+)", line)
        if match:
            candidate = Path(match.group(1))
            if candidate.is_file():
                paths.add(candidate)
    return tuple(fingerprint(path) for path in sorted(paths))


def loaded_module_fingerprints(path: Path) -> tuple[tuple[BinaryFingerprint, ...], int]:
    if not path.is_file():
        return (), 1
    modules: dict[str, BinaryFingerprint] = {}
    errors = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split("\t", 2)
        if len(fields) != 3:
            errors += 1
            continue
        module_path = Path(fields[2])
        if not module_path.is_absolute():
            # vDSO 等内核映射由 platform 字段约束，没有独立 ELF 路径可哈希。
            continue
        try:
            item = fingerprint(module_path)
        except OSError:
            # vDSO 等匿名 module 没有可哈希文件；它们不能静默进入证明范围。
            errors += 1
            continue
        modules[item.path] = item
    return tuple(modules[path] for path in sorted(modules)), errors


def capture_program(
    command: tuple[str, ...],
    output_dir: Path,
    *,
    dynamorio_home: Path,
    client_path: Path,
    environment: dict[str, str] | None = None,
    working_directory: Path | None = None,
    max_thread_events: int | None = None,
) -> TraceManifest:
    if not command:
        raise CaptureError("program command cannot be empty")
    if max_thread_events is not None and max_thread_events <= 0:
        raise CaptureError("max_thread_events must be positive")
    if platform.system() != "Linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise CaptureError("dynamic capture supports Linux/WSL2 x86-64 only")
    workdir = (working_directory or Path.cwd()).resolve(strict=True)
    executable = Path(command[0])
    if not executable.is_absolute():
        local_candidate = workdir / executable
        resolved = local_candidate if local_candidate.is_file() else shutil_which(command[0])
        if resolved is None:
            raise CaptureError(f"program not found: {command[0]}")
        executable = resolved
    with executable.open("rb") as stream:
        if stream.read(5) != b"\x7fELF\x02":
            raise CaptureError("dynamic capture requires a 64-bit ELF executable")
    # drrun 会切换到目标 cwd。先固定绝对路径，否则 client 会把相对
    # trace 目录解释到被测程序目录，导致整条轨迹没有事件文件。
    output_dir = output_dir.resolve()
    client_path = client_path.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    manifest = TraceManifest(
        trace_id=str(uuid.uuid4()),
        platform=platform.platform(),
        command=command,
        working_directory=str(workdir),
        environment=environment or {},
        executable=fingerprint(executable),
        libraries=dependency_fingerprints(executable),
        dynamorio_version=dynamorio_version(dynamorio_home),
        client_version="0.6",
        complete=False,
        limitations=(
            "trace scope excludes unexecuted paths and alternative input-dependent addresses",
            *(
                (f"per-thread event budget: {max_thread_events}",)
                if max_thread_events is not None
                else ()
            ),
        ),
    )
    manifest_path = output_dir / "manifest.json"
    manifest.save(manifest_path)

    drrun = dynamorio_home / "bin64" / "drrun"
    if not drrun.is_file():
        raise CaptureError(f"DynamoRIO launcher not found: {drrun}")
    if not client_path.is_file():
        raise CaptureError(f"BMoCheck DynamoRIO client not found: {client_path}")
    child_environment = os.environ.copy()
    child_environment.update(environment or {})
    client_options = (
        ("--max-thread-events", str(max_thread_events))
        if max_thread_events is not None
        else ()
    )
    invocation = (
        str(drrun),
        "-c",
        str(client_path),
        "--trace-dir",
        str(output_dir),
        *client_options,
        "--",
        *command,
    )
    result = subprocess.run(
        invocation, env=child_environment, cwd=workdir, check=False
    )
    complete_marker = output_dir / ".complete"
    dropped_path = output_dir / ".dropped"
    try:
        dropped_events = int(dropped_path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        dropped_events = 1
    dropped_by_reason: dict[str, int] = {}
    reasons_path = output_dir / ".drop-reasons"
    try:
        for line in reasons_path.read_text(encoding="ascii").splitlines():
            name, separator, count = line.partition("\t")
            if not separator or not name:
                raise ValueError("invalid drop reason")
            dropped_by_reason[name] = dropped_by_reason.get(name, 0) + int(count)
    except (OSError, ValueError):
        if dropped_events:
            dropped_by_reason["missing_reason_file"] = dropped_events
    loaded_modules, module_errors = loaded_module_fingerprints(output_dir / "modules.tsv")
    all_libraries = {item.path: item for item in (*manifest.libraries, *loaded_modules)}
    dropped_events += module_errors
    complete = complete_marker.is_file()
    updated = manifest.model_copy(
        update={
            "complete": complete,
            "exit_code": result.returncode,
            "dropped_events": dropped_events,
            "dropped_by_reason": dropped_by_reason,
            "libraries": tuple(all_libraries[path] for path in sorted(all_libraries)),
        }
    )
    updated.save(manifest_path)
    return updated


def shutil_which(program: str) -> Path | None:
    from shutil import which

    resolved = which(program)
    return Path(resolved) if resolved else None
