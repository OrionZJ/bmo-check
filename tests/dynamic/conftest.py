from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from bmo_check_dynamic.model import BinaryFingerprint, TraceManifest


@pytest.fixture
def trace_manifest(tmp_path: Path):
    def create(trace_dir: Path, *, complete: bool = True, control_closed: bool = False):
        trace_dir.mkdir(parents=True, exist_ok=True)
        executable = tmp_path / "program"
        executable.write_bytes(b"ELF fixture")
        manifest = TraceManifest(
            trace_id="fixture-trace",
            platform="Linux-test",
            command=(str(executable),),
            working_directory=str(tmp_path),
            executable=BinaryFingerprint(
                path=str(executable),
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            complete=complete,
            control_flow_closed=control_closed,
        )
        manifest.save(trace_dir / "manifest.json")
        return manifest

    return create
