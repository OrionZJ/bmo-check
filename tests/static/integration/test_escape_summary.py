from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from bmo_check_static.analysis.escape_summary import prove_register_parameter_nocapture
from bmo_check_static.binary.angr_backend import load_cfg
from bmo_check_static.binary.dependency_closure import build_program_manifest
from bmo_check_static.controlflow import recover_control_flow
from bmo_check_static.model import ExecutionScope



def _compile(tmp_path: Path, body: str) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.fail("gcc is required for escape-summary integration tests")
    source = tmp_path / "nocapture.c"
    source.write_text(body, encoding="utf-8")
    executable = tmp_path / "nocapture"
    subprocess.run(
        [
            gcc,
            "-O1",
            "-fno-inline",
            "-fno-omit-frame-pointer",
            "-o",
            str(executable),
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return executable


def _analyze(tmp_path: Path, body: str):
    executable = _compile(tmp_path, body)
    manifest = build_program_manifest(
        executable,
        tuple(path for path in (Path("/lib64"), Path("/lib/x86_64-linux-gnu")) if path.is_dir()),
        ExecutionScope(),
        "dbt6-mo-off-v2",
        "test-revision",
    )
    assert manifest.executable is not None
    control_flow = recover_control_flow(manifest.executable, manifest)
    context = load_cfg(manifest.executable)
    return context, control_flow


def test_register_parameter_nocapture_accepts_dereference_and_local_spill(
    tmp_path: Path,
) -> None:
    context, control_flow = _analyze(
        tmp_path,
        "__attribute__((noinline)) static void fill(int *p) { *p = 7; }\n"
        "int main(void) { int value = 0; fill(&value); return value; }\n",
    )
    function = next(item for item in control_flow.functions if item.location.symbol == "fill")

    result = prove_register_parameter_nocapture(
        context, control_flow, function.location.pc, 0
    )

    assert result.proven


def test_register_parameter_nocapture_rejects_global_publication(
    tmp_path: Path,
) -> None:
    context, control_flow = _analyze(
        tmp_path,
        "static int *sink;\n"
        "__attribute__((noinline)) static void publish(int *p) { sink = p; }\n"
        "int main(void) { int value = 0; publish(&value); return sink != 0; }\n",
    )
    function = next(item for item in control_flow.functions if item.location.symbol == "publish")

    result = prove_register_parameter_nocapture(
        context, control_flow, function.location.pc, 0
    )

    assert not result.proven
    assert "stored outside" in result.evidence[0]


def test_stack_parameter_nocapture_uses_verified_frame_layout(tmp_path: Path) -> None:
    context, control_flow = _analyze(
        tmp_path,
        "__attribute__((noinline)) static int fill(int a, int b, int c, int d, "
        "int e, int f, int *p) { *p = a+b+c+d+e+f; return 0; }\n"
        "int main(void) { int value = 0; return fill(1,2,3,4,5,6,&value)+value; }\n",
    )
    function = next(item for item in control_flow.functions if item.location.symbol == "fill")

    result = prove_register_parameter_nocapture(
        context, control_flow, function.location.pc, 6
    )

    assert result.proven
