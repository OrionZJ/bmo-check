from __future__ import annotations

from pathlib import Path

from bmo_check_dynamic.application import (
    AnalyzeRequest,
    CaptureRequest,
    analyze as analyze_dynamic,
    capture as capture_dynamic,
)
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_static.application import StaticApplicationError, StaticRequest


def test_static_request_rejects_unscoped_analysis() -> None:
    try:
        StaticRequest(
            executable=Path("/bin/program"),
            dbt_contract=Path("/tmp/dbt.yaml"),
            pthread_spec=Path("/tmp/pthread.yaml"),
            function_effects=Path("/tmp/effects.yaml"),
            scope="unknown",
        )
    except StaticApplicationError as error:
        assert "scope" in str(error)
    else:
        raise AssertionError("invalid static scope was accepted")


def test_dynamic_capture_service_passes_typed_request(monkeypatch, tmp_path: Path) -> None:
    manifest = object()
    captured: dict[str, object] = {}

    def fake_capture(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return manifest

    monkeypatch.setattr("bmo_check_dynamic.application.capture_program", fake_capture)
    request = CaptureRequest(
        command=("/bin/program", "--input"),
        output_dir=tmp_path / "trace",
        dynamorio_home=tmp_path / "dr",
        client_path=tmp_path / "client.so",
        environment=(("MODE", "test"),),
    )

    assert capture_dynamic(request) is manifest
    assert captured["args"] == (request.command, request.output_dir)
    assert captured["kwargs"] == {
        "dynamorio_home": request.dynamorio_home,
        "client_path": request.client_path,
        "environment": {"MODE": "test"},
        "working_directory": None,
        "max_thread_events": None,
    }


def test_dynamic_analyze_service_passes_typed_request(monkeypatch, tmp_path: Path) -> None:
    expected = object()
    captured: dict[str, object] = {}

    def fake_analyze(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return expected

    monkeypatch.setattr("bmo_check_dynamic.application.analyze_trace", fake_analyze)
    request = AnalyzeRequest(
        trace_dir=tmp_path / "trace",
        dbt_contract=tmp_path / "contract.yaml",
        config=DynamicConfig(),
    )

    assert analyze_dynamic(request) is expected
    assert captured["args"] == (request.trace_dir,)
    assert captured["kwargs"] == {
        "dbt_contract": request.dbt_contract,
        "config": request.config,
    }
