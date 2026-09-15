from __future__ import annotations

from pathlib import Path

import pytest

from bmo_check_dynamic.config import DynamicConfig
from bmo_check_workflow import (
    HybridWorkloadManifest,
    WorkloadManifestError,
    load_workload_manifest,
    validate_output_layout,
)


def _manifest_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "workload.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _valid_manifest_text(*, database_path: str | None = None) -> str:
    analysis = (
        "  analysis:\n"
        f"    database_path: {database_path}\n"
        if database_path is not None
        else "  analysis: {}\n"
    )
    return (
        "schema_version: hybrid-workload-v1\n"
        "workload:\n"
        "  executable: ./program\n"
        "  argv: [--input, sample.dat]\n"
        "  working_directory: .\n"
        "  environment:\n"
        "    WORKERS: '2'\n"
        "static:\n"
        "  dbt_contract: ./dbt.yaml\n"
        "  pthread_spec: ./pthread.yaml\n"
        "  function_effects: ./effects.yaml\n"
        "  dbt_revision: 0123456789abcdef0123456789abcdef01234567\n"
        "  scope: full\n"
        "dynamic:\n"
        "  dynamorio_home: ./dynamorio\n"
        "  client_path: ./libbmo_trace.so\n"
        f"{analysis}"
    )


def test_manifest_resolves_inputs_against_manifest_and_database_against_output(
    tmp_path: Path,
) -> None:
    path = _manifest_file(tmp_path, _valid_manifest_text(database_path="analysis.duckdb"))
    manifest = load_workload_manifest(path)
    output_dir = tmp_path / "e-drive-output" / "run-1"

    request = manifest.to_request(path, output_dir)

    assert request.static_request.executable == (tmp_path / "program").resolve()
    assert request.static_request.argv == ("--input", "sample.dat")
    assert request.static_request.environment == (("WORKERS", "2"),)
    assert request.trace_dir == output_dir.resolve() / "trace"
    assert request.dynamic_config.database_path == output_dir.resolve() / "analysis.duckdb"
    validate_output_layout(request, output_dir)


def test_dynamic_defaults_are_taken_from_route_config(tmp_path: Path) -> None:
    path = _manifest_file(tmp_path, _valid_manifest_text())
    manifest = load_workload_manifest(path)
    request = manifest.to_request(path, tmp_path / "out")
    defaults = DynamicConfig()

    assert request.dynamic_config.max_window_events == defaults.max_window_events
    assert request.dynamic_config.max_executions == defaults.max_executions
    assert request.dynamic_config.max_communication_edges == defaults.max_communication_edges
    assert request.dynamic_config.database_memory_limit_mb == defaults.database_memory_limit_mb
    assert request.max_snapshot_sites == 100_000


@pytest.mark.parametrize(
    "text, message",
    [
        (_valid_manifest_text().replace("hybrid-workload-v1", "future-v2"), "schema"),
        (_valid_manifest_text() + "unknown_root: true\n", "unknown_root"),
        (
            _valid_manifest_text().replace(
                "  executable: ./program\n", "  executable: ./program\n  executable: ./other\n"
            ),
            "duplicate",
        ),
        (
            _valid_manifest_text().replace("  argv: [--input, sample.dat]\n", "  argv: [1]\n"),
            "argv",
        ),
        (
            _valid_manifest_text().replace("    WORKERS: '2'\n", "    BAD=NAME: value\n"),
            "environment",
        ),
    ],
)
def test_manifest_rejects_unknown_or_malformed_inputs(
    tmp_path: Path, text: str, message: str
) -> None:
    path = _manifest_file(tmp_path, text)

    with pytest.raises(WorkloadManifestError, match=message):
        load_workload_manifest(path)


def test_manifest_rejects_non_string_mapping_keys(tmp_path: Path) -> None:
    path = _manifest_file(
        tmp_path,
        _valid_manifest_text().replace("    WORKERS: '2'\n", "    7: value\n"),
    )

    with pytest.raises(WorkloadManifestError, match="keys must be strings"):
        load_workload_manifest(path)


def test_unbound_static_revision_remains_a_valid_unknown_workflow_input(
    tmp_path: Path,
) -> None:
    path = _manifest_file(
        tmp_path,
        _valid_manifest_text().replace(
            "  dbt_revision: 0123456789abcdef0123456789abcdef01234567\n", ""
        ),
    )
    manifest = load_workload_manifest(path)

    request = manifest.to_request(path, tmp_path / "out")

    assert request.static_request.dbt_revision is None


def test_database_path_cannot_escape_or_overwrite_workflow_outputs(
    tmp_path: Path,
) -> None:
    path = _manifest_file(tmp_path, _valid_manifest_text(database_path="../outside.duckdb"))
    manifest = load_workload_manifest(path)
    output_dir = tmp_path / "out"
    request = manifest.to_request(path, output_dir)

    with pytest.raises(WorkloadManifestError, match="direct child"):
        validate_output_layout(request, output_dir)

    conflict_path = _manifest_file(
        tmp_path, _valid_manifest_text(database_path="hybrid-workflow-report.json")
    )
    conflict = load_workload_manifest(conflict_path)
    with pytest.raises(WorkloadManifestError, match="conflicts"):
        validate_output_layout(conflict.to_request(conflict_path, output_dir), output_dir)


def test_manifest_rejects_invalid_limits(tmp_path: Path) -> None:
    path = _manifest_file(
        tmp_path,
        _valid_manifest_text().replace(
            "  analysis: {}\n", "  analysis:\n    max_executions: 0\n"
        ),
    )

    with pytest.raises(WorkloadManifestError, match="max_executions"):
        load_workload_manifest(path)


def test_manifest_is_typed_and_extra_fields_are_forbidden() -> None:
    manifest = HybridWorkloadManifest.model_validate(
        {
            "schema_version": "hybrid-workload-v1",
            "workload": {"executable": "program"},
            "static": {
                "dbt_contract": "dbt.yaml",
                "pthread_spec": "pthread.yaml",
                "function_effects": "effects.yaml",
            },
        }
    )

    assert isinstance(manifest, HybridWorkloadManifest)
    with pytest.raises(ValueError):
        HybridWorkloadManifest.model_validate(
            {
                "schema_version": "hybrid-workload-v1",
                "workload": {"executable": "program"},
                "static": {
                    "dbt_contract": "dbt.yaml",
                    "pthread_spec": "pthread.yaml",
                    "function_effects": "effects.yaml",
                    "surprise": True,
                },
            }
        )
