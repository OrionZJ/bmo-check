"""``bmo-check hybrid`` command adapter for one workload."""

from __future__ import annotations

import sys
from argparse import Namespace
from pathlib import Path

from bmo_check_dynamic.capture import CaptureError
from bmo_check_workflow import (
    HybridReportError,
    HybridWorkflowError,
    analyze_workload,
    build_hybrid_workflow_report,
    load_workload_manifest,
    save_hybrid_workflow_report,
    validate_output_layout,
    validate_request_inputs,
)
from bmo_check_workflow.manifest import WorkloadManifestError


def _path(value: object, name: str) -> Path:
    if not isinstance(value, Path):
        raise WorkloadManifestError(f"{name} must be a path")
    return value


def _write_new(path: Path, payload: str) -> None:
    """新建 route artifact，避免静默覆盖同一次运行的证据。"""

    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            if not payload.endswith("\n"):
                stream.write("\n")
    except OSError as error:
        raise WorkloadManifestError(f"cannot write workflow artifact {path}: {error}") from error


def run_hybrid(args: Namespace) -> int:
    """校验输入后运行既有服务；退出码只报告 workflow 是否完成。"""

    manifest_path = _path(getattr(args, "workload", None), "workload manifest")
    output_dir = _path(getattr(args, "output_dir", None), "output-dir").resolve()
    trace_dir = output_dir / "trace"
    try:
        if output_dir.exists():
            raise WorkloadManifestError(
                f"refusing to reuse existing output directory: {output_dir}"
            )

        manifest = load_workload_manifest(manifest_path)
        request = manifest.to_request(
            manifest_path,
            output_dir,
            dynamorio_home_override=getattr(args, "dynamorio_home", None),
            client_path_override=getattr(args, "client", None),
        )
        validate_request_inputs(request)
        validate_output_layout(request, output_dir)

        try:
            output_dir.mkdir(parents=True, exist_ok=False)
        except OSError as error:
            raise WorkloadManifestError(
                f"cannot create output directory {output_dir}: {error}"
            ) from error

        result = analyze_workload(request)
        report = build_hybrid_workflow_report(result)

        _write_new(
            output_dir / "static-certificate.json",
            result.static_analysis.legacy_certificate.model_dump_json(indent=2),
        )
        _write_new(
            output_dir / "dynamic-certificate.json",
            result.dynamic_evidence.certificate.model_dump_json(indent=2),
        )
        save_hybrid_workflow_report(report, output_dir / "hybrid-workflow-report.json")

        print(f"Static verdict: {result.static_analysis.legacy_certificate.verdict.value}")
        print(f"Dynamic verdict: {result.dynamic_evidence.certificate.verdict.value}")
        if result.diagnostics_unavailable_reason is not None:
            print(f"Diagnostics unavailable: {result.diagnostics_unavailable_reason}")
        print("No combined verdict is defined.")
        print(f"Hybrid report: {output_dir / 'hybrid-workflow-report.json'}")
        print(f"Trace artifacts: {trace_dir}")
        return 0
    except (CaptureError, HybridReportError, HybridWorkflowError, OSError, ValueError) as error:
        print(f"bmo-check hybrid: error: {error}", file=sys.stderr)
        if trace_dir.exists():
            print(f"Partial trace artifacts were preserved at: {trace_dir}", file=sys.stderr)
        return 3


__all__ = ["run_hybrid"]
