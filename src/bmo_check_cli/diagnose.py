"""``bmo-check diagnose`` command adapter."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from bmo_check_core import CertificateVerdict, EvidenceId
from bmo_check_diagnostics import (
    build_affine_validation_report,
    build_diagnostic_report,
    site_filter_for_affine_unknowns,
)
from bmo_check_diagnostics.affine import save_affine_report
from bmo_check_diagnostics.serialization import (
    DiagnosticSerializationError,
    load_snapshot,
    save_report,
    sha256_file,
)


_EXIT_CODES = {
    CertificateVerdict.SAFE: 0,
    CertificateVerdict.COUNTEREXAMPLE: 1,
    CertificateVerdict.UNKNOWN: 2,
}


def _path(value: object, name: str) -> Path:
    if not isinstance(value, Path):
        raise DiagnosticSerializationError(f"{name} must be a path")
    return value


def _resolve_snapshot(args: Namespace, positional: str, option: str) -> Path:
    value = getattr(args, positional, None) or getattr(args, option, None)
    if value is None:
        raise DiagnosticSerializationError(
            f"diagnose requires {positional.replace('_', '-')} snapshot"
        )
    return _path(value, positional)


def _resolve_dynamic_input(args: Namespace) -> tuple[Path | None, Path | None]:
    snapshot_value = getattr(args, "dynamic_snapshot", None) or getattr(
        args, "dynamic_snapshot_option", None
    )
    trace_value = getattr(args, "trace_dir", None)
    if snapshot_value is not None and trace_value is not None:
        raise DiagnosticSerializationError(
            "diagnose accepts either a dynamic snapshot or --trace, not both"
        )
    if snapshot_value is None and trace_value is None:
        raise DiagnosticSerializationError(
            "diagnose requires dynamic snapshot or --trace"
        )
    return (
        (_path(snapshot_value, "dynamic_snapshot") if snapshot_value is not None else None),
        (_path(trace_value, "trace_dir") if trace_value is not None else None),
    )


def _artifact_hash(args: Namespace, name: str, fallback: Path) -> str:
    value = getattr(args, name, None)
    path = _path(value, name) if value is not None else fallback
    return sha256_file(path)


def _ids(values: object) -> tuple[EvidenceId, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        raise DiagnosticSerializationError("unknown-id values must be an array")
    result: list[EvidenceId] = []
    for value in values:
        try:
            result.append(EvidenceId.from_value(str(value)))
        except ValueError as error:
            raise DiagnosticSerializationError(f"invalid --unknown-id: {value}") from error
    return tuple(result)


def run_diagnose(args: Namespace) -> int:
    """读取两个 typed snapshot，写出报告并返回原始静态 verdict 的退出码。"""

    static_path = _resolve_snapshot(args, "static_snapshot", "static_snapshot_option")
    dynamic_path, trace_dir = _resolve_dynamic_input(args)
    output = _path(getattr(args, "output", None), "output")
    static = load_snapshot(static_path, expected_kind="static")
    if dynamic_path is not None:
        dynamic = load_snapshot(dynamic_path, expected_kind="dynamic")
        trace_artifact = dynamic_path
    else:
        from bmo_check_dynamic.adapters import dynamic_snapshot_from_trace
        from bmo_check_dynamic.trace import trace_digest

        assert trace_dir is not None
        site_filter = (
            site_filter_for_affine_unknowns(static)
            if getattr(args, "affine_output", None) is not None
            else None
        )
        dynamic = dynamic_snapshot_from_trace(
            trace_dir,
            max_sites=int(getattr(args, "max_snapshot_sites", 100_000)),
            site_filter=site_filter or None,
        )
        trace_artifact = trace_dir / "manifest.json"
    static_id = getattr(args, "static_certificate_id", None)
    trace_id = getattr(args, "trace_certificate_id", None)
    report = build_diagnostic_report(
        static,
        dynamic,
        static_certificate_id=static_id,
        trace_certificate_id=trace_id,
        static_certificate_sha256=_artifact_hash(
            args, "static_certificate", static_path
        ),
        trace_certificate_sha256=(
            _artifact_hash(args, "trace_certificate", trace_artifact)
            if dynamic_path is not None
            else (
                trace_digest(trace_dir)
                if getattr(args, "trace_certificate", None) is None
                else _artifact_hash(args, "trace_certificate", trace_artifact)
            )
        ),
        selected_unknown_ids=_ids(getattr(args, "unknown_id", ())) or None,
    )
    save_report(report, output)
    affine_output = getattr(args, "affine_output", None)
    if affine_output is not None:
        affine_report = build_affine_validation_report(static, dynamic)
        save_affine_report(affine_report, _path(affine_output, "affine_output"))
        print(
            "Observed affine coverage: "
            f"affine={affine_report.affine_unknown_count} "
            f"exercised={affine_report.exercised_count} "
            f"ambiguous={affine_report.ambiguous_count} "
            f"not-executed={affine_report.not_executed_count} "
            f"unmatched={affine_report.unmatched_count}"
        )
    print(
        f"Diagnostic report: static={report.static_verdict.value} "
        f"exact={report.coverage.exact_count} "
        f"ambiguous={report.coverage.ambiguous_count} "
        f"unmatched={report.coverage.unmatched_count}"
    )
    print(report.statement)
    return _EXIT_CODES[report.static_verdict]


__all__ = ["run_diagnose"]
