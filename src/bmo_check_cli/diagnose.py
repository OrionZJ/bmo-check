"""``bmo-check diagnose`` command adapter."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from bmo_check_core import CertificateVerdict, EvidenceId
from bmo_check_diagnostics import build_diagnostic_report
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
    dynamic_path = _resolve_snapshot(args, "dynamic_snapshot", "dynamic_snapshot_option")
    output = _path(getattr(args, "output", None), "output")
    static = load_snapshot(static_path, expected_kind="static")
    dynamic = load_snapshot(dynamic_path, expected_kind="dynamic")
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
        trace_certificate_sha256=_artifact_hash(
            args, "trace_certificate", dynamic_path
        ),
        selected_unknown_ids=_ids(getattr(args, "unknown_id", ())) or None,
    )
    save_report(report, output)
    print(
        f"Diagnostic report: static={report.static_verdict.value} "
        f"exact={report.coverage.exact_count} "
        f"ambiguous={report.coverage.ambiguous_count} "
        f"unmatched={report.coverage.unmatched_count}"
    )
    print(report.statement)
    return _EXIT_CODES[report.static_verdict]


__all__ = ["run_diagnose"]
