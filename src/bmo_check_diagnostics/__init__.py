"""只依赖 bmo_check_core 的诊断入口；不读取 static/dynamic 内部状态。"""

from bmo_check_core.diagnostics import (
    DynamicDiagnosticSnapshot,
    EvidenceSnapshot,
    SnapshotError,
    StaticDiagnosticSnapshot,
)
from .correlation import (
    CorrelationError,
    CorrelationKey,
    CorrelationRecord,
    CorrelationStatus,
    DiagnosticCorrelationReport,
    correlate_unknowns,
)
from .report import (
    CertificateIdentity,
    DiagnosticCoverage,
    DiagnosticReport,
    DiagnosticReportError,
    build_diagnostic_report,
    diagnose,
)

__all__ = [
    "DynamicDiagnosticSnapshot",
    "EvidenceSnapshot",
    "SnapshotError",
    "StaticDiagnosticSnapshot",
    "CorrelationError",
    "CorrelationKey",
    "CorrelationRecord",
    "CorrelationStatus",
    "DiagnosticCorrelationReport",
    "correlate_unknowns",
    "CertificateIdentity",
    "DiagnosticCoverage",
    "DiagnosticReport",
    "DiagnosticReportError",
    "build_diagnostic_report",
    "diagnose",
]
