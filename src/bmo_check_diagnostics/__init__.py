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
from .classification import (
    ClassificationError,
    ClassificationResult,
    DiagnosticRootCause,
    ROOT_CAUSE_REGISTRY,
    RootCauseDescriptor,
    classify_unknown,
    classify_unknowns,
    validate_root_cause_registry,
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
    "ClassificationError",
    "ClassificationResult",
    "DiagnosticRootCause",
    "ROOT_CAUSE_REGISTRY",
    "RootCauseDescriptor",
    "classify_unknown",
    "classify_unknowns",
    "validate_root_cause_registry",
    "CertificateIdentity",
    "DiagnosticCoverage",
    "DiagnosticReport",
    "DiagnosticReportError",
    "build_diagnostic_report",
    "diagnose",
]
