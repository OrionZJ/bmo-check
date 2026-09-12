"""Temporary one-way adapters from legacy static reports to canonical evidence."""

from .evidence import (
    LegacyEvidenceLink,
    LegacyFactType,
    StaticAdapterError,
    StaticEvidenceSnapshot,
    adapt_static_report,
    legacy_unknown_key,
)
from .diagnostic_snapshot import (
    DiagnosticSnapshotAdapterError,
    static_snapshot_from_certificate,
)

__all__ = [
    "LegacyEvidenceLink",
    "LegacyFactType",
    "StaticAdapterError",
    "StaticEvidenceSnapshot",
    "adapt_static_report",
    "legacy_unknown_key",
    "DiagnosticSnapshotAdapterError",
    "static_snapshot_from_certificate",
]
