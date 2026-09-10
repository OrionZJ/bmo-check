"""Temporary one-way adapters from legacy static reports to canonical evidence."""

from .evidence import (
    LegacyEvidenceLink,
    LegacyFactType,
    StaticAdapterError,
    StaticEvidenceSnapshot,
    adapt_static_report,
)

__all__ = [
    "LegacyEvidenceLink",
    "LegacyFactType",
    "StaticAdapterError",
    "StaticEvidenceSnapshot",
    "adapt_static_report",
]
