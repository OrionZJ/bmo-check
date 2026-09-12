"""Dynamic route adapters into canonical core snapshots."""

from .diagnostic_snapshot import (
    DynamicSnapshotAdapterError,
    dynamic_snapshot_from_trace,
)

__all__ = [
    "DynamicSnapshotAdapterError",
    "dynamic_snapshot_from_trace",
]
