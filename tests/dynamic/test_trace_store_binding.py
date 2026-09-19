from __future__ import annotations

import pytest

from bmo_check_core import (
    ModuleId,
    TraceChunkRecord,
    TraceId,
    TraceImportLayer,
    TraceImportLedger,
    TraceImportState,
    TraceLayerRecord,
)
from bmo_check_dynamic.storage import TraceStore, TraceStoreError


HASH = "a" * 64
CONFIG = "b" * 64


def _subject(marker: str = "complete") -> TraceId:
    module = ModuleId.from_parts(HASH, "executable")
    return TraceId.from_parts("1.2", HASH, (module,), (marker,), "c" * 64)


def _creating(subject: TraceId | None = None) -> TraceImportLedger:
    return TraceImportLedger(
        subject=subject or _subject(),
        trace_digest=HASH,
        schema_version="trace-1.2",
        config_digest=CONFIG,
        state=TraceImportState.CREATING,
    )


def _layered(subject: TraceId) -> TraceImportLedger:
    return TraceImportLedger(
        subject=subject,
        trace_digest=HASH,
        schema_version="trace-1.2",
        config_digest=CONFIG,
        state=TraceImportState.CREATING,
        chunks=(TraceChunkRecord("events-1.bin", HASH, 32, 1),),
        layers=tuple(TraceLayerRecord(layer, 1, HASH) for layer in TraceImportLayer),
    )


def test_store_binds_one_subject_and_reads_partial_ledger(tmp_path) -> None:
    path = tmp_path / "trace.duckdb"
    subject = _subject()
    with TraceStore(path) as store:
        store.begin_import(_creating(subject))
        store.record_import_layers(_layered(subject))
        ledger = store.import_ledger()
        assert ledger is not None
        assert ledger.subject == subject
        assert ledger.state is TraceImportState.CREATING
        assert ledger.missing_layers == ()


def test_store_rejects_mixed_subject_and_duplicate_active_import(tmp_path) -> None:
    path = tmp_path / "trace.duckdb"
    with TraceStore(path) as store:
        store.begin_import(_creating())
        with pytest.raises(TraceStoreError, match="subject/schema/config"):
            store.begin_import(_creating(_subject("other")))
        with pytest.raises(TraceStoreError, match="already has an import"):
            store.begin_import(_creating())


def test_legacy_unbound_store_is_explicitly_not_an_import(tmp_path) -> None:
    with TraceStore(tmp_path / "legacy.duckdb") as store:
        assert store.import_ledger() is None
        with pytest.raises(TraceStoreError, match="must start in CREATING"):
            store.begin_import(
                TraceImportLedger(
                    subject=_subject(),
                    trace_digest=HASH,
                    schema_version="trace-1.2",
                    config_digest=CONFIG,
                    state=TraceImportState.COMPLETE,
                    chunks=(TraceChunkRecord("events-1.bin", HASH, 32, 1),),
                    layers=tuple(
                        TraceLayerRecord(layer, 1, HASH) for layer in TraceImportLayer
                    ),
                )
            )

