from __future__ import annotations

import pytest
from pathlib import Path

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
from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.trace import TraceReader, TraceWriter, trace_digest


HASH = "a" * 64
CONFIG = "b" * 64


def _subject(marker: str = "complete") -> TraceId:
    module = ModuleId.from_parts(HASH, "executable")
    return TraceId.from_parts("1.2", HASH, (module,), (marker,), "c" * 64)


def _creating(
    subject: TraceId | None = None,
    *,
    digest: str = HASH,
) -> TraceImportLedger:
    return TraceImportLedger(
        subject=subject or _subject(),
        trace_digest=digest,
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


def _write_trace(trace_manifest, tmp_path: Path, *, truncated: bool = False) -> tuple[Path, str]:
    trace_dir = tmp_path / ("truncated" if truncated else "complete")
    trace_manifest(trace_dir)
    event_path = trace_dir / "events-1.bin"
    with TraceWriter(event_path) as writer:
        writer.write(TraceEvent(1, 1, 1, 0x10, EventKind.LOAD, 0x4000, 4))
    if truncated:
        event_path.write_bytes(event_path.read_bytes()[:-1])
    return trace_dir, trace_digest(trace_dir)


def test_complete_import_recomputes_manifest_chunks_events_objects_and_threads(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir, digest = _write_trace(trace_manifest, tmp_path)
    subject = _subject("verified")
    with TraceStore(tmp_path / "verified.duckdb") as store:
        store.begin_import(_creating(subject, digest=digest))
        store.add_events(
            TraceReader(trace_dir / "events-1.bin"),
            max_pages_per_access=16,
            batch_size=8,
        )
        store.materialize_objects()

        ledger = store.complete_import(trace_dir)

        assert ledger.state is TraceImportState.COMPLETE
        assert ledger.missing_layers == ()
        assert ledger.layers[-1].layer is TraceImportLayer.THREAD_INVENTORY
        assert ledger.layers[-1].count == 1


def test_chunk_tampering_marks_import_incomplete_before_completion(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir, digest = _write_trace(trace_manifest, tmp_path)
    event_path = trace_dir / "events-1.bin"
    with TraceStore(tmp_path / "tampered.duckdb") as store:
        store.begin_import(_creating(_subject("tampered"), digest=digest))
        store.add_events(
            TraceReader(event_path), max_pages_per_access=16, batch_size=8
        )
        store.materialize_objects()
        event_path.write_bytes(event_path.read_bytes() + b"tampered")

        with pytest.raises(TraceStoreError, match="trace digest differs"):
            store.complete_import(trace_dir)
        ledger = store.import_ledger()
        assert ledger is not None
        assert ledger.state is TraceImportState.INCOMPLETE


def test_truncated_chunk_cannot_be_completed(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir, digest = _write_trace(trace_manifest, tmp_path, truncated=True)
    with TraceStore(tmp_path / "truncated.duckdb") as store:
        store.begin_import(_creating(_subject("truncated"), digest=digest))
        with pytest.raises(TraceStoreError):
            store.complete_import(trace_dir)
        ledger = store.import_ledger()
        assert ledger is not None
        assert ledger.state is TraceImportState.INCOMPLETE


def test_producer_layer_claim_is_checked_against_recomputed_content(
    trace_manifest, tmp_path: Path
) -> None:
    trace_dir, digest = _write_trace(trace_manifest, tmp_path)
    subject = _subject("producer-claim")
    bogus = TraceImportLedger(
        subject=subject,
        trace_digest=digest,
        schema_version="trace-1.2",
        config_digest=CONFIG,
        state=TraceImportState.CREATING,
        chunks=(TraceChunkRecord("events-1.bin", "d" * 64, 1, 1),),
        layers=tuple(TraceLayerRecord(layer, 999, "d" * 64) for layer in TraceImportLayer),
    )
    with TraceStore(tmp_path / "producer-claim.duckdb") as store:
        store.begin_import(_creating(subject, digest=digest))
        store.record_import_layers(bogus)
        store.add_events(
            TraceReader(trace_dir / "events-1.bin"),
            max_pages_per_access=16,
            batch_size=8,
        )
        store.materialize_objects()

        with pytest.raises(TraceStoreError, match="ledger differs"):
            store.complete_import(trace_dir)
