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


HASH = "a" * 64
CONFIG = "b" * 64


def _subject() -> TraceId:
    module = ModuleId.from_parts(HASH, "executable")
    return TraceId.from_parts("1.2", HASH, (module,), ("complete",), "c" * 64)


def _layers() -> tuple[TraceLayerRecord, ...]:
    return tuple(
        TraceLayerRecord(layer, 1, HASH)
        for layer in TraceImportLayer
    )


def _complete(subject: TraceId | None = None) -> TraceImportLedger:
    return TraceImportLedger(
        subject=subject or _subject(),
        trace_digest=HASH,
        schema_version="trace-1.2",
        config_digest=CONFIG,
        state=TraceImportState.COMPLETE,
        chunks=(TraceChunkRecord("events-1.bin", HASH, 32, 1),),
        layers=_layers(),
    )


def test_complete_import_requires_every_layer_and_a_raw_chunk() -> None:
    ledger = _complete()

    assert ledger.missing_layers == ()
    assert ledger.matches(
        subject=ledger.subject,
        schema_version="trace-1.2",
        config_digest=CONFIG,
    )

    with pytest.raises(ValueError, match="every required layer"):
        TraceImportLedger(
            subject=ledger.subject,
            trace_digest=HASH,
            schema_version="trace-1.2",
            config_digest=CONFIG,
            state=TraceImportState.COMPLETE,
            chunks=ledger.chunks,
            layers=ledger.layers[:-1],
        )

    with pytest.raises(ValueError, match="at least one raw chunk"):
        TraceImportLedger(
            subject=ledger.subject,
            trace_digest=HASH,
            schema_version="trace-1.2",
            config_digest=CONFIG,
            state=TraceImportState.COMPLETE,
            chunks=(),
            layers=ledger.layers,
        )


def test_incomplete_import_exposes_missing_layers_and_reason() -> None:
    subject = _subject()
    ledger = TraceImportLedger(
        subject=subject,
        trace_digest=HASH,
        schema_version="trace-1.2",
        config_digest=CONFIG,
        state=TraceImportState.INCOMPLETE,
        chunks=(TraceChunkRecord("events-1.bin", HASH, 32, 1),),
        layers=(TraceLayerRecord(TraceImportLayer.MANIFEST, 1, HASH),),
        reason="decoded event import stopped",
    )

    assert ledger.missing_layers == (
        TraceImportLayer.RAW_CHUNK,
        TraceImportLayer.DECODED_EVENT,
        TraceImportLayer.OBJECT_INVENTORY,
        TraceImportLayer.THREAD_INVENTORY,
    )
    assert not ledger.matches(
        subject=subject,
        schema_version="trace-1.2",
        config_digest=CONFIG,
    )


def test_store_reuse_requires_exact_subject_schema_and_config() -> None:
    ledger = _complete()
    other = _complete(
        TraceId.from_parts("1.2", HASH, (), ("other",), "d" * 64)
    )

    assert not ledger.matches(
        subject=other.subject,
        schema_version="trace-1.2",
        config_digest=CONFIG,
    )
    assert not ledger.matches(
        subject=ledger.subject,
        schema_version="trace-1.3",
        config_digest=CONFIG,
    )
    assert not ledger.matches(
        subject=ledger.subject,
        schema_version="trace-1.2",
        config_digest=HASH,
    )


def test_duplicate_chunk_or_layer_identity_is_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate names"):
        TraceImportLedger(
            subject=_subject(),
            trace_digest=HASH,
            schema_version="trace-1.2",
            config_digest=CONFIG,
            state=TraceImportState.CREATING,
            chunks=(
                TraceChunkRecord("events-1.bin", HASH, 1, 0),
                TraceChunkRecord("events-1.bin", "c" * 64, 1, 0),
            ),
        )

    with pytest.raises(ValueError, match="duplicate identities"):
        TraceImportLedger(
            subject=_subject(),
            trace_digest=HASH,
            schema_version="trace-1.2",
            config_digest=CONFIG,
            state=TraceImportState.CREATING,
            layers=(
                TraceLayerRecord(TraceImportLayer.MANIFEST, 1, HASH),
                TraceLayerRecord(TraceImportLayer.MANIFEST, 1, "c" * 64),
            ),
        )

