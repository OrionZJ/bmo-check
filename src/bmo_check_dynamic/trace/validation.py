from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bmo_check_dynamic.model import TraceManifest

from .format import TraceFormatError, TraceReader, event_files


@dataclass(frozen=True, slots=True)
class TraceValidation:
    valid: bool
    event_count: int
    thread_ids: tuple[int, ...]
    reasons: tuple[str, ...]


def validate_trace(trace_dir: Path) -> TraceValidation:
    reasons: list[str] = []
    event_count = 0
    thread_ids: set[int] = set()
    manifest_path = trace_dir / "manifest.json"
    if not manifest_path.is_file():
        return TraceValidation(False, 0, (), ("missing manifest.json",))
    try:
        manifest = TraceManifest.load(manifest_path)
    except (OSError, ValueError) as error:
        return TraceValidation(False, 0, (), (f"invalid manifest: {error}",))
    if not manifest.complete:
        reasons.append("trace did not reach a clean process exit")
    if manifest.dropped_events:
        reasons.append(f"trace dropped {manifest.dropped_events} events")
    files = event_files(trace_dir)
    if not files:
        reasons.append("trace contains no event files")
    try:
        for path in files:
            previous: dict[int, int] = {}
            for event in TraceReader(path):
                event_count += 1
                thread_ids.add(event.thread_id)
                old = previous.get(event.thread_id)
                if old is not None and event.sequence <= old:
                    reasons.append(
                        f"non-monotonic sequence for thread {event.thread_id} in {path.name}"
                    )
                previous[event.thread_id] = event.sequence
                if event.kind.is_memory and event.size <= 0:
                    reasons.append(f"zero-width memory event {event.event_id}")
    except (OSError, TraceFormatError) as error:
        reasons.append(str(error))
    return TraceValidation(not reasons, event_count, tuple(sorted(thread_ids)), tuple(reasons))
