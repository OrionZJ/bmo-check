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
    omitted_reasons = 0
    event_count = 0
    thread_ids: set[int] = set()

    def add_reason(reason: str) -> None:
        nonlocal omitted_reasons
        # 损坏的采集器可能连续生成数百万个同类错误。证书只需保留足够的
        # 定位样本和总数，不能让错误列表本身再次耗尽内存。
        if len(reasons) < 100:
            reasons.append(reason)
        else:
            omitted_reasons += 1

    manifest_path = trace_dir / "manifest.json"
    if not manifest_path.is_file():
        return TraceValidation(False, 0, (), ("missing manifest.json",))
    try:
        manifest = TraceManifest.load(manifest_path)
    except (OSError, ValueError) as error:
        return TraceValidation(False, 0, (), (f"invalid manifest: {error}",))
    if not manifest.complete:
        add_reason("trace did not reach a clean process exit")
    if manifest.dropped_events:
        add_reason(f"trace dropped {manifest.dropped_events} events")
        for name, count in sorted(manifest.dropped_by_reason.items()):
            add_reason(f"trace drop reason {name}: {count}")
    files = event_files(trace_dir)
    if not files:
        add_reason("trace contains no event files")
    try:
        for path in files:
            previous: dict[int, int] = {}
            for event in TraceReader(path):
                event_count += 1
                thread_ids.add(event.thread_id)
                old = previous.get(event.thread_id)
                if old is not None and event.sequence <= old:
                    add_reason(
                        f"non-monotonic sequence for thread {event.thread_id} in {path.name}"
                    )
                previous[event.thread_id] = event.sequence
                if event.kind.is_memory and event.size <= 0:
                    add_reason(f"zero-width memory event {event.event_id}")
    except (OSError, TraceFormatError) as error:
        add_reason(str(error))
    if omitted_reasons:
        reasons.append(f"trace validation omitted {omitted_reasons} additional errors")
    return TraceValidation(not reasons, event_count, tuple(sorted(thread_ids)), tuple(reasons))
