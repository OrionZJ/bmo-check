from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bmo_check_dynamic.model import EventFlags, TraceManifest

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
    if manifest.exit_code not in (None, 0):
        add_reason(f"traced program exited with status {manifest.exit_code}")
    if manifest.dropped_events:
        add_reason(f"trace dropped {manifest.dropped_events} events")
        for name, count in sorted(manifest.dropped_by_reason.items()):
            add_reason(f"trace drop reason {name}: {count}")
    files = event_files(trace_dir)
    if not files:
        add_reason("trace contains no event files")
    # 每个线程只保留最后序号；跨文件重复不能逃过检查，也无需缓存所有 event_id。
    previous: dict[int, int] = {}
    known_flags = sum(int(flag) for flag in EventFlags)
    for path in files:
        file_event_count = 0
        try:
            for event in TraceReader(path):
                event_count += 1
                file_event_count += 1
                thread_ids.add(event.thread_id)
                old = previous.get(event.thread_id)
                expected = 1 if old is None else old + 1
                if event.sequence != expected:
                    add_reason(
                        f"sequence gap or duplicate for thread {event.thread_id} "
                        f"in {path.name}: expected {expected}, got {event.sequence}"
                    )
                previous[event.thread_id] = event.sequence
                if int(event.flags) & ~known_flags:
                    add_reason(f"unsupported flags for {event.event_id}: {int(event.flags)}")
                if event.kind.is_memory and event.size <= 0:
                    add_reason(f"zero-width memory event {event.event_id}")
                if event.kind.is_memory and event.end_address > 1 << 64:
                    add_reason(f"memory range overflows address space: {event.event_id}")
            if not file_event_count:
                add_reason(f"empty event file: {path.name}")
        except (OSError, TraceFormatError) as error:
            # 一个坏文件不应掩盖其他线程也损坏的事实。
            add_reason(str(error))
    if omitted_reasons:
        reasons.append(f"trace validation omitted {omitted_reasons} additional errors")
    return TraceValidation(not reasons, event_count, tuple(sorted(thread_ids)), tuple(reasons))
