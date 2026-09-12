from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bmo_check_dynamic.model import EventFlags, EventKind, TraceManifest

from .format import (
    HEADER,
    MAGIC,
    RECORD,
    VERSION_MAJOR,
    VERSION_MINOR,
    TraceFormatError,
    event_files,
)
from .syscalls import SyscallObservation, unsupported_syscall_effects


@dataclass(frozen=True, slots=True)
class TraceValidation:
    valid: bool
    # structurally_complete 只描述采集、格式和序号；模型不支持不等于 trace 截断。
    structurally_complete: bool
    event_count: int
    thread_ids: tuple[int, ...]
    reasons: tuple[str, ...]


def validate_trace(trace_dir: Path) -> TraceValidation:
    reasons: list[str] = []
    omitted_reasons = 0
    event_count = 0
    thread_ids: set[int] = set()
    syscall_count = 0
    saw_syscall_metadata = False
    syscall_observations: list[SyscallObservation] = []
    lifecycle: list[tuple[int, int, int]] = []
    stacks: dict[int, tuple[int, int]] = {}
    captured_munmaps: set[tuple[int, int, int]] = set()

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
        return TraceValidation(False, False, 0, (), ("missing manifest.json",))
    try:
        manifest = TraceManifest.load(manifest_path)
    except (OSError, ValueError) as error:
        return TraceValidation(False, False, 0, (), (f"invalid manifest: {error}",))
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
    known_kinds = {int(kind) for kind in EventKind}
    # 与 EventKind.is_memory 共用一个来源，避免新增长期内存事件时只更新一处。
    memory_kinds = {int(kind) for kind in EventKind if kind.is_memory}
    for path in files:
        file_event_count = 0
        pending_call: dict[str, object] | None = None

        def finish_pending(result: int | None = None) -> None:
            nonlocal pending_call
            if pending_call is None:
                return
            arguments = pending_call["arguments"]
            assert isinstance(arguments, dict)
            syscall_observations.append(
                SyscallObservation(
                    thread_id=int(pending_call["thread_id"]),
                    ticket=int(pending_call["ticket"]),
                    number=int(pending_call["number"]),
                    arguments=tuple(
                        int(arguments[index])
                        for index in range(6)
                        if index in arguments
                    ),
                    result=result,
                )
            )
            pending_call = None

        try:
            with path.open("rb") as stream:
                raw_header = stream.read(HEADER.size)
                if len(raw_header) != HEADER.size:
                    raise TraceFormatError(f"truncated trace header: {path}")
                magic, major, minor, record_size = HEADER.unpack(raw_header)
                if (
                    magic != MAGIC
                    or major != VERSION_MAJOR
                    or minor > VERSION_MINOR
                    or record_size != RECORD.size
                ):
                    raise TraceFormatError(f"unsupported trace format: {path}")
                # 校验只需原始字段。批量解包避免为亿级记录创建
                # TraceEvent/Pydantic 对象，但仍然逐条检查序号、标志和地址。
                while raw := stream.read(RECORD.size * 65536):
                    if len(raw) % RECORD.size:
                        raise TraceFormatError(f"truncated event record: {path}")
                    for record in RECORD.iter_unpack(raw):
                        kind, flags, thread_id, sequence = record[:4]
                        ticket, address, value, size, aux = (
                            record[4],
                            record[6],
                            record[7],
                            record[8],
                            record[9],
                        )
                        event_count += 1
                        file_event_count += 1
                        thread_ids.add(thread_id)
                        if kind not in known_kinds:
                            raise TraceFormatError(f"unknown event kind {kind}: {path}")
                        if kind == int(EventKind.SYSCALL):
                            syscall_count += 1
                            finish_pending()
                            pending_call = {
                                "thread_id": thread_id,
                                "ticket": ticket,
                                "number": aux,
                                "arguments": {},
                            }
                        elif kind == int(EventKind.SYSCALL_ARG):
                            saw_syscall_metadata = True
                            if (
                                pending_call is None
                                or int(pending_call["number"]) != value
                                or aux >= 6
                            ):
                                add_reason(
                                    f"orphan syscall argument for thread {thread_id} "
                                    f"in {path.name}"
                                )
                            else:
                                arguments = pending_call["arguments"]
                                assert isinstance(arguments, dict)
                                if aux in arguments:
                                    add_reason(
                                        f"duplicate syscall argument {aux} for thread "
                                        f"{thread_id} in {path.name}"
                                    )
                                arguments[aux] = address
                        elif kind == int(EventKind.SYSCALL_EXIT):
                            saw_syscall_metadata = True
                            if (
                                pending_call is None
                                or int(pending_call["number"]) != aux
                            ):
                                add_reason(
                                    f"orphan syscall return for thread {thread_id} "
                                    f"in {path.name}"
                                )
                            else:
                                finish_pending(value)
                        if kind in {
                            int(EventKind.THREAD_START),
                            int(EventKind.THREAD_END),
                        }:
                            lifecycle.append((ticket, kind, thread_id))
                        elif kind == int(EventKind.THREAD_STACK):
                            stacks[thread_id] = (address, size)
                        elif kind == int(EventKind.MUNMAP):
                            captured_munmaps.add((thread_id, address, size))
                        old = previous.get(thread_id)
                        expected = 1 if old is None else old + 1
                        if sequence != expected:
                            add_reason(
                                f"sequence gap or duplicate for thread {thread_id} "
                                f"in {path.name}: expected {expected}, got {sequence}"
                            )
                        previous[thread_id] = sequence
                        event_id = f"t{thread_id}:e{sequence}"
                        if flags & ~known_flags:
                            add_reason(f"unsupported flags for {event_id}: {flags}")
                        if flags & int(EventFlags.OPERAND_INDEX):
                            if kind not in memory_kinds:
                                add_reason(
                                    f"operand discriminator on non-memory event {event_id}"
                                )
                            elif minor < 2:
                                add_reason(
                                    f"operand discriminator requires trace format 1.2: {event_id}"
                                )
                        if kind in memory_kinds and size <= 0:
                            add_reason(f"zero-width memory event {event_id}")
                        if kind in memory_kinds and address + size > 1 << 64:
                            add_reason(
                                f"memory range overflows address space: {event_id}"
                            )
            if not file_event_count:
                add_reason(f"empty event file: {path.name}")
        except (OSError, TraceFormatError) as error:
            # 一个坏文件不应掩盖其他线程也损坏的事实。
            add_reason(str(error))
        finish_pending()
    structurally_complete = not reasons
    if len(thread_ids) > 1 and syscall_count:
        if not saw_syscall_metadata:
            add_reason(
                f"multi-thread trace contains {syscall_count} opaque syscall boundaries"
            )
        else:
            for reason in unsupported_syscall_effects(
                tuple(syscall_observations),
                tuple(lifecycle),
                stacks,
                captured_munmaps,
            ):
                add_reason(reason)
    if omitted_reasons:
        reasons.append(f"trace validation omitted {omitted_reasons} additional errors")
    return TraceValidation(
        not reasons,
        structurally_complete,
        event_count,
        tuple(sorted(thread_ids)),
        tuple(reasons),
    )
