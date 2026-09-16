from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Iterable


LINUX_PATH_MAX = 4096
# 当前动态主线只接受 Linux x86-64，普通页的大小固定为 4 KiB。
LINUX_X86_64_PAGE_SIZE = 4096
_ADDRESS_LIMIT = 1 << 64


@dataclass(frozen=True, slots=True)
class SyscallObservation:
    # thread_id 用于查找该线程的 stack/TLS 范围。
    thread_id: int
    # ticket 把 syscall enter 放进线程生命周期，不给普通访存添加顺序。
    ticket: int
    # number 是 Linux x86-64 syscall 编号。
    number: int
    # arguments 保留六个 64 位原始参数，effect 表只解释已支持项。
    arguments: tuple[int, ...]
    # result 保留原始寄存器值；不返回的 exit syscall 为 None。
    result: int | None
    # exit_ticket 只界定系统调用的生命周期，不给普通访存排序。
    exit_ticket: int | None = None


@dataclass(frozen=True, slots=True)
class SyscallBufferAccess:
    # thread_id 用于排除系统调用所属线程本身。
    thread_id: int
    # ticket 标识该次系统调用，避免同线程重复调用共用结论。
    ticket: int
    # address/size 是按 Linux syscall ABI 得到的保守用户缓冲区范围。
    address: int
    size: int
    # kernel_writes 表示内核会改写用户字节，否则内核只读取这些字节。
    kernel_writes: bool

    @property
    def end_address(self) -> int:
        return self.address + self.size


@dataclass(frozen=True, slots=True)
class SyscallBufferProof:
    # closed_calls 只对本次完整 trace 成立，不是静态 NoAlias 事实。
    closed_calls: frozenset[tuple[int, int]]
    # conflicting_calls 保存至少一个可能的跨线程缓冲区交叠。
    conflicting_calls: frozenset[tuple[int, int]]
    # limited_calls 表示证明扫描触及页数预算，不能把它当成无冲突。
    limited_calls: frozenset[tuple[int, int]]


class _MappingOperationKind(Enum):
    # 成功 mmap 后，这段虚拟地址从 syscall 返回时开始可用于后续证明。
    MAP = 1
    # 成功 munmap 后，这段虚拟地址从 syscall 返回时不再属于旧映射。
    UNMAP = 2


@dataclass(frozen=True, slots=True)
class _MappingOperation:
    # kind 区分建立映射和移除映射，回放时两者对活动范围的影响相反。
    kind: _MappingOperationKind
    # thread_id 和 entry_ticket 唯一标识这次 syscall，避免把调用和自己比较。
    thread_id: int
    entry_ticket: int
    # exit_ticket 是 syscall 返回位置；只有完成的操作才能改变后续映射状态。
    exit_ticket: int
    # start/end 是按 x86-64 Linux 4 KiB 页边界扩展后的半开地址范围。
    start: int
    end: int
    # replaces_existing 表示成功 MAP_FIXED 会先替换范围内的旧映射。
    replaces_existing: bool = False


def unsupported_syscall_effects(
    observations: tuple[SyscallObservation, ...],
    lifecycle: tuple[tuple[int, int, int], ...],
    stacks: dict[int, tuple[int, int]],
    closed_munmaps: frozenset[tuple[int, int]] = frozenset(),
    read_only_ranges: tuple[tuple[int, int], ...] = (),
    buffer_proof: SyscallBufferProof | None = None,
) -> tuple[str, ...]:
    """只关闭已证明的 syscall effect；其他调用保持 UNKNOWN。"""

    active: set[int] = set()
    timeline = [(*item, None) for item in lifecycle]
    timeline.extend((call.ticket, 33, call.thread_id, call) for call in observations)
    unsupported: Counter[str] = Counter()
    for _ticket, kind, thread_id, call in sorted(timeline, key=lambda item: item[0]):
        if kind == 10:
            active.add(thread_id)
            continue
        if kind == 11:
            active.discard(thread_id)
            continue
        assert call is not None
        if len(call.arguments) != 6:
            unsupported[f"syscall {call.number} is missing captured arguments"] += 1
            continue
        if call.result is None and call.number not in {60, 231}:
            unsupported[f"syscall {call.number} is missing its return record"] += 1
            continue
        if _effect_is_closed(
            call,
            len(active) > 1,
            stacks.get(thread_id),
            closed_munmaps,
            read_only_ranges,
            buffer_proof,
        ):
            continue
        phase = "concurrent" if len(active) > 1 else "serial"
        call_key = (call.thread_id, call.ticket)
        if buffer_proof is not None and call_key in buffer_proof.conflicting_calls:
            reason = f"{phase} syscall {call.number} user buffer may overlap another thread"
        elif buffer_proof is not None and call_key in buffer_proof.limited_calls:
            reason = f"{phase} syscall {call.number} buffer proof exceeded its page budget"
        else:
            reason = f"{phase} syscall {call.number} has an unsupported memory effect"
        unsupported[reason] += 1
    return tuple(
        f"{reason} ({count} call{'s' if count != 1 else ''})"
        for reason, count in sorted(unsupported.items())
    )


def _effect_is_closed(
    call: SyscallObservation,
    concurrent: bool,
    stack: tuple[int, int] | None,
    closed_munmaps: frozenset[tuple[int, int]],
    read_only_ranges: tuple[tuple[int, int], ...],
    buffer_proof: SyscallBufferProof | None,
) -> bool:
    number = call.number
    args = call.arguments
    # 没有其他 app thread 存活时，内核 effect 只形成后续轨迹的初始/最终状态。
    # 这些字节不参与跨线程内存序环。
    if not concurrent:
        return True
    # 这些 syscall 会读写用户缓冲区。只有完整 trace 的地址检查证明没有
    # 跨线程冲突后才能把它们从 guest 通信图中略过。
    if number in {0, 1, 257}:
        return (
            buffer_proof is not None
            and (call.thread_id, call.ticket) in buffer_proof.closed_calls
        )
    # close/exit 不读写用户字节；线程退出由 THREAD_END 另外记录。
    if number in {3, 60, 231}:
        return True
    # 私有、非固定映射创建新对象，不会覆盖其他线程现有字节。
    if number == 9:
        flags = args[3]
        map_private = bool(flags & 0x02)
        map_fixed = bool(flags & 0x10)
        return map_private and not map_fixed and _succeeded(call.result)
    # mprotect 不改写字节；增加执行权限可能引入 JIT，仍然拒绝。
    if number == 10:
        prot_exec = bool(args[2] & 0x04)
        return not prot_exec and _succeeded(call.result)
    # munmap 必须命中仍活动的完整 mapping；部分解除映射暂不切分对象。
    if number == 11:
        return _succeeded(call.result) and (call.thread_id, call.ticket) in closed_munmaps
    # signal mask 的 set 只读；oldset 会被内核写入，必须留在本线程 stack。
    if number == 14:
        length = args[3]
        if call.result != 0 or length != 8:
            return False
        set_is_local = _local_or_null(args[1], length, stack)
        set_is_read_only = _covered_by_read_only_range(
            args[1], length, read_only_ranges
        )
        return (set_is_local or set_is_read_only) and _local_or_null(
            args[2], length, stack
        )
    # ARCH_SET_FS/GS 只更新当前线程的 TLS base。GET 只允许写回本线程 stack。
    if number == 158:
        operation = args[0]
        if operation in {0x1001, 0x1002}:
            return True
        if operation in {0x1003, 0x1004}:
            return _local_or_null(args[1], 8, stack)
        return False
    # Linux 要求 rseq area 按线程注册；它是内核与当前线程的 TLS 契约。
    if number == 334:
        return True
    # clone3 在新线程可运行前读完参数。参数必须留在创建者 stack。
    if number == 435:
        return _local_or_null(args[0], args[1], stack) and args[0] != 0
    # WAIT/WAIT_BITSET 成功时只比较同步字，TraceStore 已把它物化为
    # FUTEX_WAIT read-from 事件。WAKE 只操作内核等待队列，不读写用户字节；
    # REQUEUE、PI 和未知 op 仍需额外配对信息，不能只凭 syscall 编号放行。
    if number == 202:
        base_operation = args[1] & ~(0x80 | 0x100)
        if base_operation in {0, 9}:
            return call.result == 0
        if base_operation in {1, 10}:
            return call.result is not None and call.result >= 0
        return False
    # 其他 futex 和未建模 syscall 仍可能读写共享状态，不能按编号放行。
    return False


def prove_syscall_buffer_disjointness(
    observations: tuple[SyscallObservation, ...],
    lifecycle: tuple[tuple[int, int, int], ...],
    memory_events: Iterable[tuple[int, int, int, int]],
    *,
    max_pages: int = 16_384,
) -> SyscallBufferProof:
    """只在本次 trace 的活跃线程中检查 syscall 缓冲区是否与访存相交。

    这个结果可关闭 trace-local syscall effect；它不能变成静态 NoAlias。
    """

    active_by_call = _active_threads_for_calls(observations, lifecycle)
    accesses: list[tuple[SyscallBufferAccess, frozenset[int]]] = []
    limited: set[tuple[int, int]] = set()
    page_index: dict[int, list[int]] = {}
    indexed_pages = 0

    for call in observations:
        key = (call.thread_id, call.ticket)
        active = active_by_call.get(key, frozenset())
        if len(active) <= 1 or call.number not in {0, 1, 257}:
            continue
        access = syscall_buffer_access(call)
        if access is None:
            continue
        if access.size == 0:
            accesses.append((access, frozenset()))
            continue
        page_first = access.address >> 12
        page_last = (access.end_address - 1) >> 12
        page_count = page_last - page_first + 1
        if page_count <= 0 or indexed_pages + page_count > max_pages:
            limited.add(key)
            continue
        index = len(accesses)
        accesses.append((access, frozenset(active - {call.thread_id})))
        for page in range(page_first, page_last + 1):
            page_index.setdefault(page, []).append(index)
        indexed_pages += page_count

    conflicts: set[tuple[int, int]] = set()
    # 两个并发 syscall 也可能直接共享缓冲区，不能只和已插桩的访存比较。
    for index, (left, left_threads) in enumerate(accesses):
        left_key = (left.thread_id, left.ticket)
        if left.size == 0:
            continue
        for right, right_threads in accesses[index + 1 :]:
            right_key = (right.thread_id, right.ticket)
            if left.thread_id == right.thread_id:
                continue
            if (
                right.thread_id not in left_threads
                and left.thread_id not in right_threads
            ):
                continue
            if left.kernel_writes or right.kernel_writes:
                if left.address < right.end_address and right.address < left.end_address:
                    conflicts.update((left_key, right_key))

    if not page_index:
        return SyscallBufferProof(
            closed_calls=frozenset(
                (access.thread_id, access.ticket)
                for access, _other_threads in accesses
                if access.size == 0
            ),
            conflicting_calls=frozenset(conflicts),
            limited_calls=frozenset(limited),
        )

    for thread_id, kind, address, size in memory_events:
        if size <= 0 or address < 0 or address + size > _ADDRESS_LIMIT:
            continue
        end_address = address + size
        first_page = address >> 12
        last_page = (end_address - 1) >> 12
        candidate_indices: set[int] = set()
        if last_page - first_page <= 64:
            for page in range(first_page, last_page + 1):
                candidate_indices.update(page_index.get(page, ()))
        else:
            # 超宽访存很少见；逐个比较少量 syscall 范围比展开数百万页安全。
            candidate_indices.update(range(len(accesses)))
        for index in candidate_indices:
            access, other_threads = accesses[index]
            key = (access.thread_id, access.ticket)
            if thread_id not in other_threads:
                continue
            if not access.kernel_writes and kind not in {2, 3}:
                continue
            if address < access.end_address and access.address < end_address:
                conflicts.add(key)

    checked = {
        (access.thread_id, access.ticket)
        for access, _other_threads in accesses
        if (access.thread_id, access.ticket) not in limited
    }
    return SyscallBufferProof(
        closed_calls=frozenset(checked - conflicts),
        conflicting_calls=frozenset(conflicts),
        limited_calls=frozenset(limited),
    )


def syscall_buffer_access(call: SyscallObservation) -> SyscallBufferAccess | None:
    """返回受支持的 syscall 用户缓冲区范围；无法界定时返回 None。"""

    if len(call.arguments) != 6:
        return None
    args = call.arguments
    if call.number == 0:
        requested = args[2]
        result = call.result
        if result is None:
            return None
        if result < _ADDRESS_LIMIT // 2:
            if result > requested:
                return None
            size = result
        else:
            # 错误返回仍可能在内核发现坏页前触碰缓冲区，用整个请求范围作上界。
            size = requested
        address = args[1]
        kernel_writes = True
    elif call.number == 1:
        address, size = args[1], args[2]
        kernel_writes = False
    elif call.number == 257:
        address, size = args[1], LINUX_PATH_MAX
        kernel_writes = False
    else:
        return None
    if size == 0:
        return SyscallBufferAccess(call.thread_id, call.ticket, address, 0, kernel_writes)
    if address == 0 or address + size > _ADDRESS_LIMIT:
        return None
    return SyscallBufferAccess(call.thread_id, call.ticket, address, size, kernel_writes)


def prove_active_munmaps(
    observations: tuple[SyscallObservation, ...],
) -> frozenset[tuple[int, int]]:
    """只关闭落在完整 trace 已知活动映射中的 munmap。"""

    operations = _mapping_operations(observations)
    unmaps = [
        operation
        for operation in operations
        if operation.kind is _MappingOperationKind.UNMAP
    ]
    proven: set[tuple[int, int]] = set()

    for candidate in unmaps:
        overlapping_in_flight = any(
            other != candidate
            and _operations_overlap(candidate, other)
            and _ranges_overlap(candidate.start, candidate.end, other.start, other.end)
            for other in operations
        )
        if overlapping_in_flight:
            continue

        completed = sorted(
            (operation for operation in operations if operation.exit_ticket < candidate.entry_ticket),
            key=lambda operation: operation.exit_ticket,
        )
        # 两个已完成的并发 syscall 若改动同一字节，返回 ticket 不能说明内核
        # 先后顺序。把交叠范围留作未知，后续即使地址复用也不据此闭合 munmap。
        ambiguous_ranges = [
            (max(left.start, right.start), min(left.end, right.end))
            for index, left in enumerate(completed)
            for right in completed[index + 1 :]
            if _operations_overlap(left, right)
            and _ranges_overlap(left.start, left.end, right.start, right.end)
        ]
        if any(
            _ranges_overlap(candidate.start, candidate.end, start, end)
            for start, end in ambiguous_ranges
        ):
            continue

        active_ranges: list[tuple[int, int]] = []
        for operation in completed:
            if operation.kind is _MappingOperationKind.UNMAP:
                active_ranges = _subtract_address_range(
                    active_ranges, operation.start, operation.end
                )
            else:
                if operation.replaces_existing:
                    active_ranges = _subtract_address_range(
                        active_ranges, operation.start, operation.end
                    )
                active_ranges.append((operation.start, operation.end))

        if _range_is_covered(active_ranges, candidate.start, candidate.end):
            proven.add((candidate.thread_id, candidate.entry_ticket))
    return frozenset(proven)


def _mapping_operations(
    observations: tuple[SyscallObservation, ...],
) -> list[_MappingOperation]:
    operations: list[_MappingOperation] = []
    for call in observations:
        if (
            len(call.arguments) != 6
            or not _succeeded(call.result)
            or call.exit_ticket is None
            or call.exit_ticket <= call.ticket
        ):
            continue
        if call.number == 9:
            address = call.result
            size = call.arguments[1]
            flags = call.arguments[3]
            # HugeTLB 使用另一种页粒度；本证明不猜测其映射范围。
            if flags & 0x00040000 or address % LINUX_X86_64_PAGE_SIZE:
                continue
            rounded = _page_rounded_range(address, size)
            if rounded is None:
                continue
            operations.append(
                _MappingOperation(
                    _MappingOperationKind.MAP,
                    call.thread_id,
                    call.ticket,
                    call.exit_ticket,
                    *rounded,
                    replaces_existing=bool(flags & 0x10),
                )
            )
        elif call.number == 11:
            address, size = call.arguments[:2]
            rounded = _page_rounded_range(address, size)
            if rounded is None or address % LINUX_X86_64_PAGE_SIZE:
                continue
            operations.append(
                _MappingOperation(
                    _MappingOperationKind.UNMAP,
                    call.thread_id,
                    call.ticket,
                    call.exit_ticket,
                    *rounded,
                )
            )
    return operations


def _page_rounded_range(address: int, size: int) -> tuple[int, int] | None:
    if size <= 0 or address < 0 or address + size > _ADDRESS_LIMIT:
        return None
    end = (address + size + LINUX_X86_64_PAGE_SIZE - 1) & -LINUX_X86_64_PAGE_SIZE
    if end > _ADDRESS_LIMIT:
        return None
    return address, end


def _operations_overlap(left: _MappingOperation, right: _MappingOperation) -> bool:
    return left.entry_ticket < right.exit_ticket and right.entry_ticket < left.exit_ticket


def _ranges_overlap(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start < right_end and right_start < left_end


def _range_is_covered(
    ranges: list[tuple[int, int]], start: int, end: int
) -> bool:
    cursor = start
    for range_start, range_end in sorted(ranges):
        if range_end <= cursor:
            continue
        if range_start > cursor:
            return False
        cursor = max(cursor, range_end)
        if cursor >= end:
            return True
    return False


def _subtract_address_range(
    ranges: list[tuple[int, int]], start: int, end: int
) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for range_start, range_end in ranges:
        if end <= range_start or range_end <= start:
            result.append((range_start, range_end))
            continue
        if range_start < start:
            result.append((range_start, start))
        if end < range_end:
            result.append((end, range_end))
    return result


def _active_threads_for_calls(
    observations: tuple[SyscallObservation, ...],
    lifecycle: tuple[tuple[int, int, int], ...],
) -> dict[tuple[int, int], frozenset[int]]:
    active: set[int] = set()
    timeline = [(*item, None) for item in lifecycle]
    timeline.extend((call.ticket, 33, call.thread_id, call) for call in observations)
    result: dict[tuple[int, int], frozenset[int]] = {}
    for _ticket, kind, thread_id, call in sorted(timeline, key=lambda item: item[0]):
        if kind == 10:
            active.add(thread_id)
        elif kind == 11:
            active.discard(thread_id)
        elif call is not None:
            result[(call.thread_id, call.ticket)] = frozenset(active)
    return result


def _local_or_null(address: int, size: int, stack: tuple[int, int] | None) -> bool:
    if address == 0:
        return True
    if stack is None or size < 0:
        return False
    base, length = stack
    return base <= address and address + size <= base + length


def _covered_by_read_only_range(
    address: int, size: int, ranges: tuple[tuple[int, int], ...]
) -> bool:
    return any(start <= address and address + size <= end for start, end in ranges)


def _succeeded(result: int | None) -> bool:
    if result is None:
        return False
    return result < (1 << 63)
