from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


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


def unsupported_syscall_effects(
    observations: tuple[SyscallObservation, ...],
    lifecycle: tuple[tuple[int, int, int], ...],
    stacks: dict[int, tuple[int, int]],
    captured_munmaps: set[tuple[int, int, int]],
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
            captured_munmaps,
        ):
            continue
        phase = "concurrent" if len(active) > 1 else "serial"
        unsupported[f"{phase} syscall {call.number} has an unsupported memory effect"] += 1
    return tuple(
        f"{reason} ({count} call{'s' if count != 1 else ''})"
        for reason, count in sorted(unsupported.items())
    )


def _effect_is_closed(
    call: SyscallObservation,
    concurrent: bool,
    stack: tuple[int, int] | None,
    captured_munmaps: set[tuple[int, int, int]],
) -> bool:
    number = call.number
    args = call.arguments
    # 没有其他 app thread 存活时，内核 effect 只形成后续轨迹的初始/最终状态。
    # 这些字节不参与跨线程内存序环。
    if not concurrent:
        return True
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
    # munmap 只在对象生命周期已由 drwrap 记录时关闭。否则地址复用
    # 可能把两代对象误连到同一个 coherence 空间。
    if number == 11:
        return (
            _succeeded(call.result)
            and (call.thread_id, args[0], args[1]) in captured_munmaps
        )
    # signal mask 是线程状态。指针只能为 NULL 或指向本线程 stack。
    if number == 14:
        length = args[3]
        return _local_or_null(args[1], length, stack) and _local_or_null(
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
    # 成功的 WAIT_BITSET/WAIT_PRIVATE 只比较同步字，TraceStore 已把它
    # 物化为 FUTEX_WAIT read-from 事件；WAKE、失败 wait 和其他 op 仍需
    # 配对信息，不能只凭 syscall 编号放行。
    if number == 202:
        operation = args[1]
        return operation in {0x80, 0x81, 0x108, 0x109} and call.result == 0
    # futex 及并发 I/O 仍可以参与通信环，本阶段不推测它们的排序。
    return False


def _local_or_null(address: int, size: int, stack: tuple[int, int] | None) -> bool:
    if address == 0:
        return True
    if stack is None or size < 0:
        return False
    base, length = stack
    return base <= address and address + size <= base + length


def _succeeded(result: int | None) -> bool:
    if result is None:
        return False
    return result < (1 << 63)
