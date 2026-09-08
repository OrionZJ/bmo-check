from __future__ import annotations

from bmo_check_dynamic.trace.syscalls import (
    SyscallObservation,
    unsupported_syscall_effects,
)


def _call(number: int, arguments: tuple[int, ...], *, ticket: int = 3):
    return SyscallObservation(1, ticket, number, arguments, 0)


def _concurrent_lifecycle() -> tuple[tuple[int, int, int], ...]:
    return ((1, 10, 1), (2, 10, 2), (10, 11, 2), (11, 11, 1))


def test_serial_external_effect_is_folded_into_trace_state() -> None:
    call = _call(0, (0, 0x2000, 16, 0, 0, 0), ticket=1)
    assert unsupported_syscall_effects((call,), ((2, 10, 1),), {}, set()) == ()


def test_concurrent_futex_remains_unknown() -> None:
    call = _call(202, (0x3000, 0, 1, 0, 0, 0))
    reasons = unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {1: (0x7000, 0x1000)}, set()
    )
    assert reasons == ("concurrent syscall 202 has an unsupported memory effect (1 call)",)


def test_successful_private_futex_wait_is_closed_by_materialized_read() -> None:
    call = _call(202, (0x3000, 0x109, 0, 0, 0, 0))
    assert unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {1: (0x7000, 0x1000)}, set()
    ) == ()


def test_private_nonfixed_mmap_is_a_fresh_object() -> None:
    call = _call(9, (0, 0x2000, 3, 0x22, (1 << 64) - 1, 0))
    assert unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {}, set()
    ) == ()


def test_signal_mask_buffers_must_belong_to_calling_stack() -> None:
    local = _call(14, (2, 0x7800, 0, 8, 0, 0))
    escaped = _call(14, (2, 0x9000, 0, 8, 0, 0), ticket=4)
    reasons = unsupported_syscall_effects(
        (local, escaped),
        _concurrent_lifecycle(),
        {1: (0x7000, 0x1000)},
        set(),
    )
    assert reasons == ("concurrent syscall 14 has an unsupported memory effect (1 call)",)


def test_munmap_requires_matching_object_lifetime_event() -> None:
    call = _call(11, (0x4000, 0x2000, 0, 0, 0, 0))
    assert unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {}, {(1, 0x4000, 0x2000)}
    ) == ()
    assert "unsupported" in unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {}, set()
    )[0]
