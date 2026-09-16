from __future__ import annotations

from bmo_check_dynamic.trace.syscalls import (
    SyscallObservation,
    prove_active_munmaps,
    prove_syscall_buffer_disjointness,
    syscall_buffer_access,
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
    call = _call(202, (0x3000, 8, 1, 0, 0, 0))
    reasons = unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {1: (0x7000, 0x1000)}, set()
    )
    assert reasons == ("concurrent syscall 202 has an unsupported memory effect (1 call)",)


def test_successful_private_futex_wait_is_closed_by_materialized_read() -> None:
    call = _call(202, (0x3000, 0x109, 0, 0, 0, 0))
    assert unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {1: (0x7000, 0x1000)}, set()
    ) == ()


def test_successful_futex_wake_has_no_user_memory_effect() -> None:
    call = _call(202, (0x3000, 0x81, 1, 0, 0, 0))
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


def test_signal_mask_readonly_input_can_come_from_verified_module_range() -> None:
    call = _call(14, (2, 0x8100, 0x7800, 8, 0, 0))
    assert unsupported_syscall_effects(
        (call,),
        _concurrent_lifecycle(),
        {1: (0x7000, 0x1000)},
        set(),
        ((0x8000, 0x9000),),
    ) == ()


def test_signal_mask_output_must_stay_in_calling_stack() -> None:
    call = _call(14, (2, 0x7800, 0x8100, 8, 0, 0))
    assert unsupported_syscall_effects(
        (call,),
        _concurrent_lifecycle(),
        {1: (0x7000, 0x1000)},
        set(),
        ((0x8000, 0x9000),),
    ) == ("concurrent syscall 14 has an unsupported memory effect (1 call)",)


def test_munmap_requires_a_known_active_mapping() -> None:
    mmap = SyscallObservation(
        1, 1, 9, (0, 0x4000, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=2,
    )
    call = SyscallObservation(
        1, 3, 11, (0x4000, 0x2000, 0, 0, 0, 0), 0, exit_ticket=4
    )
    closed = prove_active_munmaps((mmap, call))
    assert unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {}, closed
    ) == ()
    assert "unsupported" in unsupported_syscall_effects(
        (call,), _concurrent_lifecycle(), {}, prove_active_munmaps((call,))
    )[0]


def test_read_footprint_uses_returned_byte_count() -> None:
    call = _call(0, (0, 0x1FFE, 8, 0, 0, 0), ticket=3)
    access = syscall_buffer_access(call)
    assert access is not None
    assert (access.address, access.size, access.kernel_writes) == (0x1FFE, 0, True)

    completed = SyscallObservation(1, 3, 0, call.arguments, 3)
    access = syscall_buffer_access(completed)
    assert access is not None
    assert (access.address, access.size, access.kernel_writes) == (0x1FFE, 3, True)


def test_read_buffer_conflict_is_checked_at_byte_granularity() -> None:
    lifecycle = ((1, 10, 1), (2, 10, 2), (10, 11, 2), (11, 11, 1))
    call = SyscallObservation(1, 3, 0, (0, 0x1000, 8, 0, 0, 0), 3)

    disjoint = prove_syscall_buffer_disjointness(
        (call,), lifecycle, ((2, 2, 0x1003, 1),)
    )
    assert disjoint.closed_calls == frozenset({(1, 3)})
    assert not disjoint.conflicting_calls

    overlapping = prove_syscall_buffer_disjointness(
        (call,), lifecycle, ((2, 2, 0x1002, 1),)
    )
    assert overlapping.conflicting_calls == frozenset({(1, 3)})
    assert not overlapping.closed_calls


def test_kernel_read_only_conflicts_with_remote_writes() -> None:
    lifecycle = ((1, 10, 1), (2, 10, 2), (10, 11, 2), (11, 11, 1))
    call = SyscallObservation(1, 3, 1, (1, 0x2000, 8, 0, 0, 0), 8)

    read_only = prove_syscall_buffer_disjointness(
        (call,), lifecycle, ((2, 1, 0x2000, 8),)
    )
    assert read_only.closed_calls == frozenset({(1, 3)})

    with_store = prove_syscall_buffer_disjointness(
        (call,), lifecycle, ((2, 2, 0x2000, 1),)
    )
    assert with_store.conflicting_calls == frozenset({(1, 3)})


def test_overlapping_syscall_buffers_remain_unresolved() -> None:
    lifecycle = ((1, 10, 1), (2, 10, 2), (10, 11, 2), (11, 11, 1))
    read = SyscallObservation(1, 3, 0, (0, 0x3000, 16, 0, 0, 0), 8)
    write = SyscallObservation(2, 4, 1, (1, 0x3004, 16, 0, 0, 0), 8)
    proof = prove_syscall_buffer_disjointness((read, write), lifecycle, ())
    assert proof.conflicting_calls == frozenset({(1, 3), (2, 4)})


def test_large_user_buffer_stays_unknown_when_page_budget_is_exceeded() -> None:
    lifecycle = ((1, 10, 1), (2, 10, 2), (10, 11, 2), (11, 11, 1))
    call = SyscallObservation(1, 3, 1, (1, 0x1FFF, 8192, 0, 0, 0), 8192)
    proof = prove_syscall_buffer_disjointness(
        (call,), lifecycle, (), max_pages=1
    )
    assert proof.limited_calls == frozenset({(1, 3)})
    assert not proof.closed_calls


def test_partial_munmap_changes_only_the_removed_part_of_a_mapping() -> None:
    mmap = SyscallObservation(
        1, 1, 9, (0, 0x4000, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=2,
    )
    first = SyscallObservation(
        1, 3, 11, (0x5000, 0x1000, 0, 0, 0, 0), 0, exit_ticket=4
    )
    left_and_right = (
        SyscallObservation(
            1, 5, 11, (0x4000, 0x1000, 0, 0, 0, 0), 0, exit_ticket=6
        ),
        SyscallObservation(
            1, 7, 11, (0x6000, 0x1000, 0, 0, 0, 0), 0, exit_ticket=8
        ),
    )
    assert prove_active_munmaps((mmap, first, *left_and_right)) == frozenset(
        {(1, 3), (1, 5), (1, 7)}
    )


def test_munmap_does_not_reuse_a_range_removed_by_an_earlier_call() -> None:
    mmap = SyscallObservation(
        1, 1, 9, (0, 0x4000, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=2,
    )
    first = SyscallObservation(
        1, 3, 11, (0x5000, 0x1000, 0, 0, 0, 0), 0, exit_ticket=4
    )
    repeat = SyscallObservation(
        1, 5, 11, (0x5000, 0x1000, 0, 0, 0, 0), 0, exit_ticket=6
    )
    assert prove_active_munmaps((mmap, first, repeat)) == frozenset({(1, 3)})


def test_munmap_accepts_a_completed_remap_at_the_same_address() -> None:
    original = SyscallObservation(
        1, 1, 9, (0, 0x2000, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=2,
    )
    remove = SyscallObservation(
        1, 3, 11, (0x4000, 0x2000, 0, 0, 0, 0), 0, exit_ticket=4
    )
    remap = SyscallObservation(
        1, 5, 9, (0, 0x2000, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=6,
    )
    remove_again = SyscallObservation(
        1, 7, 11, (0x4000, 0x2000, 0, 0, 0, 0), 0, exit_ticket=8
    )
    assert prove_active_munmaps(
        (original, remove, remap, remove_again)
    ) == frozenset({(1, 3), (1, 7)})


def test_munmap_stays_unknown_when_an_overlapping_mmap_is_in_flight() -> None:
    mapping = SyscallObservation(
        2, 3, 9, (0, 0x2000, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=6,
    )
    unmap = SyscallObservation(
        1, 4, 11, (0x4000, 0x2000, 0, 0, 0, 0), 0, exit_ticket=5
    )
    prior_map = SyscallObservation(
        1, 1, 9, (0, 0x2000, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=2,
    )
    assert not prove_active_munmaps((prior_map, mapping, unmap))


def test_munmap_stays_unknown_when_overlapping_munmaps_race() -> None:
    mmap = SyscallObservation(
        1, 1, 9, (0, 0x2000, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=2,
    )
    left = SyscallObservation(
        1, 3, 11, (0x4000, 0x2000, 0, 0, 0, 0), 0, exit_ticket=7
    )
    right = SyscallObservation(
        2, 4, 11, (0x4000, 0x1000, 0, 0, 0, 0), 0, exit_ticket=6
    )
    assert not prove_active_munmaps((mmap, left, right))


def test_munmap_page_rounding_does_not_exceed_the_known_mapping() -> None:
    mmap = SyscallObservation(
        1, 1, 9, (0, 1, 3, 0x22, (1 << 64) - 1, 0), 0x4000,
        exit_ticket=2,
    )
    unmap = SyscallObservation(
        1, 3, 11, (0x4000, 1, 0, 0, 0, 0), 0, exit_ticket=4
    )
    assert prove_active_munmaps((mmap, unmap)) == frozenset({(1, 3)})
