from __future__ import annotations

from bmo_check.model import AbstractAddress, AddressKind


def prove_affine_partition(address: AbstractAddress) -> tuple[bool, tuple[str, ...]]:
    """证明不同 tid 的整个有界访问集合不相交。"""
    required = (
        address.thread_coefficient,
        address.index_coefficient,
        address.index_lower,
        address.index_upper,
        address.thread_lower,
        address.thread_upper,
    )
    if address.kind != AddressKind.AFFINE or any(item is None for item in required):
        return False, ("affine coefficients or bounds are incomplete",)
    try:
        from z3 import Int, Solver, sat

        t1, t2, i1, i2 = (Int(name) for name in ("t1", "t2", "i1", "i2"))
        solver = Solver()
        solver.add(t1 >= address.thread_lower, t1 <= address.thread_upper)
        solver.add(t2 >= address.thread_lower, t2 <= address.thread_upper)
        solver.add(t1 != t2)
        solver.add(i1 >= address.index_lower, i1 <= address.index_upper)
        solver.add(i2 >= address.index_lower, i2 <= address.index_upper)
        first = address.offset + address.thread_coefficient * t1 + address.index_coefficient * i1
        second = address.offset + address.thread_coefficient * t2 + address.index_coefficient * i2
        solver.add(first == second)
        result = solver.check()
        if result == sat:
            return False, (
                "Z3 found overlapping addresses for distinct thread ids",
                str(solver.model()),
            )
        return True, (
            "Z3 proved address(t1,i1) != address(t2,i2) for t1 != t2",
            f"tid=[{address.thread_lower},{address.thread_upper}]",
            f"index=[{address.index_lower},{address.index_upper}]",
            f"address={address.offset}+{address.thread_coefficient}*tid+{address.index_coefficient}*index",
        )
    except Exception as error:
        return False, (f"Z3 affine proof failed: {error}",)
