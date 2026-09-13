"""为 herd 生成最小的 contract-lowered RISC-V litmus 输入。

这不是 `.litmus` 编译器，也不读取生成 ELF。它只消费已经审核过的 typed
fixture，把其中支持的 load/store/fence/atomic operation 映射成 herd 能理解的
RISC-V 指令文本，供外部 oracle 使用。输出仍属于 evaluation artifact；缺少
store 值或 target-specific outcome 时直接拒绝，避免把 x86 观察猜成 target 语义。
"""

from __future__ import annotations

from collections import defaultdict
import re

from bmo_check_core.contracts import MemoryOrderContract, TargetFence

from .model import FixtureEventKind, LitmusCase


class TargetExportError(ValueError):
    """fixture 或 contract 超出 target oracle exporter 的支持集。"""


_WIDTH_MNEMONICS = {
    1: ("lb", "sb"),
    2: ("lh", "sh"),
    4: ("lw", "sw"),
    8: ("ld", "sd"),
}
_FENCE_FIELDS = {
    FixtureEventKind.LFENCE: "lfence",
    FixtureEventKind.SFENCE: "sfence",
    FixtureEventKind.MFENCE: "mfence",
}
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _registers(case: LitmusCase) -> dict[tuple[int, str], str]:
    objects = sorted(
        {event.object_label for event in case.critical_events if event.object_label}
    )
    result: dict[tuple[int, str], str] = {}
    for thread in sorted({event.thread for event in case.critical_events}):
        for index, object_label in enumerate(objects):
            # x6..x15 是 herd RISC-V parser 接受的临时寄存器；每个线程使用
            # 相同的对象布局，target condition 可据此稳定引用 load 结果。
            result[thread, object_label] = f"x{6 + index}"
    return result


def _identifier(value: str, field: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise TargetExportError(f"{field} is not a valid herd identifier: {value!r}")
    return value


def _case_name(value: str) -> str:
    if not value or any(character in value for character in "\r\n\x00"):
        raise TargetExportError("case_id must be a non-empty single-line value")
    name = re.sub(r"[^A-Za-z0-9_]", "_", value)
    return name if not name[0].isdigit() else f"_{name}"


def _load_store(event_kind: FixtureEventKind, width: int) -> str:
    try:
        load, store = _WIDTH_MNEMONICS[width]
    except KeyError as error:
        raise TargetExportError(f"unsupported target memory width: {width}") from error
    return load if event_kind is FixtureEventKind.LOAD else store


def _event_instruction(
    kind: FixtureEventKind,
    *,
    width: int | None,
    value: int | None,
    object_register: str | None,
    destination: str,
    contract: MemoryOrderContract,
) -> tuple[str, ...]:
    if kind in {FixtureEventKind.LOAD, FixtureEventKind.STORE}:
        if width is None or object_register is None:
            raise TargetExportError("plain target memory event needs width and object")
        mnemonic = _load_store(kind, width)
        if kind is FixtureEventKind.LOAD:
            return (f"{mnemonic} {destination},0({object_register})",)
        if value is None:
            raise TargetExportError("plain target store needs an explicit value")
        if not -2048 <= value <= 2047:
            raise TargetExportError(
                "target oracle exporter only supports signed 12-bit store values"
            )
        return (f"addi x5,x0,{value}", f"{mnemonic} x5,0({object_register})")
    if kind is FixtureEventKind.ATOMIC_RMW:
        if width not in {4, 8} or object_register is None:
            raise TargetExportError("target atomic oracle supports only 4/8-byte AMO")
        mnemonic = "amoadd.w.aqrl" if width == 4 else "amoadd.d.aqrl"
        return (f"{mnemonic} {destination},x0,({object_register})",)
    if kind in _FENCE_FIELDS:
        field = _FENCE_FIELDS[kind]
        fence = getattr(contract.translation, field)
        if fence is TargetFence.UNKNOWN:
            raise TargetExportError(f"contract does not define target fence for {kind.value}")
        return (f"fence {fence.value}",)
    raise TargetExportError(f"unsupported target fixture event: {kind.value}")


def export_contract_target(
    case: LitmusCase,
    contract: MemoryOrderContract,
    *,
    outcome: str | None = None,
) -> str:
    """把 fixture 的 critical operations 经 contract 映射为 RISC-V herd 文本。"""

    issue = contract.unsupported_field()
    if issue is not None:
        raise TargetExportError(issue.render())
    case_name = _case_name(case.case_id)
    registers = _registers(case)
    by_thread: dict[int, list] = defaultdict(list)
    for event in sorted(case.critical_events, key=lambda item: (item.thread, item.ordinal)):
        by_thread[event.thread].append(event)
    if not by_thread:
        raise TargetExportError("target oracle export needs at least one critical event")

    lines = [f"RISCV {case_name}", "{"]
    objects = sorted(
        {event.object_label for event in case.critical_events if event.object_label}
    )
    for thread in sorted(by_thread):
        declarations = "; ".join(
            f"{thread}:{registers[thread, _identifier(object_label, 'object_label')]}="
            f"{_identifier(object_label, 'object_label')}"
            for object_label in objects
        )
        if declarations:
            lines.append(f"{declarations};")
    lines.append("}")

    programs: list[list[str]] = []
    for thread in sorted(by_thread):
        instructions: list[str] = []
        load_index = 0
        for event in by_thread[thread]:
            object_register = (
                registers[thread, _identifier(event.object_label, "object_label")]
                if event.object_label is not None
                else None
            )
            destination = f"x{10 + load_index}"
            if event.kind is FixtureEventKind.LOAD or event.kind is FixtureEventKind.ATOMIC_RMW:
                load_index += 1
            instructions.extend(
                _event_instruction(
                    event.kind,
                    width=event.width,
                    value=event.value,
                    object_register=object_register,
                    destination=destination,
                    contract=contract,
                )
            )
        programs.append(instructions)
    lines.append(" | ".join(f"P{thread}" for thread in sorted(by_thread)) + " ;")
    for row in range(max(len(program) for program in programs)):
        columns = [program[row] if row < len(program) else "" for program in programs]
        lines.append(" | ".join(columns) + " ;")
    selected_outcome = (outcome or case.oracle.target_condition or "").strip()
    if selected_outcome:
        lines.append(
            selected_outcome
            if selected_outcome.startswith("exists ")
            else f"exists {selected_outcome}"
        )
    else:
        raise TargetExportError(
            "target oracle export requires a target-specific outcome expression"
        )
    return "\n".join(lines) + "\n"


__all__ = ["TargetExportError", "export_contract_target"]
