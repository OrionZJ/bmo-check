from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from bmo_check.binary.elf import executable_segments, inspect_elf
from bmo_check.controlflow.cfg import _jump_table_targets
from bmo_check.model import ModuleRole


def test_jump_table_is_complete_only_with_entries_inside_executable_elf(
    elf_fixture,
) -> None:
    module = inspect_elf(elf_fixture.executable, ModuleRole.EXECUTABLE)
    target = executable_segments(Path(module.path))[0].virtual_address
    context = SimpleNamespace(
        module=module,
        to_elf_pc=lambda address: address,
        contains_rebased=lambda address: address == target,
    )
    indirect = SimpleNamespace(
        resolved_targets={target},
        jumptable=True,
        jumptable_entries=(target,),
    )

    targets, complete = _jump_table_targets(context, indirect)

    assert complete
    assert tuple(item.pc for item in targets) == (target,)


def test_angr_candidates_without_a_table_are_not_complete(elf_fixture) -> None:
    module = inspect_elf(elf_fixture.executable, ModuleRole.EXECUTABLE)
    target = executable_segments(Path(module.path))[0].virtual_address
    context = SimpleNamespace(
        module=module,
        to_elf_pc=lambda address: address,
        contains_rebased=lambda address: True,
    )
    indirect = SimpleNamespace(
        resolved_targets={target},
        jumptable=False,
        jumptable_entries=None,
    )

    _, complete = _jump_table_targets(context, indirect)

    assert not complete
