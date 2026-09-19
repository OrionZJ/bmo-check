from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bmo_check_core.identity import (
    AbstractObjectId,
    BasicBlockId,
    BinaryClosureId,
    EvidenceId,
    FunctionId,
    InstructionId,
    MemoryEventId,
    MemoryOperandId,
    ModuleId,
    ObjectOrigin,
    ObligationId,
    PropositionId,
    ThreadInstanceId,
    ThreadRoleId,
    TraceId,
)
from bmo_check_core.identity.ids import IdentityMaterialError


A = "a" * 64
B = "b" * 64
C = "c" * 64


def _identity_graph() -> dict[str, object]:
    module = ModuleId.from_parts(A, "executable")
    function = FunctionId.from_parts(module, 0x120)
    block = BasicBlockId.from_parts(function, 0x140)
    instruction = InstructionId.from_parts(module, 0x148)
    operand = MemoryOperandId.from_parts(instruction, 0, "load")
    role = ThreadRoleId.from_parts(None, None, (function,))
    event = MemoryEventId.from_parts(operand, role, "Load", "ordinary")
    object_id = AbstractObjectId.from_parts(ObjectOrigin.ALLOCATION, "calloc@0x120")
    premise = EvidenceId.from_parts("ProofFact", "1", "static-test", event, ())
    evidence = EvidenceId.from_parts(
        "ProofFact", "1", "static-test", object_id, (premise,)
    )
    trace = TraceId.from_parts("1.0", B, (module,), ("complete", "modules"), C)
    instance = ThreadInstanceId.from_parts(trace, 7)
    closure = BinaryClosureId.from_parts(A, (("shared", B), ("executable", A)), "x86_64")
    return {
        "module": module,
        "function": function,
        "block": block,
        "instruction": instruction,
        "operand": operand,
        "role": role,
        "event": event,
        "object": object_id,
        "premise": premise,
        "evidence": evidence,
        "trace": trace,
        "instance": instance,
        "closure": closure,
    }


def test_collection_order_does_not_change_set_based_ids() -> None:
    first = BinaryClosureId.from_parts(
        A, (("executable", A), ("shared", B)), "x86_64"
    )
    second = BinaryClosureId.from_parts(
        A, (("shared", B), ("executable", A)), "x86_64"
    )
    module = ModuleId.from_parts(A, "executable")
    function = FunctionId.from_parts(module, 0x120)
    trace_first = TraceId.from_parts("1.0", B, (module,), ("modules", "complete"), C)
    trace_second = TraceId.from_parts("1.0", B, (module,), ("complete", "modules"), C)

    assert first == second
    assert trace_first == trace_second
    assert function == FunctionId.from_parts(module, 0x120)


def test_semantic_changes_change_the_relevant_id() -> None:
    module = ModuleId.from_parts(A, "executable")
    changed_module = ModuleId.from_parts(B, "executable")
    function = FunctionId.from_parts(module, 0x120)
    changed_function = FunctionId.from_parts(module, 0x121)
    instruction = InstructionId.from_parts(module, 0x148)
    operand = MemoryOperandId.from_parts(instruction, 0, "load")
    changed_operand = MemoryOperandId.from_parts(instruction, 1, "load")

    assert module != changed_module
    assert function != changed_function
    assert operand != changed_operand


def test_nested_ids_change_when_their_parent_changes() -> None:
    module = ModuleId.from_parts(A, "executable")
    other_module = ModuleId.from_parts(B, "executable")
    function = FunctionId.from_parts(module, 0x120)
    other_function = FunctionId.from_parts(other_module, 0x120)
    assert BasicBlockId.from_parts(function, 0x140) != BasicBlockId.from_parts(
        other_function, 0x140
    )


def test_all_identity_values_round_trip() -> None:
    identities = _identity_graph()
    for identity in identities.values():
        restored = type(identity).from_value(json.loads(json.dumps(identity.value)))
        assert restored == identity
        assert str(restored) == identity.value


def test_identity_is_deterministic_across_processes() -> None:
    src = Path(__file__).resolve().parents[2] / "src"
    expected = str(ModuleId.from_parts(A, "executable"))
    script = (
        "from bmo_check_core.identity import ModuleId; "
        f"print(ModuleId.from_parts('{A}', 'executable'))"
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(src)
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.stdout.strip() == expected


def test_thread_roles_and_evidence_use_canonical_sets() -> None:
    module = ModuleId.from_parts(A, "executable")
    first = FunctionId.from_parts(module, 0x100)
    second = FunctionId.from_parts(module, 0x200)
    role_a = ThreadRoleId.from_parts(None, None, (first, second))
    role_b = ThreadRoleId.from_parts(None, None, (second, first))
    event = MemoryEventId.from_parts(
        MemoryOperandId.from_parts(InstructionId.from_parts(module, 0x300), 0, "store"),
        role_a,
        "Store",
        "ordinary",
    )
    one = EvidenceId.from_parts("ProofFact", "1", "producer", event, ())
    two = EvidenceId.from_parts("ProofFact", "1", "producer", role_a, (one,))
    two_reordered = EvidenceId.from_parts("ProofFact", "1", "producer", role_b, (one,))

    assert role_a == role_b
    assert two == two_reordered


def test_legacy_thread_role_identity_is_stable_but_explicitly_legacy() -> None:
    first = ThreadRoleId.from_legacy("worker:create@0x401000")
    second = ThreadRoleId.from_legacy("worker:create@0x401000")
    assert first == second
    assert first != ThreadRoleId.from_legacy("worker:create@0x401100")


def test_identity_material_rejects_unstable_or_ambiguous_values() -> None:
    with pytest.raises(IdentityMaterialError):
        ModuleId.from_parts("not-a-hash", "executable")
    with pytest.raises(IdentityMaterialError):
        AbstractObjectId.from_parts("allocation", "site")  # type: ignore[arg-type]
    with pytest.raises(IdentityMaterialError):
        ThreadRoleId.from_parts(None, None, ("benchmark-name",))  # type: ignore[arg-type]


def test_binary_closure_binds_abi_and_module_role() -> None:
    executable = BinaryClosureId.from_parts(A, (("shared", B),), "x86_64")
    other_abi = BinaryClosureId.from_parts(A, (("shared", B),), "aarch64")
    other_role = BinaryClosureId.from_parts(A, (("interpreter", B),), "x86_64")
    assert executable != other_abi
    assert executable != other_role


def test_proposition_identity_preserves_relation_direction() -> None:
    forward = PropositionId.from_parts("read_from", ("store", "load"))
    reverse = PropositionId.from_parts("read_from", ("load", "store"))

    assert forward != reverse
    assert PropositionId.from_value(forward.value) == forward


def test_obligation_identity_is_order_independent_for_subject_sets() -> None:
    first = ObligationId.from_parts("memory-order", "slice-1", ("event-b", "event-a"))
    second = ObligationId.from_parts("memory-order", "slice-1", ("event-a", "event-b"))

    assert first == second
    assert first != ObligationId.from_parts("memory-order", "slice-2", ("event-a", "event-b"))
