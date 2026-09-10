# D2 — Trace operand identity

Status: implemented on branch `dev`

## Scope

Trace format minor version 1.2 uses the existing `aux` word plus an explicit
`OPERAND_INDEX` flag for memory records. The DynamoRIO client writes the stable
instrumentation operand slot, while the Python reader and DuckDB adapter preserve
it as `TraceEvent.operand_index`.

Version 1.1 traces remain readable and deliberately expose `operand_index=None`.
They are site-level observations only; a later correlator must report an ambiguous
match when one PC has multiple static memory operands.

## Safety boundary

- The discriminator is only valid for LOAD/STORE/ATOMIC_RMW/FUTEX memory records.
- `aux` remains unchanged for syscall, lifecycle and indirect-target records.
- A future trace minor version is rejected until a reviewed reader exists.
- Adding an operand index changes correlation precision only; it does not add or
  remove memory-model edges.

## Next gate

Use this field in the dynamic observation adapter and static `MemoryOperandId`
correlator. PC-only matches from old traces must remain `Ambiguous`, never `Exact`.
