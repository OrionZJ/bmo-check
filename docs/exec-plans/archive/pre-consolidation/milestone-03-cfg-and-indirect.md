# Milestone 03 — CFG and Indirect Control Flow

## Goal

恢复 CFG/call graph，同时显式保存完整性不确定性。

## Backend

第一版：

```text
angr CFGFast
+
ELF/Capstone facts
```

## Deliverables

```text
FunctionFact
BasicBlockFact
CallSite
IndirectTargetSet
CFGCoverage
```

## Resolver

1. direct；
2. PLT/GOT；
3. simple jump table；
4. static function-pointer table；
5. angr candidates。

## Soundness Rule

```text
known targets != complete target set
```

## Tests

- direct call
- PLT
- jump table
- unresolved function pointer
- dynamic profile cannot force complete

## Acceptance

每个 indirect site 必须是 complete 或 explicit incomplete。
