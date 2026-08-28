# Milestone 02 — x86 Instruction Facts

## Goal

建立 x86-64 原始指令事实层。

## Backend

Capstone。

## Required Facts

```text
PC/raw bytes
memory operands
Load/Store
LOCK
memory XCHG
LFENCE/SFENCE/MFENCE
direct/indirect call/jump
RET
syscall
```

## Critical Rule

后续转换到高层 IR 时不能丢 LOCK/XCHG 信息。

## Tests

- MOV load/store
- LOCK CMPXCHG
- LOCK XADD
- LOCK DEC
- memory XCHG
- register XCHG
- fences
- direct/indirect control flow

## Acceptance

本阶段不输出 SAFE/COUNTEREXAMPLE。
