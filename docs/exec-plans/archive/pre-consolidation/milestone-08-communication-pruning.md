# Milestone 08 — Communication Pruning and Slice Construction

## Goal

把 whole binary 缩成 communication-relevant slice。

## Pruning Reasons

```text
ThreadLocal
ReadOnlyShared
DisjointPartition
optional AtomicCovered
```

## Output

`SharedMemorySlice`：

```text
thread roles
remaining memory events
program-order edges
alias relations
sync edges
Unknowns
```

## Soundness

每个 removed event 必须有 proof reason。

Unknown shared effect 必须保留。

## Acceptance

slice builder 不允许静默丢 Unknown。
