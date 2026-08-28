# Milestone 05 — Concrete pthread Synchronization Summaries

## Goal

分析实际 x86 runtime library 中的同步实现。

## Initial Functions

```text
pthread_mutex_lock/unlock
pthread_spin_lock/unlock
pthread_cond_wait/signal/broadcast
pthread_barrier_wait
pthread_once
```

## Output

每个函数：

```text
API-required semantics
actual x86 implementation
DBT6-translated target ordering
summary completeness
library fingerprint
```

## Required Example

必须能表达：

```text
pthread_spin_unlock
API: Release
binary: plain MOV
target: Relaxed
```

## Acceptance

未知 library implementation 不能默认安全。
