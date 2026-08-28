# 09 — Communication Pruning

## 1. 目标

把真实 binary 的大量 memory events 缩减为真正 relevant 的跨线程通信。

---

## 2. 初始 pruning categories

```text
ThreadLocal
ReadOnlyShared
DisjointPartition
AtomicCovered
```

每一类都必须有 proof object。

---

## 3. ThreadLocal

可证明来源：

- TLS；
- 未逃逸 stack object；
- 未跨线程逃逸 heap object。

以下都可能导致 escape：

```text
store pointer into shared object
pass to pthread_create
pass to unknown call
return to unknown caller
enqueue into shared structure
```

---

## 4. ReadOnlyShared

典型：

```text
main init
    ↓
pthread_create
    ↓
workers only read
```

必须证明没有隐藏 writer。

---

## 5. DisjointPartition

典型：

```text
worker tid writes:
base + f(tid,index)
```

目标证明：

```text
tid1 != tid2
    =>
write_set(tid1) ∩ write_set(tid2) = ∅
```

后续可用 Z3。

---

## 6. AtomicCovered

如果通信已经由：

```text
aq/rl atomic
explicit Fence
modeled create/join/barrier
```

覆盖，可以摘要。

第一版可先不删，优先保证正确性。

---

## 7. Conflict candidate

重点保留：

```text
different concurrent thread roles
AND MayAlias
AND at least one Store
AND not ThreadLocal
AND not ReadOnly-only
AND not Disjoint
```

---

## 8. Pruning report

每次输出：

```text
total events
ThreadLocal removed
ReadOnly removed
Disjoint removed
AtomicCovered removed
remaining shared events
unknown events
```
