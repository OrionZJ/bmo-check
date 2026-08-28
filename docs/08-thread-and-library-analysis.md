# 08 — Thread and Library Analysis

## 1. pthread 第一阶段

支持：

```text
pthread_create
pthread_join
pthread_mutex_*
pthread_spin_*
pthread_cond_*
pthread_barrier_*
pthread_once
```

---

## 2. Thread discovery

恢复：

```text
create site
parent role
child start routine
child arg origin
join relation
```

无法恢复 callback：

```text
UNKNOWN
```

---

## 3. 为什么必须看实际动态库

不能直接认为：

```text
pthread_spin_unlock = Release
```

必须继续分析 actual x86 binary。

如果它是：

```asm
mov [lock], 1
```

那么结合 DBT6 `mo-off`：

```text
plain x86 Store
    ↓
plain RV Store
```

target 不自动拥有 Release。

---

## 4. 三层同步摘要

每个同步函数记录：

```text
API-required semantics
actual x86 implementation
DBT6 target ordering
```

例如：

```text
pthread_mutex_lock
API: Acquire
binary: LOCK CMPXCHG
target: AcqRel
```

```text
pthread_spin_unlock
API: Release
binary: plain MOV
target: Relaxed
```

---

## 5. Library binding

summary 必须绑定：

```text
library SHA-256 / Build ID
function PC/range
instruction pattern
```

不能假设所有 glibc 版本一样。

---

## 6. OpenMP

后续支持：

```text
GOMP_parallel
GOMP_critical_start/end
GOMP_barrier
GOMP_loop_*
```

规则仍然是分析实际 binary。

---

## 7. Custom synchronization

程序自己实现的 lock：

```text
LOCK/XCHG/plain Store/Fence
```

直接通过指令层分析。
