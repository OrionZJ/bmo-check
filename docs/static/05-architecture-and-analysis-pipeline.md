# 05 — Architecture and Analysis Pipeline

## Pipeline

```text
Executable + .so + config + DBT contract
        ↓
[1] Binary closure / fingerprint
        ↓
[2] x86 instruction facts
        ↓
[3] CFG / call graph / indirect targets
        ↓
[4] Thread discovery
        ↓
[5] MemoryEvent IR
        ↓
[6] Concrete synchronization summaries
        ↓
[7] Address / escape / shared-state analysis
        ↓
[8] Communication pruning
        ↓
[9] Shared-memory slice
        ↓
[10] Portability check
        ↓
SAFE / UNKNOWN / COUNTEREXAMPLE
```

---

## Phase 1

输出：

```text
ProgramManifest
```

确保知道分析的到底是哪组 binary。

---

## Phase 2

Capstone 恢复：

```text
Load
Store
LOCK
XCHG
Fence
branch/call
syscall
```

---

## Phase 3

CFG 每个 indirect site 必须包含：

```text
known_targets
complete
reason
```

---

## Phase 4

pthread 第一阶段：

```text
pthread_create
pthread_join
```

恢复 thread roles。

---

## Phase 5

全部转换为统一 MemoryEvent。

---

## Phase 6

同步 summary 必须区分：

```text
API required
actual x86 implementation
DBT translated ordering
```

---

## Phase 7

分类：

```text
ThreadLocal
ReadOnlyShared
DisjointPartition
SharedKnown
SharedUnknown
```

---

## Phase 8

安全剪枝。

---

## Phase 9

构建 compact concurrent slice。

---

## Phase 10

比较：

```text
x86-TSO
vs
DBT6 mo-off + RVWMO
```

---

## Coverage

每次都输出：

```text
modules
functions
reachable functions
indirect total/complete/incomplete
thread roles
unknown thread entries
memory events
shared events
unknown shared effects
pruning counts
slice events
slice edges
checker result
```
