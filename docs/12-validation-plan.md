# 12 — Validation Plan

## 1. 三层验证

### Layer A

tiny synthetic tests。

### Layer B

small compiled pthread programs。

### Layer C

PARSEC。

---

## 2. 必须有的 synthetic tests

### SAFE: single thread

无跨线程通信。

### SAFE: TLS only

多个线程只访问自己的 TLS。

### SAFE: read-only after create

```text
main init
pthread_create
workers only read
```

### SAFE: disjoint partition

线程写不重叠分片。

### SAFE: atomic publication

publication/acquire 被 DBT6 aq/rl 覆盖。

### COUNTEREXAMPLE: plain-store publication

```text
data=1
flag=1
```

target 可能看到 flag 新、data 旧。

### UNKNOWN: unresolved indirect shared call

### UNKNOWN: missing library

### UNKNOWN: profile-only target closure

---

## 3. PARSEC

### blackscholes

尝试证明：

```text
shared input read-only
worker outputs disjoint
create/join lifecycle
```

目标：

```text
SAFE if proof closes
```

### swaptions

同样尝试：

```text
read-only input
per-thread partition
join
```

### dedup

重点检查：

```text
spin-unlock plain-store publication
```

目标：

```text
COUNTEREXAMPLE
```

或 precise UNKNOWN。

### canneal

重点检查 ordinary-store publication。

---

## 4. 开发期 source ground truth

源码可以用来：

- 对照线程入口；
- 对照分片公式；
- 对照对象；
- 检查 binary analysis 是否正确。

但 final certificate 不依赖源码。

---

## 5. Ablation

建议实验：

```text
no pruning
ThreadLocal
+ ReadOnly
+ DisjointPartition
+ AtomicCovered
```

比较：

```text
slice size
analysis time
checker time
SAFE/UNKNOWN rate
```

---

## 6. Runtime baseline

可比较：

```text
mo-off
mo-baseline
mo-arancini
mo-fsm
```

Verifier 本身不是 Fence-placement baseline。

它只是决定 `mo-off` 是否被批准。
