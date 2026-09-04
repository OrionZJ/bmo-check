# 02 — Research Positioning

## 1. 不应声称的新颖点

不要声称首次：

```text
比较两个内存模型的程序行为
```

已有 portability / robustness checking。

不要声称首次：

```text
用 FSM 优化 Fence
```

CrossMapping 等已有工作已做。

不要声称首次：

```text
按应用选择不同 TSO 强度
```

实际系统已有 compatibility profile / memory-order levels。

---

## 2. 目标研究缺口

本项目聚焦以下组合：

```text
real x86 ELF
+ concrete runtime libraries
+ binary-level indirect control flow
+ actual synchronization implementation
+ DBT-specific lowering
+ communication pruning
+ portability checking
```

最终回答：

```text
Can this concrete binary safely run with DBT6 mo-off?
```

---

## 3. 与 CrossMapping-like FSM 的关系

FSM：

```text
假设必须保持 TSO
    ↓
追踪 ordering obligation
    ↓
选择最弱足够 Fence
```

Verifier：

```text
分析具体程序
    ↓
判断这些额外 TSO ordering 是否真正影响跨线程通信
```

最终：

```text
SAFE -> mo-off
otherwise -> mo-fsm
```

---

## 4. 与 PORTHOS-style checker 的关系

我们不发明 portability 定义。

采用现有思想：

```text
TargetBehaviors ⊆ SourceBehaviors ?
```

真正的研究挑战是：

> 如何从真实 ELF 得到一个足够小、又不漏掉相关行为的 shared-memory slice。

---

## 5. 候选贡献

### Contribution 1

Binary-level DBT-aware frontend。

### Contribution 2

Concrete library synchronization summaries：

```text
API semantics
vs
actual x86 implementation
vs
DBT target ordering
```

### Contribution 3

Communication pruning：

```text
ThreadLocal
ReadOnly
DisjointPartition
AtomicCovered
```

### Contribution 4

Program-level `mo-off` certification。

### Contribution 5

与现有 `mo-fsm` 的安全组合。
