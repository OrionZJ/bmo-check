# 10 — PORTHOS-Style Portability Check

## 1. 目标

shared-memory slice 构建完成后，检查：

> translated target model 是否允许 source x86-TSO 不允许的新执行？

---

## 2. 理论形式

```text
TargetBehaviors ⊆ SourceBehaviors
```

其中：

```text
Source = x86-TSO
Target = DBT6 mo-off lowering + RVWMO
```

---

## 3. 为什么叫 PORTHOS-style

采用已有 portability/robustness checking 思想。

不要求直接复用 PORTHOS 源码。

可能实现：

```text
SMT
herd7
custom bounded checker
adapted existing checker
```

需要先通过 decision record 选方案。

---

## 4. Checker 输入

至少：

```text
threads
MemoryEvents
program order
addresses / alias
read-from candidates
synchronization edges
source ordering
target ordering
guards
```

---

## 5. Source model

普通 x86 TSO 重点：

```text
Load -> Load
Load -> Store
Store -> Store
```

Store -> Load 本身可放松。

---

## 6. Target model

不是单纯 RVWMO。

而是：

```text
RVWMO
+
DBT6 mo-off lowering
```

例如：

```text
plain Store -> ordinary Store
LOCK -> aq/rl
XCHG -> aq/rl
MFENCE -> full Fence
```

---

## 7. Counterexample 示例

```text
T0:
data = 1
flag = 1

T1:
r1 = flag
r2 = data
```

如果 target 允许：

```text
r1=1, r2=0
```

而 source 不允许：

```text
COUNTEREXAMPLE
```

---

## 8. Timeout / unsupported

必须：

```text
UNKNOWN
```

不能当成 no-counterexample。

---

## 9. Bounded checker

如果 checker 只是 bounded：

certificate 必须显式写 bound。

不能把 bounded no-counterexample 自动包装成 unconditional SAFE。

---

## 10. 当前有限模型

首版使用 Z3：

```text
target solver
  枚举 rf + coherence
  检查 RVWMO + DBT6 ordering 无环

source solver
  固定同一 rf + coherence
  检查 x86-TSO preserved order 无环
```

x86-TSO 保留：

```text
L→L
L→S
S→S
```

并放松普通 `S→L`。RVWMO 侧保留同地址顺序、已恢复依赖、AcqRel、显式 Fence 和完整同步边。

首版支持集：

```text
finite linear event graph
exact Global alias class
aligned 1/2/4/8-byte Load/Store
AcqRel RMW
LFENCE/SFENCE/MFENCE lowering
```

mixed-size、misaligned、Unknown address、循环事件图、开放控制流和超界输入返回 `UNKNOWN`。
