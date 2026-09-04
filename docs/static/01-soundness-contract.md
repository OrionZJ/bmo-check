# 01 — Soundness Contract

## 1. 理想性质

概念目标：

```text
Behaviors(DBT6_mo_off(binary), RVWMO)
    ⊆
Behaviors(binary, x86-TSO)
```

即 target 不能增加 source 中不存在的执行。

---

## 2. 工程原则

采用：

```text
sound but incomplete
```

规则：

```text
证明完成 -> SAFE
证明失败 -> UNKNOWN
发现 target-only execution -> COUNTEREXAMPLE
```

---

## 3. SAFE 的必要条件

至少满足：

1. binary dependency closure 完整；
2. 线程入口覆盖；
3. relevant control flow 没有被漏掉；
4. relevant indirect target 集合已封闭或保守摘要；
5. shared-memory effects 已恢复；
6. alias / escape 有足够证明；
7. synchronization 基于实际 binary + DBT contract；
8. pruning 每一步都有证据；
9. shared-memory slice 没漏 relevant communication；
10. portability checker 完成；
11. 无 relevant Unknown。

---

## 4. UNKNOWN 是正常结果

例如：

```text
UnresolvedIndirectCall
UnknownThreadEntry
MissingLibrary
UnknownSharedAddress
UnknownEscape
UnknownSynchronization
UnsupportedDynamicCode
PortabilityCheckIncomplete
```

每个 Unknown 必须带：

```text
module
pc/function
reason
impact
```

---

## 5. 动态测试不能证明 SAFE

允许使用 dynamic profile：

- 找 observed targets；
- 验证 callback；
- 调试地址公式；
- 帮助定位 benchmark。

禁止：

```text
跑了很多次没错 -> SAFE
```

---

## 6. 源码不能证明 SAFE

源码可用于开发期 ground truth。

但 final certificate 必须在没有源码时仍成立。

---

## 7. Pruning 必须有 proof object

每个被移除 event 必须记录：

```text
event
proof reason
supporting facts
```

比如：

```text
ThreadLocal
ReadOnlyAfterCreate
DisjointPartition
AtomicCovered
```

分析失败：

```text
保留 event 或 UNKNOWN
```

禁止静默删除。

---

## 8. Counterexample 标准

必须展示：

```text
target execution allowed
AND
source execution forbidden
```

并报告：

- threads；
- PCs；
- memory objects；
- source ordering；
- target ordering；
- target-only outcome。

---

## 9. 回归红线

发现以下情况必须调查：

- unresolved indirect 数突然下降；
- shared events 突然大量消失；
- analyzer exception 被转成空结果；
- missing library 仍能 SAFE；
- dynamic profile 把 incomplete targets 变 complete；
- benchmark name 影响 verdict；
- checker timeout 变 SAFE。
