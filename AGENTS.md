# BMoCheck — Codex Project Rules

## 1. 项目目标

本项目实现一个 **binary-only、DBT-aware 的内存序安全验证器**。

核心问题：

> 给定一个真实 x86-64 ELF、它实际使用的动态库、运行配置以及 DBT6 的 `mo-off` 翻译规则，能否证明该程序在 RVWMO 上不会出现 x86-TSO 下不允许的新行为？

最终策略：

```text
real x86-64 binary
        ↓
BMoCheck
   /          \
SAFE       UNKNOWN / COUNTEREXAMPLE
 ↓                 ↓
mo-off            mo-fsm
                    ↓
          CrossMapping-like FSM
```

Verifier 回答：

```text
这个程序是否根本需要 TSO 模拟？
```

FSM 回答：

```text
如果需要 TSO 模拟，Fence 应该怎么插？
```

不要把两者混为一谈。

---

## 2. 开始任务前必须阅读

按顺序阅读：

1. `docs/00-project-definition.md`
2. `docs/01-soundness-contract.md`
3. `docs/02-research-positioning.md`
4. `docs/03-binary-only-input-contract.md`
5. `docs/04-dbt6-memory-order-contract.md`
6. `docs/05-architecture-and-analysis-pipeline.md`
7. `docs/06-memory-event-ir.md`
8. `docs/07-control-flow-and-indirect-calls.md`
9. `docs/08-thread-and-library-analysis.md`
10. `docs/09-communication-pruning.md`
11. `docs/10-portability-check.md`
12. `docs/11-verdict-and-certificate.md`
13. `docs/12-validation-plan.md`
14. 当前 milestone plan

如果实现和这些文档冲突，先指出冲突，不要自行改变项目方向。

---

## 3. 最高优先级规则：SAFE 必须有证明

本项目采用：

```text
sound but incomplete
```

允许：

```text
无法证明
    ↓
UNKNOWN
```

禁止：

```text
无法证明
    ↓
看起来没问题
    ↓
SAFE
```

允许漏掉优化机会。

不允许错误批准 `mo-off`。

---

## 4. 顶层 Verdict

只允许：

```text
SAFE
UNKNOWN
COUNTEREXAMPLE
```

### SAFE

所有可能影响结果的跨线程通信均已证明在 DBT6 `mo-off + RVWMO` 下不会引入 x86-TSO 不允许的新行为。

### UNKNOWN

存在无法封闭的必要事实。

例如：

- unresolved indirect target；
- unknown thread entry；
- missing library；
- unsupported `dlopen`；
- JIT/self-modifying code；
- unknown shared-memory effect；
- alias/escape 无法证明；
- synchronization semantics 未建模；
- portability checker timeout。

### COUNTEREXAMPLE

找到一个：

```text
target model 允许
source x86-TSO 不允许
```

的执行。

必须能定位到具体事件、线程和 PC。

---

## 5. Binary-only 原则

最终 SAFE 证明不能依赖源码。

核心输入必须是：

```text
x86-64 executable
+ concrete shared-library closure
+ execution configuration
+ DBT6 translation contract
```

以下只能用于辅助：

```text
symbols
DWARF
source code
dynamic profiles
manual annotations
```

源码可以帮助调试和解释，但不能偷偷成为 SAFE 的必要前提。

---

## 6. 外部工具信任边界

### pyelftools

只负责恢复 ELF 事实：

- headers
- symbols
- relocations
- DT_NEEDED
- Build ID

### Capstone

负责原始 x86 指令事实：

- Load / Store
- LOCK prefix
- memory XCHG
- LFENCE / SFENCE / MFENCE
- branch / call / ret / syscall

### angr

负责辅助恢复：

- CFG
- call graph
- reaching definitions
- indirect target candidates

这些工具都不能直接输出 SAFE。

只有 `proof/` 层允许生成最终 verdict。

---

## 7. Unknown 必须是一等对象

禁止用：

```python
None
[]
False
```

表示可能影响正确性的未知状态。

例如 indirect call 必须表示：

```python
IndirectTargetSet(
    known_targets={...},
    complete=False,
    reason=...
)
```

分析失败不能变成：

```text
没有事件
```

而应该变成显式 Unknown。

---

## 8. 间接控制流规则

允许过近似：

```text
真实目标 = {A, B}
分析目标 = {A, B, C}
```

不允许漏目标：

```text
真实目标 = {A, B}
分析目标 = {A}
```

无法证明目标集合封闭：

```text
complete = false
```

如果该调用可能影响共享内存，最终不能 SAFE。

动态 tracing 只能增加 observed targets，不能证明 target-set 完整。

---

## 9. 共享内存分类规则

默认：

```text
MayAlias
SharedUnknown
UnknownEscape
```

只有有证明时才允许提升为：

```text
ThreadLocal
ReadOnlyShared
DisjointPartition
NoAlias
```

禁止：

```text
stack -> 自动 ThreadLocal
malloc -> 自动 private
变量名不同 -> NoAlias
一次运行地址没重叠 -> Disjoint
```

---

## 10. 同步 API 规则

不能把 API 名字直接当 target ordering。

例如：

```text
pthread_spin_unlock
```

API 需要 Release，但实际 x86 library 可能实现为：

```asm
mov [lock], 1
```

如果 DBT6 `mo-off` 把它翻成普通 RV Store，则不能自动认为 target 有 Release。

必须区分：

```text
API-required semantics
actual x86 implementation
DBT6 translated ordering
```

---

## 11. DBT6 边界

本项目不修改现有 LOCK/XCHG 原子实现。

DBT6 的 memory-order translation 作为外部 contract 输入。

详见：

```text
docs/04-dbt6-memory-order-contract.md
```

---

## 12. 分层架构

必须保持：

```text
binary facts
    ↓
control-flow / thread recovery
    ↓
MemoryEvent IR
    ↓
shared-state analysis
    ↓
communication pruning
    ↓
shared-memory slice
    ↓
portability checker
    ↓
SAFE / UNKNOWN / COUNTEREXAMPLE
```

禁止：

```text
angr 没发现问题 -> SAFE
```

禁止：

```text
benchmark 跑很多次没错 -> SAFE
```

---

## 13. 第一批 benchmark

只优先覆盖：

```text
blackscholes
swaptions
dedup
canneal
```

研究目标：

```text
blackscholes -> SAFE（若 partition/read-only proof 闭合）
swaptions    -> SAFE（若 partition/read-only proof 闭合）

dedup        -> 暴露 plain-store spin-unlock publication
canneal      -> 暴露 ordinary-store publication
```

不能硬编码 benchmark 名称和 verdict。

---

## 14. Milestone 规则

复杂任务必须对应：

```text
docs/exec-plans/active/milestone-XX-*.md
```

每个 milestone 必须写：

- goal
- non-goals
- input
- output
- soundness hazards
- tests
- acceptance criteria

一次只完成一个 milestone。

不要提前实现后续 milestone。

---

## 15. 测试要求

每个新 proof capability 必须同时有：

1. 正例；
2. 反例；
3. UNKNOWN 传播用例。

特别要保留：

```text
unresolved indirect shared call -> UNKNOWN
missing library                 -> UNKNOWN
unknown sync implementation     -> UNKNOWN
dynamic profile only            -> not unconditional SAFE
plain Store publication         -> never SAFE
```

---

## 16. Explainability

SAFE 报告必须解释：

- 哪些对象共享；
- 哪些对象被证明 ThreadLocal/ReadOnly/Disjoint；
- 哪些同步由 atomic/fence 覆盖；
- 为什么没有剩余 target-only behavior。

UNKNOWN 报告必须解释未知发生在哪。

COUNTEREXAMPLE 必须显示：

- thread roles；
- PCs；
- memory objects；
- source ordering；
- translated target ordering；
- target-only outcome。

---

## 17. 注释风格

注释主要解释：

- 为什么这个 proof step 可以成立；
- 它防止什么 false SAFE；
- Unknown 为什么必须传播；
- 结论依赖哪个 binary/DBT contract 事实。

不要逐行翻译代码。
