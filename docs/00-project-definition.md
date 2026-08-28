# 00 — Project Definition

## 1. 最终问题

给定：

```text
真实 x86-64 executable
+ 实际动态库
+ 运行配置
+ DBT6 mo-off translation contract
```

判断：

> DBT6 在 RVWMO 上关闭普通 Load/Store 的额外 TSO Fence 后，是否会允许 x86-TSO 原本不允许的新执行？

---

## 2. 本项目不是做什么

不是：

```text
再设计一套 Fence 插入 FSM
```

现有 `mo-fsm` 已负责：

```text
需要 TSO 时，如何用最弱 Fence 恢复 ordering
```

本项目做：

```text
这个具体程序到底需不需要 TSO 模拟？
```

---

## 3. 顶层策略

```text
program
  ↓
verifier
 /      \
SAFE   else
 ↓       ↓
off     fsm
```

这意味着：

- verifier 是 program-level selector；
- FSM 是 instruction/TB-level fence mapper。

---

## 4. 输入

必需：

```text
x86-64 ELF
concrete .so closure
argv/config
thread-count scope
DBT contract
```

可选：

```text
symbols
DWARF
source
profiles
```

---

## 5. 输出

```text
SAFE
UNKNOWN
COUNTEREXAMPLE
```

### SAFE

可以使用 `mo-off`。

### UNKNOWN

不能证明，回退 `mo-fsm`。

### COUNTEREXAMPLE

找到 target-only behavior，回退 `mo-fsm`。

---

## 6. 为什么需要 slicing

真实程序可能有：

```text
几十万甚至更多 memory events
```

直接进行 weak-memory model checking 很难扩展。

因此先：

```text
全部 memory events
    ↓
ThreadLocal / ReadOnly / Disjoint / Atomic-covered
    ↓
只保留真正可能跨线程通信的事件
    ↓
shared-memory slice
```

再交给 checker。

---

## 7. 第一版非目标

不要求支持：

- JIT；
- self-modifying code；
- 未知 dlopen；
- 所有 C++ vtable；
- 任意 heap shape；
- 完整 path-sensitive alias；
- 完整 RVWMO solver；
- 所有 PARSEC。
