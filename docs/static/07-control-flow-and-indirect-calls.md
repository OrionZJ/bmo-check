# 07 — Control Flow and Indirect Calls

## 1. 原则

Binary-level SAFE 最危险的问题之一是漏 reachable code。

因此 indirect control flow 是 soundness boundary。

---

## 2. 第一阶段 resolver

按优先级：

1. direct call/jump；
2. PLT/GOT relocation；
3. switch jump table；
4. static function-pointer table；
5. pthread callback；
6. basic vtable；
7. unresolved。

---

## 3. TargetSet

每个 site：

```text
known_targets
complete
evidence
reason
```

`known_targets` 和 `complete` 必须分开。

---

## 4. 允许过近似

```text
real = {A,B}
analysis = {A,B,C}
```

---

## 5. 禁止漏目标

如果无法证明完整：

```text
complete=False
```

可能影响共享内存：

```text
SAFE forbidden
```

---

## 6. Dynamic tracing

可以：

```text
增加 observed target
```

不能：

```text
自动 complete=True
```

---

## 7. Future runtime guard

未来可做：

```text
certified target set
        ↓
runtime check
        ↓
unexpected target -> switch mo-fsm
```

不是第一版目标。
