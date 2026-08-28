# 04 — DBT6 Memory-Order Contract

## 1. 目的

Verifier 必须检查 translated program，而不是只看 x86 源指令。

因此 DBT6 lowering 是显式输入。

---

## 2. `mo-off`

含义：

```text
普通 guest Load/Store
不由 memory-order module 自动增加 TSO Fence
```

这不等于“整个程序没有任何 ordering”。

---

## 3. Plain Load / Store

```text
plain x86 Load
    -> ordinary RV memory access
    -> no automatic TSO fence

plain x86 Store
    -> ordinary RV memory access
    -> no automatic TSO fence
```

---

## 4. LOCK RMW

当前 contract：

```text
x86 LOCK RMW
    -> existing LR/SC atomic path
    -> aq/rl
```

Verifier 不修改该路径。

---

## 5. Memory XCHG

```text
memory XCHG
    -> existing atomic path
    -> aq/rl
```

不能拆成普通 Load+Store。

---

## 6. Guest explicit Fence

当前约定：

```text
LFENCE -> fence r,r
SFENCE -> fence w,w
MFENCE -> fence rw,rw
```

`mo-off` 下仍保留。

---

## 7. Runtime/helper ordering

不能假设：

```text
syscall/helper = full barrier
```

只有有明确 summary 才能使用其 ordering。

---

## 8. 版本化

机器可读版本：

```text
specs/dbt6-mo-off.yaml
```

certificate 必须记录：

```text
contract_version
DBT git revision
```
