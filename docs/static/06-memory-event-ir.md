# 06 — MemoryEvent IR

## 1. 目的

Proof 层不直接操作 Capstone/angr 对象。

统一成 backend-independent IR。

---

## 2. Event kinds

```text
Load
Store
AtomicRMW
Fence
ThreadCreate
ThreadJoin
Acquire
Release
Barrier
OpaqueCall
Syscall
UnknownMemoryEffect
```

Acquire/Release 不能只根据 API 名字产生。

---

## 3. 建议结构

```python
MemoryEvent:
    id
    module
    pc
    function
    kind
    address
    size
    source_ordering
    target_ordering
    thread_role
    guard
    provenance
```

---

## 4. AbstractAddress

第一版：

```text
Global(symbol, offset)
TLS(symbol, offset)
Stack(frame, offset)
Heap(allocation_site, offset)
Unknown
```

后续：

```text
Affine
Interval
field-sensitive heap
```

---

## 5. Ordering

至少：

```text
Relaxed
Acquire
Release
AcqRel
Full
FenceRR
FenceRW
FenceWW
FenceWR
Unknown
```

---

## 6. Provenance

保留：

```text
raw bytes
x86 mnemonic
source PC
module
backend evidence
DBT contract rule
optional DWARF/source location
```

---

## 7. Unknown

未知必须显式建模：

```text
UnknownAddress
UnknownMemoryEffect
UnknownThreadRole
```

不能丢弃。

---

## 8. Program-order edges

单独记录线程内 program-order edge。

后续 proof 需要判断：

```text
required by x86?
preserved by target?
```
