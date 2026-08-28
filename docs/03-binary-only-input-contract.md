# 03 — Binary-Only Input Contract

## 1. 核心原则

最终证明对象是 binary，不是 source。

必需证据来自：

```text
machine code
ELF metadata
concrete runtime libraries
DBT translation contract
```

---

## 2. Executable fingerprint

记录：

```text
path
SHA-256
Build ID
ELF type
arch
interpreter
```

---

## 3. Shared libraries

记录：

```text
DT_NEEDED
resolved path
SONAME
SHA-256
Build ID
```

缺少必要库：

```text
UNKNOWN
```

不能根据 imported function name 猜实际实现。

---

## 4. Execution configuration

记录：

```text
argv
thread count/range
benchmark input
relevant environment assumptions
```

---

## 5. Optional data

以下只能辅助：

```text
symbol
DWARF
source file
profile trace
manual annotation
```

---

## 6. dlopen / JIT / SMC

第一版：

```text
unknown dlopen -> UNKNOWN
JIT -> UNKNOWN
SMC -> UNKNOWN
```

未来可考虑 runtime guard。

---

## 7. Certificate binding

SAFE certificate 必须绑定：

```text
main binary hash
library hashes
DBT revision
DBT contract
analysis config
```

任一变化，旧证书失效。
