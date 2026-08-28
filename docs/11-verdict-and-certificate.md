# 11 — Verdict and Certificate

## 1. Verdict

```text
SAFE
UNKNOWN
COUNTEREXAMPLE
```

---

## 2. SAFE certificate

必须绑定：

```text
main executable hash
all relevant library hashes
DBT contract version
DBT git revision
analysis config
execution scope
```

并且：

```text
relevant_unknowns = 0
```

---

## 3. UNKNOWN report

示例：

```json
{
  "status": "UNKNOWN",
  "reason": {
    "kind": "UnresolvedIndirectCall",
    "module": "app",
    "pc": "0x401234",
    "may_access_shared_memory": true
  }
}
```

---

## 4. COUNTEREXAMPLE report

至少包含：

```text
threads
events
PCs
memory objects
source required ordering
target actual ordering
target-only outcome
```

---

## 5. Coverage

certificate 中必须保存：

```text
modules
functions
indirect sites
incomplete indirect sites
thread roles
unknown thread entries
memory events
unknown memory effects
shared objects
unknown shared objects
pruning counts
slice size
checker result
```

---

## 6. Explain CLI

目标：

```text
bmo-check explain certificate.json
```

SAFE 示例：

```text
input[]:
  initialized before create
  read-only in worker phase

prices[]:
  worker write ranges proven disjoint

no unresolved communication remains
```

COUNTEREXAMPLE 示例：

```text
writer:
  store payload

publication:
  pthread_spin_unlock
  actual implementation = plain MOV

DBT6 mo-off:
  MOV -> relaxed RV Store

missing order:
  Store -> Store
```

---

## 7. 未来 runtime 使用

```text
matching SAFE certificate
    -> DBT6 mo-off

otherwise
    -> DBT6 mo-fsm
```
