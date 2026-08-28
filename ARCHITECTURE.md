# Architecture

## 1. 核心原则

必须把：

```text
事实恢复
```

和：

```text
安全证明
```

彻底分开。

错误：

```text
angr 没发现冲突
    ↓
SAFE
```

正确：

```text
ELF / Capstone / angr
        ↓
normalized facts
        ↓
program analysis
        ↓
shared-memory slice
        ↓
portability proof
        ↓
verdict
```

---

## 2. 推荐目录

```text
src/bmo_check/
├── cli.py
├── config.py
│
├── model/
│   ├── binary.py
│   ├── controlflow.py
│   ├── memory_event.py
│   ├── address.py
│   ├── thread.py
│   ├── sync.py
│   ├── unknown.py
│   └── verdict.py
│
├── binary/
│   ├── elf.py
│   ├── dependency_closure.py
│   ├── capstone_backend.py
│   └── angr_backend.py
│
├── controlflow/
│   ├── cfg.py
│   ├── callgraph.py
│   ├── indirect.py
│   └── callbacks.py
│
├── analysis/
│   ├── thread_discovery.py
│   ├── memory_events.py
│   ├── address_analysis.py
│   ├── escape_analysis.py
│   ├── alias_analysis.py
│   ├── readonly_analysis.py
│   ├── partition_analysis.py
│   └── shared_objects.py
│
├── sync/
│   ├── binary_summary.py
│   ├── pthread.py
│   ├── openmp.py
│   └── dbt_contract.py
│
├── pruning/
│   ├── threadlocal.py
│   ├── readonly.py
│   ├── partition.py
│   └── atomic_covered.py
│
├── slicing/
│   ├── conflicts.py
│   ├── communication.py
│   └── slice_builder.py
│
├── proof/
│   ├── source_model.py
│   ├── target_model.py
│   ├── portability.py
│   ├── counterexample.py
│   └── verifier.py
│
├── certificate/
│   ├── schema.py
│   ├── writer.py
│   └── explain.py
│
└── reporting/
    ├── text.py
    ├── json.py
    └── graph.py
```

---

## 3. 依赖方向

```text
model
  ↑
binary / controlflow
  ↑
analysis / sync
  ↑
pruning / slicing
  ↑
proof
  ↑
certificate / reporting
```

`model/` 不得依赖：

```text
angr
capstone
pyelftools
z3
```

proof 层只依赖 normalized IR，不直接操作 angr objects。

---

## 4. Verdict 所有权

只有：

```text
proof/verifier.py
```

可以生成最终：

```text
SAFE
UNKNOWN
COUNTEREXAMPLE
```

其他层只能生成：

- facts
- summaries
- partial proofs
- UnknownFact
- coverage
- counterexample candidates
