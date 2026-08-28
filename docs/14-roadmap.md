# 14 — Roadmap

## MVP：五个合并阶段

```text
M0 foundation + binary facts
M1 program recovery + synchronization
M2 shared state + communication slicing
M3 portability proof + verdict
M4 PARSEC evaluation
```

MVP 最终应能：

1. fingerprint executable 与实际动态库闭包；
2. 恢复 x86 memory/atomic/control-flow facts；
3. 显式保留 unresolved indirect 和 unknown thread entry；
4. 分析实际 pthread 同步实现及 DBT lowering；
5. 分类基础 ThreadLocal、ReadOnly 和 Disjoint；
6. 构建带 proof object 的 shared-memory slice；
7. 在受支持的有限切片上寻找 target-only execution；
8. 输出 SAFE、UNKNOWN 或 COUNTEREXAMPLE 并解释原因；
9. 在 blackscholes、swaptions、dedup、canneal 上评估。

## MVP 之后

- libgomp/OpenMP；
- 更完整的 C++ vtable 和 heap field sensitivity；
- 更强 affine/Z3 partition；
- runtime indirect target guard；
- region-level certificate；
- SAFE certificate 驱动的外部 DBT launcher；
- 不只 off/fsm，自动选择更细 memory-order policy。
