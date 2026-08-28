# Milestone 07 — Disjoint Partition Proofs

## Goal

证明常见 per-thread output partition 不重叠。

## Motivation

blackscholes / swaptions 需要。

## Approach

先恢复 affine address：

```text
base + tid * stride + index * element_size
```

先 interval reasoning，必要时加 Z3。

## Query

```text
tid1 != tid2
    =>
write_set(tid1) ∩ write_set(tid2) = ∅ ?
```

UNSAT -> DisjointPartition。

## Tests

- fixed disjoint blocks
- overlap
- symbolic chunk
- unknown bounds

## Acceptance

不能 hard-code benchmark-specific formula。
