# Milestone 11 — PARSEC Evaluation

## Goal

在真实 benchmark 上验证完整 pipeline。

## Programs

```text
blackscholes
swaptions
dedup
canneal
```

## Expected Research Paths

### blackscholes

```text
read-only inputs
disjoint outputs
create/join
```

目标：proof closes 时 SAFE。

### swaptions

```text
read-only shared input
per-thread work partition
join
```

### dedup

重点暴露：

```text
spin-unlock plain-store publication
```

### canneal

重点暴露：

```text
ordinary-store publication path
```

## Measurements

```text
analysis time
CFG coverage
unresolved indirects
memory-event count
pruning count
slice size
checker time
verdict
DBT performance
```

## Acceptance

结果必须由 proof evidence 得出，不能由 benchmark 名称得出。
