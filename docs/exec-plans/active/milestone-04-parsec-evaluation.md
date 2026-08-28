# Milestone 04 — PARSEC Evaluation

## Goal

在真实 PARSEC binary 和实际 x86lib 上验证完整 pipeline，量化剪枝和 checker 效果。

## Non-goals

- 不按 benchmark 名称硬编码 verdict；
- 不把程序正常退出当作正确性证明；
- 不实现自动 DBT mode launcher。

## Input

固定 executable、实际动态库闭包、argv、线程范围和 DBT contract。

## Programs

```text
blackscholes
swaptions
dedup
canneal
```

## Measurements

```text
analysis time
CFG coverage
indirect complete/incomplete
thread roles
memory events
pruning counts
slice size
checker time
verdict
```

## Expected research paths

- blackscholes/swaptions：read-only 和 disjoint proof 闭合时 SAFE；
- dedup：暴露 spin-unlock plain Store publication；
- canneal：暴露 AtomicPtr::Checkin ordinary Store publication。

这些仅作为人工核对目标，不能作为分析器输入。

## Tests

- 四个程序的完整分析脚本；
- ThreadLocal、ReadOnly、Disjoint、AtomicCovered 逐级 ablation；
- certificate 与实际 binary/library hash 匹配；
- 输出验证与 benchmark 退出状态分开记录。

## Acceptance criteria

- verdict 只由 proof evidence 得出；
- 报告包含 Unknown 和 coverage，不隐藏失败路径；
- 给出 slice 缩减、分析时间和 checker 时间；
- launcher 作为后续 roadmap 项保留。
