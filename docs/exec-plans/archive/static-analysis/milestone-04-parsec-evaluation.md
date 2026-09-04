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

- blackscholes/swaptions：先闭合 read-only、disjoint 和 lifecycle，再单独验证 join Acquire；
- dedup：暴露 spin-unlock plain Store publication；
- canneal：暴露 AtomicPtr::Checkin ordinary Store publication。

这些仅作为人工核对目标，不能作为分析器输入。

## Current experiment results

- blackscholes 的固定输入分区和 create/join handle 集合均由机器码符号执行证明。
- lifecycle 结果只覆盖 suite 明确声明的 create/join 成功执行；该假设进入 certificate 配置 hash，未声明时证明器拒绝剪枝。
- blackscholes 在 Disjoint 级别已没有普通访存冲突候选；外部 memory effect 和仿射 Unknown 都已清零。
- blackscholes 仍不能输出 SAFE。本地 `pthread_join` 存在 Relaxed 返回路径，DBT contract 也没有给 syscall 提供 Acquire；报告把它标为 `WeakSynchronizationLowering`。
- swaptions 的分区与 lifecycle 证明同样闭合，但 worker 内部 malloc/free 和失败路径仍留下对象 effect 缺口。
- swaptions 的正常完成 scope 已用 CFG 反向可达性排除无法到达 ret 的 assert/stack-check 分支；Unknown 由 40 降为 35。
- allocator 契约把 malloc/free 的隐藏元数据收窄为 `runtime:allocator`，不再让它别名任意应用数组；Unknown 进一步降为 31，但 allocator 自身仍保留 Unknown。
- 剩余 18 个地址缺口中，11 个已命中 swaptions 的 Z3 分片证明，但仍被 `print_usage` 的 stdio wildcard 阻塞。下一步需要对固定 argv 做二进制前缀路径证明，不按函数名删除。
- dedup 已定位 `pthread_spin_unlock@0xed40` 的普通 Store；canneal 已定位 `AtomicPtr::Checkin@0x6b7c` 的普通 Store。二者应进入风险回归，不得因其他 Unknown 被隐藏。

当前结论修正了最初的 SAFE 预期：即使应用数组已证明只读或分片，join 后读取 worker 输出仍需要具体 Acquire 证据。程序在多次实测中正常退出不能替代该证明。

`normal_completion_only` 和 lifecycle 的 create/join 成功假设都进入 certificate 的配置 hash。不开启时，失败分支和线程 API 失败路径仍保留 Unknown。

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
