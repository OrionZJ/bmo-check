# Milestone 01 — Program Recovery and Synchronization

## Status

COMPLETE（2026-08-28）

## Goal

使用 angr 恢复保守 CFG、间接目标、pthread 线程角色和实际动态库同步摘要。

## Non-goals

- 不做共享对象剪枝；
- 不证明线程分片；
- 不运行 portability checker；
- 不使用动态 profile 封闭目标集合。

## Input

Milestone 00 的完整或显式不完整 `ProgramManifest` 与 `InstructionFact`。

## Output

```text
FunctionFact / BasicBlockFact / CallSite
IndirectTargetSet
ThreadRole
SynchronizationSummary
CFGCoverage
```

## Implementation

- angr CFGFast 提供 CFG 和候选目标，ELF/Capstone 事实负责校验原始指令。
- 每个间接站点保存 `known_targets/complete/evidence/reason`；只有封闭证据才能设置 complete。
- 恢复 pthread_create/join 的 start routine、参数来源、父子角色和 join 关系。
- 分析具体 libpthread 函数，区分 API 要求、实际 x86 指令和 DBT6 target ordering。
- 同步摘要绑定动态库哈希、函数地址范围和指令证据。

## Soundness hazards

- angr 候选被误当成完整目标集合；
- unresolved callback 被忽略；
- 根据 API 名称猜 target ordering；
- 对其他 glibc 版本复用当前 x86lib 摘要。

## Tests

- direct、PLT/GOT、jump table 和 unresolved function pointer；
- direct callback、callback table、多 create site、未知 start routine；
- mutex LOCK 原子路径；
- pthread_spin_unlock 普通 MOV；
- 未知同步实现传播为 Unknown。

## Acceptance criteria

- 每个 indirect site 都是 complete 或显式 incomplete；
- 未知 thread entry 产生 `UnknownThreadEntry`；
- 可能访问共享内存的 unresolved call 阻止未来 SAFE；
- 同步摘要不依赖源码或函数名猜测。

## Implemented

- `angr CFGFast` 恢复函数、基本块、调用点和间接站点；所有地址统一还原为 ELF PC。
- direct、PLT/GOT relocation、PLT0、固定初始化表和 angr jump-table 分别保存封闭证据。
- angr 只提供候选而没有封闭证据时，目标集合保持 `complete=false` 并产生 Unknown。
- 从 SysV `rdx/rcx` 调用实参恢复 `pthread_create` callback 和参数来源。
- 从 main/worker 入口沿直接调用图计算 create/join 所属角色；角色归属不唯一时产生 Unknown。
- 对实际 pthread 动态库逐函数生成三层摘要：API requirement、x86 指令证据、DBT target ordering。
- 同名版本化函数全部进入摘要，避免在缺少 version binding 时任选一个实现。
- 新增 `bmo-check recover`，一次输出 manifest、CFG、线程角色和同步摘要。

## Validation result

- 27 个测试通过，覆盖 direct、PLT、未封闭间接调用、jump-table 封闭条件、direct/unknown callback、join、LOCK 和 plain-store unlock。
- 本地 blackscholes：45 个函数、179 个基本块、65 个调用点；6 个间接站点中 3 个完整、3 个显式不完整。
- blackscholes worker 恢复为 `_Z9bs_threadPv@0xfbb`，create/join 归属 main role。
- 本地 `x86lib/libpthread.so.0`：`pthread_spin_lock@0xed00` 为 `AcqRel` 且路径完整；`pthread_spin_unlock@0xed40` 为 `Relaxed` 且路径完整。
- 复杂 pthread 函数含尚未组合的 callee 或 tail jump 时保持不完整摘要，不根据 API 名称提升 ordering。

## Boundary kept

本阶段没有生成 MemoryEvent、没有做共享对象剪枝，也没有输出 SAFE、UNKNOWN 或 COUNTEREXAMPLE verdict。顶层 Unknown 只是事实缺口，最终 verdict 仍只能由后续 proof 层生成。
