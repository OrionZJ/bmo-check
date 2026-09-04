# Milestone 02 — Shared State and Communication Slicing

## Status

COMPLETE（2026-08-28）

## Goal

生成 MemoryEvent，证明基础 ThreadLocal/ReadOnly/Disjoint 事实，并构建不丢 Unknown 的共享内存切片。

## Non-goals

- 不对任意 heap shape 做完整 points-to；
- 不让动态 profile 成为证明依据；
- 不生成最终 verdict。

## Input

前两阶段的 binary、CFG、thread role 和 synchronization facts。

## Output

```text
MemoryEvent
AbstractAddress
ProofObject
SharedObject
SharedMemorySlice
PruningCoverage
```

## Implementation

- 将 VEX 内存效果与 Capstone 原始证据归一化为 backend-independent MemoryEvent。
- 地址域支持 Global、TLS、Stack、Heap、Affine 和 Unknown。
- 默认使用 MayAlias、SharedUnknown 和 UnknownEscape。
- 实现基础 escape、ThreadLocal、ReadOnlyAfterCreate 和共享对象分析。
- 使用区间推理和 Z3 证明不同 tid 的仿射写入集合不相交。
- 每个被移除事件保存 proof reason 和 supporting facts。
- 只保留不同并发角色、MayAlias、至少一个 Store 且尚未证明无通信的事件。

## Soundness hazards

- 把 stack 或 malloc 自动当作私有；
- 因地址未知而静默删除事件；
- 用一次动态运行证明分片不重叠；
- benchmark 名称影响地址或剪枝结论。

## Tests

- TLS、未逃逸 stack、stack pointer 传线程、opaque escape；
- create 前初始化且 worker 只读；
- 固定分片、符号分片、重叠分片和未知 bounds；
- Unknown memory effect 留在 slice；
- pruning proof object round-trip。

## Acceptance criteria

- 分析失败不能产生 empty shared set；
- 每个剪除事件都有可解释 proof object；
- blackscholes/swaptions 的分片公式不硬编码程序名；
- slice 保存线程、事件、程序顺序、alias、同步边和 Unknown。

## Implemented

- 从 reachable CFG block 和 Capstone 指令事实生成 backend-independent MemoryEvent。
- 普通 read/write、非原子 read-modify-write、LOCK/XCHG、显式 fence、syscall、pthread lifecycle 和 opaque call 均保留为独立事件。
- x86 source ordering 与 DBT target ordering 分开记录；普通访存为 `TSO -> Relaxed`，LOCK/XCHG 为 `Full -> AcqRel`。
- 地址域支持 Global、TLS、Stack、Affine 和 Unknown；寄存器地址没有闭合 bounds 时保持 MayAlias。
- 从 main/worker 入口沿调用图复制线程角色事件，并为未知 worker、未封闭间接 jump 和提取器失败生成 UnknownMemoryEffect 哨兵。
- program-order 只来自块内指令顺序和 CFG successor，不按 PC 猜跨分支顺序。
- TLS 只有在没有地址物化和 wildcard effect 时剪除；stack 只有在函数未物化 frame 地址时剪除。
- ReadOnlyAfterCreate 同时要求 writer 位于 main、worker 无 writer、writer 到 create 的 CFG 路径闭合，且实际 `pthread_create` target summary 至少为 Release。
- 仿射分片使用 Z3 检查不同 tid 的整个有界写集合；缺少 bounds、存在重叠或外部 wildcard 时不剪除。
- Unknown address、opaque call、syscall 和 unknown thread entry 全部留在 slice，并与可能冲突的事件建立 MayAlias candidate。
- 每个 removed event 都由 ProofObject 覆盖；模型校验器拒绝无证明的剪除记录。
- 新增 `bmo-check slice`，一次输出 recovery、MemoryEvent、shared objects、proofs 和 shared-memory slice。

## Validation result

- 36 个测试通过；synthetic/integration 覆盖 TLS、未逃逸 stack、传线程或 opaque call 的 stack pointer、具体 create Release 下的只读初始化、仿射不相交、重叠、缺失 bounds、Unknown effect 和提取器失败哨兵。
- 本地 blackscholes 生成 634 个事件；217 个事件以 ThreadLocal proof 剪除，417 个事件保留。
- blackscholes 保留 122 个 unknown event、9463 条冲突候选和所有 178 条 Unknown，未因分析困难得到空 shared set。
- blackscholes 当前没有 ReadOnly/Disjoint 剪除；缺少具体生命周期 ordering 或仿射 bounds 时保持保守结果。
- 源码中没有 benchmark 名称分支；仿射证明只读取地址式、tid bounds 和 index bounds。

## Boundary kept

本阶段只产生 proof-carrying slice。它不比较 x86-TSO 与 RVWMO，不生成 SAFE、UNKNOWN 或 COUNTEREXAMPLE verdict；这些工作仍属于 Milestone 3。
