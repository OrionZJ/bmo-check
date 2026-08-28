# Milestone 02 — Shared State and Communication Slicing

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
