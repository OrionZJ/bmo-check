# Decision — 使用 Z3 构建首版有限可移植性检查器

Date: 2026-08-28

## Problem

Milestone 3 需要比较同一有限执行在 x86-TSO 与 DBT6 `mo-off + RVWMO` 下是否可行，
并且必须区分“找到反例”和“界限内没找到”。checker 还要把 PC、read-from、coherence
和缺失顺序写进证书。

## Options

### Option A — herd7/cat

优点是模型生态成熟。缺点是要把 BMoCheck 的二进制事件、proof object 和 Unknown 转成
外部格式，证书还需重新绑定外部工具版本与输出。

### Option B — 自建枚举器

直接枚举 read-from、coherence 和总序。实现简单，但组合爆炸快，超时与反例解释都较难控制。

### Option C — Z3 有限公理编码

用布尔变量选择 read-from/coherence，用 rank 约束 preserved program order、rf、co 和 fr
无环。先求 target 执行，再固定同一 rf/co 检查 source。

## Decision

选择 Option C。首版支持普通对齐 1/2/4/8 字节 Load/Store、精确 Global alias class、
AcqRel RMW、显式 Fence、完整 program order 和有限 thread role。模型版本写入 certificate。

共享通信已经被 proof object 全部消除时，verifier 可给结构性 `SAFE`。只要进入有限 checker，
没有反例的结果一律是 `UNKNOWN`；只有 target 可满足且 source 对同一 rf/co 不可满足时才输出
`COUNTEREXAMPLE`。

## Soundness Impact

可能造成 false SAFE 吗？

不会把 bounded no-counterexample 当成 `SAFE`。Unknown、开放间接目标、不完整线程角色、
不完整同步摘要、mixed-size、misaligned、未知地址、非线性 program order 和超界输入都会阻止
`SAFE`。

target 中尚未闭合的 load→store 依赖按“存在依赖”保守保序。这可能漏报反例，但不会制造
target 实际不允许的反例。checker 找到的反例必须同时带 source 拒绝环。

新增 Unknown：

- `UnsupportedPortabilityInput`
- `PortabilityCheckTimeout`
- `PortabilityCheckBound`
- `StaleCertificate`

## Evidence

- plain Store publication 测试能找到 `flag=new, data=initial` 的 target-only rf 执行；
- 双侧 full Fence 与 AcqRel 原子发布会排除该反例，但结果仍是 bounded `UNKNOWN`；
- certificate validator 拒绝把 bounded 结果包装为 `SAFE`；
- stale scope 检查覆盖 binary、library、DBT revision、执行参数和 checker limits。

## Revisit When

- 需要支持循环的多实例展开；
- MemoryEvent 能携带完整 data/address/control dependency；
- 需要 mixed-size 或 misaligned 模型；
- 引入 herd7 作为独立交叉验证后端。
