# D1 — Complete trace and streaming storage

## Goal

记录访存、边界、线程、同步、对象、module 和间接目标，并以有界内存导入 DuckDB。

## Non-goals

本阶段不生成最终 verdict，也不根据一次调度删除候选通信。

## Input / Output

输入为 Linux x86-64 ELF、argv、环境和 DynamoRIO；输出为 manifest、每线程事件文件、完整性 marker 和 DuckDB 事件/页索引。

## Soundness hazards

插桩失败、文件写失败、异常退出、地址复用或漏掉动态库访存都可能把真实通信误删。

## Tests

覆盖 pthread/OpenMP、LOCK/XCHG、Fence、malloc/free/realloc、mmap、dlopen、间接分支、signal、syscall 和 dropped event 注入。

## Acceptance criteria

所有失败都有显式 dropped/Unknown；地址复用产生新 generation；导入峰值内存不随 trace 总大小线性增长。

## 当前验收证据

2026-09-05 在 WSL2 使用真实 DynamoRIO client 跑过 pthread、OpenMP、同步 API 和
不支持共享映射测试；最终全仓 161 项测试通过。`.complete` 现在只在 dropped 计数、
drop reason 和 module 清单落盘后创建，证书哈希也绑定这些文件。写失败、module
宽度溢出和 allocation 尺寸溢出都会阻止 `TRACE_SAFE`。

D1 已达到本阶段验收条件。syscall 用户缓冲区 effect 尚未采集时由 D2 完整性门
返回 UNKNOWN；它不会被当作已建模的普通访存。
