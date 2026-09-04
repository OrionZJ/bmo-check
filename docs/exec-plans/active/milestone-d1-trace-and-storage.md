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
