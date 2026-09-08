# Application scope 证明

`--application-only` 不是把 full scope 的 `UNKNOWN` 改名成 `TRACE_SAFE`。它
先在主 ELF 的实际 PC 范围内检查三个条件：每个 worker 的普通写范围互不重叠、
worker 存活期间主线程没有冲突写入、轨迹完整。任一条件不满足，仍返回 `UNKNOWN`。

条件成立后，通信扫描得到的原始边仍保留在证书的
`communication_edge_count` 中。只有两端 PC 都在外部运行库的边会从窗口中排除，
其数量写入 `external_runtime_edge_count`。证书的 `analysis_scope` 为
`application`，并声明运行库的 LOCK/XCHG、显式 Fence 和 pthread/系统调用契约由
DBT contract 承担；这些边没有被当成“没有发生”。

因此该模式回答的是一个更窄的问题：主程序的普通共享数据是否需要额外的
`mo-off` Fence。它不能证明 libc、间接调用未覆盖的路径、其他输入或未来调度。
要声称整个进程安全，仍必须使用默认 full scope，并闭合运行库访问的值和控制可行性。

当前 PARSEC 复核中，使用新 client 0.6 的 blackscholes 与 swaptions 均满足主模块
分区条件；full scope 分别留下 12 和 67 条运行库边，而 application scope 能够
把这些被审计的外部边排除并生成 `TRACE_SAFE`。canneal 的主模块存在 worker 写冲突，
不会被这个模式放行。
