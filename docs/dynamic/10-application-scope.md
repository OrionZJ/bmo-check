# Application scope 证明

`--application-only` 不是把 full scope 的 `UNKNOWN` 改名成 `TRACE_SAFE`。它
先在主 ELF 的实际 PC 范围内检查三个条件：每个 worker 的普通写范围互不重叠、
worker 存活期间主线程没有冲突写入、轨迹完整。任一条件不满足，仍返回 `UNKNOWN`。

如果完整轨迹只有一个线程实例，分区直接标记为 safe：线程集合中没有第二个
访存者，不可能形成跨线程通信边。这只适用于这条完整轨迹，不能外推到其他线程配置。

条件成立后，优先检查是否有唯一的 create/start/end/join 交接证据。若交接完整，
“应用无共享写”已经是普通应用通信为空的充分条件，工具不再把运行库热页送入
通信图，并将 `communication_edges_complete=false` 写入证书。此时
`communication_edge_count=0` 只表示边未枚举，不能解释成进程没有边；运行库的
LOCK/XCHG、显式 Fence 和 pthread/系统调用契约仍由 DBT contract 承担。

若交接证据不足，工具仍执行通信扫描。此时原始边保留在
`communication_edge_count` 中，只有两端 PC 都在外部运行库的边会从窗口中排除，
其数量写入 `external_runtime_edge_count`。

应用 PC 范围内只要出现 `ATOMIC_RMW`，就不会走这个快速路径；原子访问可能与
普通访问共同发布数据，必须回到通信扫描和窗口求解。

因此该模式回答的是一个更窄的问题：主程序的普通共享数据是否需要额外的
`mo-off` Fence。它不能证明 libc、间接调用未覆盖的路径、其他输入或未来调度。
要声称整个进程安全，仍必须使用默认 full scope，并闭合运行库访问的值和控制可行性。

如果主模块分区已经失败，工具会立即返回 `UNKNOWN`，不再把运行库边送入通信图。
这是资源边界而不是证明放宽：这些边没有被证明安全，分析器只是避免在已知失败的
情况下为百万级运行库访问建立 Python 图。

当前 PARSEC 复核中，使用新 client 0.6 的 blackscholes 与 swaptions 均满足主模块
分区条件；full scope 分别留下 12 和 67 条运行库边，而 application scope 能够
把这些被审计的外部边排除并生成 `TRACE_SAFE`。canneal 和 streamcluster 也通过了
主模块分区与线程交接检查，其中 streamcluster 通过“无共享写”充分条件关闭了
百万级运行库热页。
