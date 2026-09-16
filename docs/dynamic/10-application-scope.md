# Application scope 证明

`--application-only` 不是把 full scope 的 `UNKNOWN` 改名成 `TRACE_SAFE`。主 ELF
的 PC 范围必须先从 trace 的 module map 唯一恢复；缺失时仍返回 `UNKNOWN`。
随后分析器检查 worker 之间是否有普通写重叠、worker 存活时主线程是否有冲突写入。
这些条件决定能否走快速路径，不是 application-only 结论的唯一依据。

如果完整轨迹只有一个线程实例，分区直接标记为 safe：线程集合中没有第二个
访存者，不可能形成跨线程通信边。这只适用于这条完整轨迹，不能外推到其他线程配置。

只有分区证明 worker 普通写范围互不重叠、主线程没有冲突写，并且 create/start/end/join
交接唯一时，分析器才使用“应用普通通信为空”的快速路径。此时不枚举运行库热页，
并将 `communication_edges_complete=false` 写入证书。`communication_edge_count=0`
只表示边未枚举，不能解释成进程没有边；运行库的 LOCK/XCHG、显式 Fence 和
pthread/系统调用契约仍由 DBT contract 承担。

快速路径不适用时——包括分区发现真实 worker 写重叠、交接证据不足或主 ELF 含
`ATOMIC_RMW`——分析器改做精确通信扫描，不把分区失败直接当成 `UNKNOWN`。
只扫描至少含一个主 ELF 访存的页。精确地址区间相交后，主 ELF 与运行库之间的混合边
仍会进入窗口；只有两端 PC 都在外部运行库的边才跳过，数量记入
`external_runtime_edge_count`。过滤发生在逐边扫描时，不会先把纯运行库边装进内存、
也不会让它们触发 application-scope 的通信边预算。完整扫描时，
`communication_edge_count` 记录过滤前的精确总数。若应用相关边超过预算、活动页超限
或扫描中断，证书保留 `UNKNOWN`；若全部窗口闭合，分区证据可以保持 `unknown`，
但不会阻止窗口 checker 给出 trace-bound 结论。

因此该模式回答的是一个更窄的问题：主程序的普通共享数据是否需要额外的
`mo-off` Fence。它不能证明 libc、间接调用未覆盖的路径、其他输入或未来调度。
要声称整个进程安全，仍必须使用默认 full scope，并闭合运行库访问的值和控制可行性。

当前 PARSEC 复核中，使用新 client 0.6 的 blackscholes 与 swaptions 均满足主模块
分区条件；full scope 分别留下 12 和 67 条运行库边，而 application scope 能够
把这些被审计的外部边排除并生成 `TRACE_SAFE`。canneal 和 streamcluster 也通过了
主模块分区与线程交接检查，其中 streamcluster 通过“无共享写”充分条件关闭了
百万级运行库热页。
