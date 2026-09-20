# Application scope 证明

`--application-only` 不是把 full scope 的 `UNKNOWN` 改名成 `TRACE_SAFE`。主 ELF
的 PC 范围必须先从 trace 的 module map 唯一恢复；缺失时仍返回 `UNKNOWN`。
随后分析器检查 worker 之间是否有普通写重叠、worker 存活时主线程是否有冲突写入。
这些分区事实只用于解释和缩小候选页，不能代替通信图扫描。

如果完整轨迹只有一个线程实例，分区直接标记为 safe：线程集合中没有第二个
访存者，不可能形成跨线程通信边。这只适用于这条完整轨迹，不能外推到其他线程配置。

即使分区证明 worker 普通写范围互不重叠、主线程没有冲突写，并且 create/start/end/join
交接唯一，分析器仍会对候选页做流式通信扫描。`communication_edge_count=0` 只有在
候选页完整扫描并确认没有精确重叠边时才有意义；没有完成扫描时必须记录
`communication_edges_complete=false` 并返回 `UNKNOWN`。运行库的 LOCK/XCHG、显式 Fence
和 pthread/系统调用契约仍由 DBT contract 承担，不能用分区事实把它们删除。

扫描器只读取至少含一个主 ELF 访存的候选页；没有主 ELF 访存时会扫描全部候选页，避免
把运行库访问误当作“没有通信”。精确地址区间相交后，主 ELF 与运行库之间的混合边
仍会进入窗口；只有两端 PC 都在外部运行库的边才跳过，数量记入
`external_runtime_edge_count`。过滤发生在逐边扫描时，不会先把纯运行库边装进内存、
也不会让它们触发 application-scope 的通信边预算。覆盖账本同时记录候选页、扫描的
event-page 记录、页级过滤数量和资源限制原因。完整扫描时，
`communication_edge_count` 记录过滤前的精确总数。若应用相关边超过预算、活动页超限
或扫描中断，证书保留 `UNKNOWN`；若全部窗口闭合，分区证据可以保持 `unknown`，
但不会阻止窗口 checker 给出 trace-bound 结论。

因此该模式回答的是一个更窄的问题：主程序的普通共享数据是否需要额外的
`mo-off` Fence。它不能证明 libc、间接调用未覆盖的路径、其他输入或未来调度。
要声称整个进程安全，仍必须使用默认 full scope，并闭合运行库访问的值和控制可行性。

历史 PARSEC 复核曾经用 application-only 分区快速路径生成过 blackscholes、
swaptions、canneal 和 streamcluster 的 `TRACE_SAFE`。C0.1 之后，分区和线程交接
不再代替通信扫描；这些旧证书只能作为历史实验记录。当前重跑必须重新枚举候选页，
无法闭合时返回 `UNKNOWN`，不能复用旧 verdict。
