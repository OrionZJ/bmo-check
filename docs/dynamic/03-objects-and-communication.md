# 动态对象与通信边

Heap 和 mmap 对象使用 `kind:base:generation` 标识。free/munmap 后再次出现相同数值地址时必须增加 generation，防止不同生命周期被错误连接。

通信边同时满足：线程不同、实际字节范围相交、至少一端写入。页号只用于缩小候选集合，最终必须重新检查精确区间。只读共享、同线程访问和不相交地址不会进入求解器。

TLS 标签不能证明地址没有逃逸。数值地址重叠时，即便对象标签不同也保留候选；
仅同类同基址的不同 generation 使用已有生命周期筛选。扫描活动集合超过
100,000 个事件时返回 UNKNOWN，避免只读热点在产生第一条边前耗尽内存。

当前求解器支持同址同宽访问、Store 完整覆盖较窄 Load，以及按重叠写边界切分的宽 Load。普通混合宽度写进入 overlap-connected coherence；混合宽度 RMW 仍返回 `UNKNOWN`。

通信图按连通分量切窗，并把同一线程两端之间的 Fence/atomic/sync 边界带入窗口。窗口超过配置上限时不得拆掉关键边后继续证明。

THREAD_START 和 join 的 ticket 只描述观测到的生命周期，不能单独当作排序边。
当前分析器只有在同一个父线程同时看到成功的 THREAD_CREATE、子线程的
THREAD_START/THREAD_END 和成功的 THREAD_JOIN 时，才把父线程 create 前的访问与
子线程 start 后的访问、以及子线程退出前的访问与父线程 join 后的访问从通信候选中
删除。删除的是 pthread 已经提供的共同 happens-before，不是把 ticket 的数值顺序
当作同步。

native client 优先用 clone 返回的 child tid 配对 THREAD_CREATE；wrapper 只提供
pthread handle 时，必须存在唯一的时间候选。出现缺失、重复或歧义时保留所有边，
宁可让窗口变大，也不能把两个 worker 的发布边界接反。

成功的 FUTEX_WAIT 会在落盘时物化为 `FUTEX_WAIT` 读事件。它只读取同步字并保留
read-from 边；FUTEX_WAKE、失败等待和未知 futex 操作仍由 syscall effect 门拒绝。

DuckDB 缓存受 `--database-memory-limit-mb` 硬限制。轨迹按 batch 导入，数据库在
达到上限后使用临时落盘；不能依赖操作系统在内存耗尽后杀死分析器。
