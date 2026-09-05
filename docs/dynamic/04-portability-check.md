# 轨迹可移植性检查

每个窗口枚举 read-from、每地址 coherence 和 from-read。初始写是每个 read 的候选；同线程未来写不能成为该 read 的来源。coherence 必须保留同线程同地址写顺序。

x86-TSO preserved order 保留 Load→Load、Load→Store、Store→Store，普通 Store→Load 可以放松。目标模型不为普通访存增加顺序；LFENCE、SFENCE、MFENCE 和 atomic 按 DBT contract 补边。同步 API 名称本身不产生 target ordering，库内部实际 atomic/Fence 才能产生。

若某个关系图在 target 无环、在 source 成环，它是 target-only candidate。只有 trace 声明控制骨架闭合，且所有 read-from 的值均有记录并匹配时，candidate 才能成为 `COUNTEREXAMPLE`；否则返回带 witness 的 `UNKNOWN`。

所有 target 候选均被 source 接受时，窗口为 safe。所有通信窗口 safe 且 trace 完整时，最终才是 `TRACE_SAFE`。

宽 Store 完整覆盖窄 Load 时，read-from 绑定到同一个写事件，并按小端偏移比较值。
两个不同宽度的写发生重叠，或一个 Load 需要拼接多个局部写时，当前编码仍返回
`UNKNOWN`；不能用拆成独立字节的 source 过近似冒充 x86 原子访问。

小窗口先用显式 read-from/coherence 枚举，便于生成直观 witness。排列超过执行预算
时改用 Z3 直接求“target 无环且 source 有环”；`UNSAT` 才能关闭窗口，超时仍返回
`UNKNOWN`。默认窗口上限为 64 个保留事件，超过上限不会自动扩大。

RMW 在关系图中共用一个读写节点，内部读到内部写不生成 from-read 自环。
原子读必须来自 coherence 中紧邻的前驱写；读初始值时该 RMW 必须是首个写。
当前 Trace IR 只有一个 value 字段，包含 RMW 的候选不能凭该字段同时验证旧值与
新值，因此仍需返回 UNKNOWN。超过 12 个访存或单地址超过 6 个写时直接进入
符号求解，避免在执行预算检查前展开阶乘数量的排列。
