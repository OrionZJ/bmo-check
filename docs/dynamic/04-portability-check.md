# 轨迹可移植性检查

每个窗口枚举 read-from、每地址 coherence 和 from-read。初始写是每个 read 的候选；同线程未来写不能成为该 read 的来源。coherence 必须保留同线程同地址写顺序。

x86-TSO preserved order 保留 Load→Load、Load→Store、Store→Store，普通 Store→Load 可以放松。目标模型不为普通访存增加顺序；LFENCE、SFENCE、MFENCE 和 atomic 按 DBT contract 补边。同步 API 名称本身不产生 target ordering，库内部实际 atomic/Fence 才能产生。

若某个关系图在 target 无环、在 source 成环，它是 target-only candidate。只有 trace 声明控制骨架闭合，且所有 read-from 的值均有记录并匹配时，candidate 才能成为 `COUNTEREXAMPLE`；否则返回带 witness 的 `UNKNOWN`。

所有 target 候选均被 source 接受时，窗口为 safe。所有通信窗口 safe 且 trace 完整时，最终才是 `TRACE_SAFE`。
