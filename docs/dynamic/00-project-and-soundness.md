# 动态项目定义与 soundness contract

BMoCheck 动态主线回答：给定一条完整的原生 x86-64 动态轨迹，把同一组线程内事件和实际地址交给 DBT6 `mo-off + RVWMO` 后，是否存在 x86-TSO 不允许的新执行。

`TRACE_SAFE` 只覆盖证书里的事件骨架。未执行路径、其他输入、不同循环次数、不同地址和值驱动的新控制流都不在结论内。它不能直接批准任意未来运行使用 `mo-off`。

SAFE 主线采用 target 过近似：记录到的墙上时间和线程交错不能删除 read-from 或 coherence 候选。过近似的 UNSAT 可以给出 `TRACE_SAFE`；SAT 若不能闭合值和控制路径，只能给出 `UNKNOWN`。

以下情况必须 `UNKNOWN`：trace 截断、dropped event、未知格式、零宽访存、JIT/self-modifying code、跨进程共享内存、不支持的混合宽度编码、窗口或枚举超限。
