# D2 — Communication and portability proof

## Goal

从动态地址恢复通信窗口，比较 x86-TSO 与 DBT6 `mo-off + RVWMO` 并生成严格证书。

## Non-goals

不证明未执行控制流，不把未验证 candidate 报为 COUNTEREXAMPLE。

## Input / Output

输入为完整 DuckDB trace 和 DBT contract；输出为 `TRACE_SAFE`、`COUNTEREXAMPLE` 或 `UNKNOWN` 证书。

## Soundness hazards

使用全局记录顺序、忽略初始写、错误限制 read-from、拆散超限窗口或把 mixed-width 当成同地址都可能造成 false SAFE。

## Tests

覆盖 L→L、L→S、S→S、S→L、LB、SB、MP、IRIW、atomic、三种 Fence、只读共享、thread-local、部分重叠和超限。

## Acceptance criteria

只有完整 trace 的全部窗口安全才能 `TRACE_SAFE`；已知 target-only litmus 有复核 witness；不支持编码稳定返回 `UNKNOWN`。

## 当前验收证据与剩余项

`tests/dynamic/test_litmus_matrix.py` 对 MP、SB、LB、IRIW 及相应 Fence 版本分别运行
枚举和 Z3，另覆盖四类普通访存程序序。无值/控制证明的 target-only 候选必须
保持 UNKNOWN。`test_atomic_relations.py` 覆盖 RMW 紧邻前驱、自环和初始读漏边。

生产轨迹没有值或控制路径闭合时，target-only candidate 仍返回 UNKNOWN；D2 不把
它升级为 COUNTEREXAMPLE。生命周期剪枝已经撤回。测试中的独立稠密关系定义会
穷举短序列，对照生产稀疏图的可达关系；另有专门测试覆盖同线程 store forwarding、
混合宽度和依赖缺失时的保守方向。

blackscholes 的严格复查显示，原 7,949 事件巨窗中 7,371 条通信边来自主线程
初始化写与 worker 输入读，worker 间只有 3 条边。不能用生命周期 ticket 删除前者。
x86 PPO 已换成保持同一可达关系的稀疏边，RVWMO 也补入明文规定的
overlapping-address order；普通混合宽度写可进入符号 coherence。byte-level
read-from 现已按写边界切分普通 Load，并在各片段上建立 rf/fr；混合宽度
原子仍拒绝。7,949 事件实验已继续推进到符号公式构造阶段。公式构造现在与 solver
共享时间预算，并受独立项数上限约束，不会在超限后继续堆积 Z3 AST。默认
100,000 项预算下，该实验用 46.6 秒、约 182 MiB 稳定返回 UNKNOWN；约 45 秒用于
重建通信窗。此前没有公式项预算时峰值约 716 MiB。

D2 已达到“首个严格证明闭环”的验收条件：完整、受支持且所有窗口 UNSAT 才能
TRACE_SAFE；闭合值与控制骨架的 target-only litmus 产生可复核 COUNTEREXAMPLE；
其余情况稳定 UNKNOWN。继续恢复生产轨迹值、依赖和 syscall effect 会减少 UNKNOWN，
但不属于首个闭环正确性的前置条件。
