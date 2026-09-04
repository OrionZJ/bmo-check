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
