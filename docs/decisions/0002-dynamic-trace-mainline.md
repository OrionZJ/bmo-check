# Decision 0002: dynamic trace becomes the main line

## Status

Accepted.

## Context

静态二进制分析在真实程序中反复遇到无法封闭的间接跳转、线程入口、地址 provenance 和库内部效果。严格 SAFE 要传播这些 Unknown，最终多数 benchmark 无法获得有用结论。

## Decision

默认路线改为 DynamoRIO 动态采集加离线内存模型比较。原静态实现完整保留为 `bmo_check_static`。动态结果使用 `TRACE_SAFE`，不复用静态 `SAFE`。

## Consequences

实际目标、线程和地址在已执行轨迹中成为确定事实，能显著减少静态恢复型 Unknown。代价是结论不覆盖未执行路径，因此本阶段不能自动批准未来运行使用 `mo-off`。若以后需要这种能力，必须单独设计运行时守卫与偏离前回退。
