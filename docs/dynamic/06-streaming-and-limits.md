# 流式存储与资源边界

原始事件按线程分块，Python 通过迭代器批量写入 DuckDB。事件页索引用于落盘 join，避免建立全量 Python 图。只有当前求解窗口会转换成 Python 对象。

资源边界包括：单次访问最大页数、批大小、单窗口事件数、候选执行数、符号公式项数和 solver 时间。`--max-symbolic-terms` 单独限制 Python/Z3 AST，因为这部分内存不受 DuckDB 的 memory limit 控制。任何边界触发都记录具体 event/window 并返回 `UNKNOWN`。

采集阶段还可用 `--max-thread-events` 限制每线程轨迹大小。超限会写入
`resource_limit` drop，而不是把截断轨迹当成完整输入。结构校验按定长记录
批量解包，避免为每个事件创建 Pydantic 对象。

对 dedup 等大程序，验收重点不是勉强完成一次，而是峰值内存随配置受控。不得用无界集合缓存全部地址对，也不得先构造全量笛卡尔积再过滤。
