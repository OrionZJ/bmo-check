# D1/D2 验收矩阵

验收日期：2026-09-05。分析器版本 0.3.0，动态证书 schema 1.1。

| 要求 | 权威证据 | 结论 |
|---|---|---|
| 访存、LOCK/XCHG、Fence、线程、同步、对象、module、间接目标、signal/syscall 采集 | `tests/dynamic/test_native_capture.py` 使用真实 DynamoRIO client 检查全部 event kind、flags 和返回码 | 通过 |
| 截断、丢事件、异常退出、未知字段不得产生 SAFE | `test_trace_format.py`、`test_pipeline.py` 覆盖 marker、sequence、格式、drop 和退出码 | 通过 |
| 流式存储、对象 generation、地址复用 | `TraceStore` 使用固定 batch COPY 与 DuckDB memory limit；`test_objects.py`、`test_communication.py` 覆盖 generation 和扫描上限 | 通过 |
| 精确跨线程字节相交通信边 | `test_communication.py` 覆盖跨页、非对齐、只读、TLS escape、不同 generation 和活动集合上限 | 通过 |
| 可扩展且不拆散关系环的窗口 | 迭代式双连通分解覆盖 2,500 节点深图；Fence/atomic 在分解前加入边界骨架 | 通过 |
| x86-TSO 与 mo-off/RVWMO 差分 | MP、SB、LB、IRIW、四类程序序、三种 Fence、RMW、混合宽度和 store forwarding 测试；独立稠密定义穷举长度 1–4 的短序列 | 通过首个闭环 |
| 三态证书与 explain | 原生单线程产生 TRACE_SAFE；闭合 litmus 产生 COUNTEREXAMPLE；pthread/OpenMP opaque syscall 产生 UNKNOWN | 通过 |
| 大型真实程序 | blackscholes 当前证书绑定 233,460 事件、3 线程及完整 trace digest，因 60 个 opaque syscall 严格 UNKNOWN；10,000 节点诊断受 100,000 公式项预算控制 | 通过，结论为 UNKNOWN |
| 结论范围 | `TraceScope.limitation` 与 explain 明示只覆盖证书绑定的事件骨架，不覆盖其他输入、路径或未来调度 | 通过 |
| 不修改 DBT6 | 本阶段提交只位于 BMoCheck 仓库 | 通过 |

最终命令：

```bash
export DYNAMORIO_HOME=/home/hezhj/.local/opt/dynamorio
~/.local/bin/uv run pytest -q
```

结果：`161 passed in 82.55s`。

blackscholes 当前证书位于本地实验目录
`.bmo-check/traces/blackscholes-test/certificate-current.json`：schema 1.1、analyzer
0.3.0、`trace_complete=true`、verdict UNKNOWN。通信边计数为 0 是因为 opaque syscall
在预检阶段终止分析，不能解释为程序没有通信。
