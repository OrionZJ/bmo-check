# D3 — Campaigns and large-program evaluation

## Goal

对多输入、多次运行的轨迹分别验证，汇总覆盖率、性能和 verdict，并在大型程序上保持内存有界。

## Non-goals

多次通过不能升级成全程序 SAFE；本阶段不实现 DBT runtime guard。

## Input / Output

输入为 campaign YAML、程序、输入和 repeat；输出为独立 trace/certificate、总体 campaign 报告和资源指标。

## Soundness hazards

合并不同事件骨架可能产生不存在的程序序；丢弃 UNKNOWN 成员会错误提升总体结果。

## Tests

覆盖成员 SAFE/UNKNOWN/COUNTEREXAMPLE 的合取、重复名称、失败进程、PARSEC dedup 与 open_posix_testsuite 小集。

## Acceptance criteria

每次运行保留独立证书；总体 `TRACE_SAFE` 要求所有成员 `TRACE_SAFE`；dedup 超预算时受控落盘或 `UNKNOWN`，不能被 OOM kill。

## 2026-09-06 进展

- 已覆盖用户指定的 12 个 PARSEC 程序，详见
  `docs/dynamic/08-parsec-all-programs.md`。
- client 增加每线程事件预算；超限显式产生 `resource_limit` drop。
- 结构校验改为批量解包。1.1178 亿事件在约 45 MiB RSS 下扫描完成。
- analyzer 0.4.0 与 client 0.5 已采集 syscall 参数和返回值，并按实际
  地址、线程阶段及对象生命周期闭合第一批 effect；旧格式仍保守返回
  `UNKNOWN`。
- 代表性重跑中，swaptions 与 canneal 已越过 syscall 预检并进入通信分析；
  blackscholes 只剩一个具体 futex。D3 尚未验收，下一步是闭合并发
  futex/I/O 等 effect、切分大型通信窗口，并实现多次 campaign 覆盖去重。

## 2026-09-19 收尾进展

- `campaign-v2` 已改为逐成员写独立 certificate，并在最终摘要中只保留可审计
  的成员元数据；不再把每份完整 certificate 长期堆在 Python 列表里。
- campaign 聚合严格保留失败成员和 `UNKNOWN`：只有所有成员为 `TRACE_SAFE`
  才能得到总体 `TRACE_SAFE`；`COUNTEREXAMPLE` 和 `UNKNOWN` 都不能因去重消失。
- 每个成员记录 trace bytes、事件/PC 数、capture/analyze 时间、RSS（可用时）、
  resource-limit 标记和稳定内容去重键。没有稳定摘要的失败成员仍单独计入存储。
- determinate 成员在 campaign 聚合前默认调用动态 certificate independent replay；
  重放失败会把该成员降为 `UNKNOWN` 并保留原错误，不会把 producer 的 `SAFE`
  结果直接汇总。
- 新增 `bmo-check verify CERTIFICATE --trace TRACE --dbt-contract CONTRACT`，
  可在不运行 workload 的情况下独立重放单条动态证书。
- duplicate run name、已有输出目录、空/非法命令和零次 repeat 在输入层拒绝；
  capture/analysis 失败写成 `UNKNOWN` 成员而不是让整个 campaign 静默缺行。
- 仍需完成默认回归和受控 PARSEC/open_posix 小集复核，才能把本 milestone 标为
  完整验收；本阶段不改变 memory-model checker 或 `TRACE_SAFE` 语义。
