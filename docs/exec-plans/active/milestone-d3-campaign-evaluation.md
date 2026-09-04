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
