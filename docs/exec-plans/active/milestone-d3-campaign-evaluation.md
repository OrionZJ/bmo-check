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
