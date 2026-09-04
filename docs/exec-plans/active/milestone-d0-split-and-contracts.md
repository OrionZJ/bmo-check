# D0 — Repository split and contracts

## Goal

保留静态实现并建立完全独立的动态 package、CLI、Trace IR、证书 schema 和 DBT contract。

## Non-goals

不修改 DBT6，不把动态结果叫作无条件 SAFE。

## Input / Output

输入是当前静态仓库与 `dbt6-mo-off.yaml`；输出为两个 namespace、两个命令入口、可 round-trip 的定长 trace 以及最小 DynamoRIO client。

## Soundness hazards

旧 import 残留会混用两种证书；截断记录若被当 EOF 会制造 false `TRACE_SAFE`。

## Tests

运行全部静态回归；测试 trace round-trip、版本错误、截断、sequence 逆序和 incomplete manifest。

## Acceptance criteria

旧静态测试结果不变；不存在 `bmo_check` namespace；默认 CLI 属于动态包；无效 trace 只能变成 `UNKNOWN`。
