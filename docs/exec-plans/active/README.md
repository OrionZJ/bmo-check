# Active Milestones

当前计划合并为五个阶段，按顺序执行：

| Milestone | 状态 |
|---|---|
| 00 foundation + binary facts | COMPLETE |
| 01 program recovery + synchronization | COMPLETE |
| 02 shared state + communication slicing | PENDING |
| 03 portability proof + verdict | PENDING |
| 04 PARSEC evaluation | PENDING |

一次只实现一个 milestone。完成当前阶段的测试和 acceptance 后，才能进入下一阶段。

原 13 个细分计划保存在：

```text
docs/exec-plans/archive/pre-consolidation/
```

首版不实现 DBT launcher。证书驱动的 `mo-off/mo-fsm` 自动选择保留在 roadmap 中。
