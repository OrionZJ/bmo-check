# 动态诊断快照与静态缺口定位

动态诊断不是第二个静态证明器。`bmo_check_dynamic.adapters` 先验证 trace，
再把事件文件流式折叠成 `DynamicDiagnosticSnapshot`；它只保留 trace-bound
`ObservedFact` 和 trace-scoped `UnknownFact`，不把原始事件表整体读进 Python。

每个可归一化的访存、原子、显式 Fence、间接目标或 signal 站点至少绑定：

- `TraceId`、线程实例和 module content hash；
- mapping-relative PC 与 ELF-relative PC；
- event kind、访问宽度/地址范围和 operand discriminator（旧 trace 缺失时记为
  `operand_identity=missing`）；
- 对间接目标，记录实际 target 地址范围。

module map 中没有闭包 fingerprint 的映射、坏记录、丢事件、缺少 `.complete`
尾部标记或站点预算耗尽，都会保留已经读到的观察，同时追加动态
`UnknownFact` 并将 `complete` 设为 false。诊断报告不能把这种快照当成完整
`TRACE_SAFE` 证书。

`bmo_check_diagnostics.correlate_unknowns` 的顺序是：先比较稳定 subject，再用
静态 provenance 中的 `legacy.module/legacy.pc/legacy.kind` 与动态 ELF-relative
位置回查旧适配器事实。二进制闭包不一致直接是 `Unmatched`；缺少 operand 或
同一站点有多个静态候选是 `Ambiguous`。相关结果只生成 `DiagnosticHint`，不
创建 `ProofFact`、不关闭 Unknown，也不改变静态 verdict。

```text
validated trace
    -> bounded DynamicDiagnosticSnapshot
    -> Exact / Ambiguous / Unmatched correlation
    -> D5 DiagnosticRootCause hint
    -> developer changes static analysis
    -> fresh pure-static run
```

只有新的纯静态 `ProofFact` 才能关闭静态 Unknown。观察到的地址、线程不重叠、
间接目标或某次运行的值都不能直接成为 `NoAlias`、`Disjoint` 或 `SAFE` 依据。

## UnknownAffineBounds 观察

E1 的 `ObservedAffinePattern` 只汇总已匹配的动态地址样本：每个站点和线程
有界保存首次地址、范围、相邻差分候选以及样本是否截断。`Stable` 表示当前
trace 集合中的差分没有变化，不表示静态循环上界、线程 disjoint 或 affine
proof。样本集合达到上限、trace 不完整或 operand 相关不唯一时，报告保留相应
`Incomplete`/`Ambiguous` 状态。

E2 的 `AffineValidationReport` 单独列出 canneal（或任何其他输入）的 affine
Unknown 覆盖。它把 `exercised`、`ambiguous`、`unmatched` 和明确没有动态候选的
`not_executed` 分开，并原样复制静态 verdict。`--affine-output` 生成的文件不
进入静态证书，也不能关闭 Unknown；只有后续纯静态分析产生新的 `ProofFact`
才可以改变静态结论。

当 `diagnose` 同时指定 `--affine-output` 和 `--trace` 时，如果静态 Unknown 的
provenance 含有模块/PC，适配器会以这些位置作为 `site_filter`。原始 trace 仍
完整扫描，过滤只减少保留的观察站点；因此不会把未选中的路径当成已经执行。
