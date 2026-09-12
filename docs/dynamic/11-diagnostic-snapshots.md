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
