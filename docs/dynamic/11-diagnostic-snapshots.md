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

完整 workflow 使用 `bind_dynamic_certificate_to_trace` 生成
`BoundDynamicEvidence`。它从同一个 trace 目录重建动态 snapshot，并核对 manifest
trace ID、trace 内容 digest、executable/library fingerprints、命令、工作目录和
DBT contract 文件 hash。启动器字符串 ID 与内容派生的 `TraceId` 分开保存；不能
直接比较两者是否相等。一次 workflow 只绑定一个 trace；多 trace campaign 仍由
独立 campaign service 管理。

跨静态/动态关联可以附带 typed `CorrelationBinding`。它分别记录 binary closure、
translation policy 和 analysis scope 的 `Match`、`Mismatch` 或 `Unverified`：任一
项不匹配时所有跨路由候选为 `Unmatched`；缺少材料时最多 `Ambiguous`；只有三个
维度都核对通过且 site 身份唯一时才是 `Exact`。snapshot-only 旧调用没有该对象，
因此结果只表示 site identity，不证明两边的 workload/policy/scope 相容。

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
Unknown 覆盖。它把 `exercised`、`ambiguous`、`unmatched` 和 `not_executed` 分开，
并原样复制静态 verdict。只有所有 trace 完整、相关报告携带已验证且匹配的跨路由
binding、并且静态 site 有稳定 subject 或指令位置时，才把无观察记为
`not_executed`。其他情况仍是 `unmatched`/`NotObserved`；不完整 trace 中没找到
事件不能说明该 site 没执行。`--affine-output` 生成的文件不进入静态证书，也
不能关闭 Unknown；只有后续纯静态分析产生新的 `ProofFact` 才可以改变静态结论。

当 `diagnose` 同时指定 `--affine-output` 和 `--trace` 时，如果静态 Unknown 的
provenance 含有模块/PC，适配器会以这些位置作为 `site_filter`。原始 trace 仍
完整扫描，过滤只减少保留的观察站点；因此不会把未选中的路径当成已经执行。

## Static blocking Unknown 分区

由 `static_snapshot_from_certificate` 生成的 `static-diagnostic-v2` 快照包含
`blocking_unknown_ids`。适配器先重放静态证书，再检查该 ID 集等于证书
`relevant_unknowns` 扣除已在 proof closure 中验证的 discharge，并且等于当前
ledger 的 unresolved Unknown 集。快照仍保留所有 `UnknownFact` 和 discharge；
它不会删除历史节点。

D4 `diagnostic-report-v3` 分开输出：

- `blocking_unknowns`：当前仍未闭合的全部静态 obligation；
- `selected_unknowns`：本次实际做动态关联的 blocker 子集，默认等于全部 blocker；
- `discharged_unknowns`：不再阻塞当前结论、且由静态证据中的 discharge 记录关闭的历史 Unknown。

不能把已 discharge 的 ID 作为诊断选择项。旧 `static-diagnostic-v1` 快照没有
由证书回放产生的 blocker 分区；读取后会把其中所有 Unknown 保守地视为候选
blocker，而不会根据快照内容擅自把它们移入 discharged history。此兼容行为可能
多报 blocker，但不会静默隐藏 obligation。以上字段只影响诊断呈现，不修改静态
certificate 或 verdict。
