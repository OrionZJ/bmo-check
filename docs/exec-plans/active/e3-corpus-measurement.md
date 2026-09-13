# E3 corpus measurement and first capability selection

状态：measurement 已完成；E2.5 correctness baseline 已冻结；本文件不授权修改
analyzer 的证明门槛或 verdict 语义。

记录日期：2026-09-13  
输入 corpus：`litmus-tests-x86/elf-tests` 及其对应的
`tests/non-mixed-size` source。  
外部结果目录：`E:\bmo-check-e2-5-full`（WSL：`/mnt/e/bmo-check-e2-5-full`）。

## A. E2.5 frozen baseline

E2.5 已完成，职责到此冻结为 correctness baseline 和 regression
infrastructure：

- 六个代表性真实 x86-64 ELF 经过普通 static recovery、thread/
  `MemoryEvent`/program-order 对齐、固定 execution characterization、static /
  dynamic differential、canonical DBT6 `mo-off` contract 和 herd7 独立 oracle。
- herd7 曾发现 LB 的 RVWMO modeling bug，修复后代表性 profile 和完整回归保持
  通过。
- herd outcome legality、BMoCheck execution legality、最终 static certificate
  verdict 仍是三个不同层次；CoWW 的 final-state query 仍明确保留为模型边界。
- 动态观察和 herd 结果没有进入 static `ProofFact` 或 SAFE certificate。

因此，后面的 `UNKNOWN` 是 E3 static-precision measurement，不是 E2.5 未完成项。
本轮没有实现 `UnknownMemoryEffect`、`UnknownEscape`、
`UnknownAffineBounds`、`UnknownJoinRelation` 或
`ReachingDefinitionFailure` 的修复，也没有改变 `SAFE`、`UNKNOWN` 或
`COUNTEREXAMPLE` 的定义。

## B. Corpus coverage

### B.1 输入和运行边界

本地 corpus 含 2,595 个 `.litmus` 和 2,595 个生成 ELF。每个 ELF 只产生一条
紧凑 JSONL 记录；脚本调用普通 `slice_report` 和
`verify_portability`，不保存完整 recovery 对象、目标文件或 herd 原始输出。
运行参数为：

```text
scope=application
provenance-instruction-limit=32
max-events=24
max-threads=8
max-executions=128
timeout-ms=1000
workers=2
dbt-revision=local-e2-5-corpus-sweep-v2
```

结果文件为：

```text
/mnt/e/bmo-check-e2-5-full/static-baseline-v2.jsonl
sha256 = 6c7c270193f0fe3bed019f7de98918b39ea566ba3c43ab09e02e5c42039792e7
```

文件含 2,595 条合法记录、0 条损坏/截断记录；汇总由
`scripts/report_e2_5_corpus.py` 流式生成。所有结果和日志留在 E 盘，生成的 corpus
没有复制到 BMoCheck 仓库或 D 盘。

### B.2 分层指标

| 指标 | 数量 | 如何解释 |
|---|---:|---|
| total ELF / source pairs | 2,595 | 期望输入规模 |
| result records | 2,595 | 每个 ELF 都有一条完成记录 |
| malformed/truncated rows | 0 | JSONL 完整 |
| recovery reached | 2,595 | service 调用正常返回；不是 recovery proof 已闭合 |
| thread recovery closed | 0 | 没有一行在 relevant blocking set 中消除全部 recovery Unknown |
| shared-event recovery closed | 0 | 没有一行消除全部 memory-event/sharing Unknown |
| checker reached | 2,595 | `verify_portability` 返回了 verdict 字段 |
| `COUNTEREXAMPLE` | 0 | 本轮没有产生静态反例 |
| `TRACE_SAFE` / `SAFE` | 0 | 本轮不是动态证书或静态 SAFE 评测 |
| `UNKNOWN` | 2,595 | checker conclusion 全为 `Incomplete` |
| unsupported/model-boundary ELF | 0 | 没有记录命中 checker-boundary Unknown |
| pipeline error ELF | 0 | 没有 service 外层异常记录 |
| oracle mismatch | 未测量 | 该 sweep 不运行 herd 或第二个 checker |

`recovery_reached` 和 `checker_reached` 是可观测的服务边界指标，不能被解读为
“线程恢复已证明”或“模型求解已闭合”。compact row 没有分别记录 recovery、
MemoryEvent、shared-slice 的结束时间和 proof closure，因此本报告不会猜测更细的
阶段失败数。

## C. Unknown distribution

### C.1 Checker blocking set

下表使用 `verify_portability` 返回的 `relevant_unknowns`；`affected ELF` 是至少
出现一次该 kind 的 ELF 数，`occurrences` 是所有记录中该 kind 的 typed fact
计数。后者不是 ELF 数量，也不能直接当成根因权重。

| Unknown kind | affected ELF | occurrences |
|---|---:|---:|
| `ReachingDefinitionFailure` | 2,595 | 4,422 |
| `UnknownAffineBounds` | 2,595 | 301,060 |
| `UnknownEscape` | 2,595 | 401,237 |
| `UnknownJoinRelation` | 2,595 | 2,595 |
| `UnknownMemoryEffect` | 2,595 | 158,295 |
| `UnknownSynchronization` | 2,595 | 5,190 |
| `UnknownThreadEntry` | 2,595 | 6,249 |
| `UnknownThreadRole` | 1,827 | 1,827 |

### C.2 Producer-layer union

`unknowns` 还保留了各 producer 层的 union，供比较历史结果使用；它不是 checker
blocking set。其主要差异是：`UnknownMemoryEffect` 为 851,595 次、
`UnknownThreadEntry` 为 1,827 个 ELF、`UnknownThreadRole` 为 3,654 次。
因此不能把 producer union 中数量最大的 kind 直接选为 E3 根因；同一个 fact
可能被多个阶段汇总，或者已经被 relevance filter 排除。

## D. Root-cause clusters

### D.1 Cluster A — recovery-first 的 thread/lifecycle context gap

**观察到的事实：** 2,595/2,595 行的最早观测层都是 `recovery`。其中 768 行同时
出现：

```text
ReachingDefinitionFailure
UnknownJoinRelation
UnknownSynchronization
UnknownThreadEntry
```

另外 1,827 行在这个集合上再出现 `UnknownThreadRole`。这两个集合覆盖全部
2,595 个 ELF。

源码中的约束与这一形状相符：`src/bmo_check_static/threading/pthread.py` 的
`_containing_role` 只有在函数只属于一个可达 role 时才返回 complete；
`parent_complete` 在零个或多个 caller context 时变为 false，并产生
`ReachingDefinitionFailure`。`pthread_join` 的 complete 条件还要求 parent
complete 且只剩一个候选 child role。生成的 SB harness 中，`zyva` 既作为
`pthread_create` callback 传给 `launch`，又在 main 中直接调用；`launch` 再包裹
`pthread_create`/`pthread_join`。这说明 wrapper 和 callback 的调用上下文是一个
可复用的压力点。

**证据等级：** 这是 recovery 层的稳定 co-occurrence 和源码约束；compact row
没有保存 Unknown 之间的 provenance edge，所以目前没有“RDef 必然派生 Join 或
MemoryEffect”的已证明因果链。

### D.2 Cluster B — address/memory precision co-occurrence

8 个 ELF-wide relevant kinds 中，`UnknownEscape`、`UnknownMemoryEffect` 和
`UnknownAffineBounds` 在 2,595 个 ELF 全部出现，并和 Cluster A 同时出现。
`UnknownAffineBounds` 的 occurrences 很大，主要说明循环/事件级事实被重复报告，
不能据此证明它是上游根因。`UnknownMemoryEffect` 的 producer union（851,595）
远高于 checker blocking set（158,295），进一步说明“报告数量”包含层间汇总差异。

**证据等级：** 只能标为与 recovery Unknown 的 co-occurrence。当前数据没有
MemoryEvent provenance link，无法判断 `UnknownMemoryEffect` 与 `UnknownEscape`、
`UnknownAffineBounds` 的方向，也不能把它们静默归因于 RDef。

### D.3 Cluster C — role cardinality gap

明确带有 `UnknownThreadRole` 的是 1,827 个 ELF；其余 768 个 ELF 仍有
`UnknownThreadEntry`/lifecycle Unknown。它提示 role 数量和 callback 目标集合是
独立的精度维度，但不能说明修复 role cardinality 就会自动关闭 join 或 memory
Unknown。

### D.4 未发现的类别

没有 ELF 命中 `MissingLibrary`、`MissingInterpreter`、checker-boundary
unsupported 或 pipeline error。也没有在这次 static-only sweep 中测量 oracle
mismatch；不能把“未测量”写成 0。

## E. E3.1 recommendation

### E.1 首选：context-sensitive thread/lifecycle provenance recovery

建议 E3.1 首先解决一个通用的 **pthread/OpenMP callback 调用上下文和生命周期
句柄 provenance** 能力，而不是先按 occurrences 数量修 `UnknownMemoryEffect` 或
`UnknownAffineBounds`。

理由：

1. 所有 2,595 个 ELF 的 first observed blocker 都在 recovery 层；
   `ReachingDefinitionFailure`、`UnknownThreadEntry`、`UnknownJoinRelation` 和
   `UnknownSynchronization` 覆盖整个 corpus。
2. 1,827 个 ELF 还有明确的 `UnknownThreadRole`，而 768 个 ELF 即使没有该 kind
   仍未完成 lifecycle closure，说明问题是调用上下文/句柄绑定的组合，而不是单一
   role 名称。
3. 生成 harness 的 wrapper/callback 形状在普通 C/pthread 程序中也会出现；该能力
   不需要读取 benchmark、litmus、函数名或 source marker。
4. canneal 的 affine Unknown 仍是有效的后续 validation case，但 corpus 目前没有
   证明 affine 是最早的共同阻塞层。

计划增加的 proof capability（名称在实现前可再按现有类型调整）：

- 对 callback target set 保存稳定的 call-site/context identity，而不是只按函数
  是否可达某个 role；
- 对每个 `pthread_create`/OpenMP parallel site 推导唯一 parent role、callback
  target 和参数 provenance；
- 将 `pthread_t` 的 create handle 与对应 join site 建成可审计的生命周期 fact；
- 只有所有 caller context、间接目标和句柄别名都闭合时才生成新的 proof fact，
  并保留从 ELF PC、call site 到 role 的 provenance；
- 对多 caller、别名 handle、未解析间接目标、未知 helper 或不完整生命周期继续
  产生 typed `UNKNOWN`。

**预计影响：** 直接的 role gap 有 1,827 个 ELF；由于四类 recovery blocker
覆盖 2,595 个 ELF，改进可能使整个 corpus 受益，但实际关闭数量必须由同一套
campaign 测量，不能预先承诺 2,595 个都会进入 checker proof closure。即使 E3.1
成功，也不能自动消除 `UnknownEscape`、`UnknownMemoryEffect`、
`UnknownAffineBounds` 或不透明调用 Unknown。

### E.2 第二候选：generic function-effect / argument provenance

第二候选是扩展现有 function-effect 和指针参数 provenance summaries，以减少
`OpaqueCallBoundary` 对 `UnknownMemoryEffect`/`UnknownEscape` 的传播。它的潜在
覆盖面很大，但当前 corpus 只能证明它与 recovery gap 共现，不能证明它是 root
blocker；应在 E3.1 后用相同 campaign 重新测量。

`UnknownAffineBounds`（含 canneal 的 affine 案例）作为第三候选保留，等 role/
lifecycle closure 后再判断有多少 affine Unknown 仍独立存在。

### E.3 E3.1 验收和不变量

E3.1 实现后必须用完全相同的 corpus、参数、DBT contract 和输出 schema 做前后
对比：

```text
before/after total and completed rows
recovery/thread/shared-event/checker reached
relevant Unknown affected ELF and occurrences
first-blocker layer/kind sets
co-occurrence matrix
static verdict distribution
```

同时保持 E2.5 correctness profile、herd oracle、static/dynamic differential 和
certificate proof-closure 回归全绿。改进只能新增可追溯的 `ProofFact`；不能把
`ObservedFact`、herd outcome、一次运行的地址或 benchmark 名称变成 proof，也不能
为了 coverage 删除 relevant Unknown。

## F. 后续 atomic implementation plan

当前 measurement 只新增/使用紧凑报告脚本，未改 analyzer 语义。未来 E3.1 按以下
可独立回滚的提交推进：

1. **Characterize stage provenance**：扩展每条 compact row 的 stage/Unknown
   provenance 字段，解决本次 `recovery_failure_elfs=not_stage_separated` 的
   可观测性缺口；旧字段保持可读，先不改变 verdict。
2. **Add context-sensitive role fixtures**：用小型 wrapper、多 caller、函数指针
   集合和 ambiguous handle fixture 固化正例、反例和必须保留 Unknown 的边界。
3. **Implement role/lifecycle proof facts**：逐步迁移 pthread/OpenMP recovery，
   每一步保留旧/新结果 differential 和稳定 identity；不触碰 memory-model checker。
4. **Replay the frozen corpus**：运行完全相同的 2,595-ELF campaign，比较上述
   coverage/root-blocker 指标；若出现 model mismatch，先回到 E2.5 focused
   regression，不能混入 precision patch。
5. **Reassess second candidate**：只有 E3.1 的前后数据完成后，才决定 function-effect
   或 affine 能力的下一提交。

## G. 结论边界

本测量证明的是：所有本地 ELF 都能进入普通 service 并留下可解释的静态
`UNKNOWN`，共同的首层观测阻塞在 recovery；它没有证明这些程序的 `mo-off` 一定
错误，也没有证明它们已经 `SAFE`。E2.5 的尺子保持不变；E3 只负责在明确的
soundness contract 下增加静态可证明事实。
