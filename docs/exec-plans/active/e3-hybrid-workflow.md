# E3 — 先完成动静结合诊断工作流

状态：active implementation；H0 characterization complete。分析器、真实 workload 与 frozen corpus baseline 均未改变。

## 阶段边界

- E2.5 correctness baseline 冻结；保留六个真实 litmus ELF、herd7 oracle 和现有回归。
- 2,595 个 litmus ELF 的静态 measurement 冻结为 coverage/root-blocker baseline；不重跑、不改数据。
- 原 E3.1 thread/lifecycle recovery 代码、提交和计划保留，但暂停继续扩展。据用户此前报告，E3.1 的 100-ELF 试跑仍全部是 `UNKNOWN`；这是未纳入仓库的 pilot 信号，不替代 2,595 全量 baseline。
- E3 当前优先交付一条完整 workflow：普通 workload 输入 → static analyze + dynamic capture/analyze → evidence correlation → 一个统一、可追溯报告。
- workflow 完成后，才综合 canneal、litmus corpus measurement 和真实诊断来选择 1–2 个 generic static precision capability。届时再决定是否恢复 thread/lifecycle work。

## 1. 当前 hybrid workflow 已经有什么

1. **Evidence 类型和隔离已经落地。** `bmo_check_core` 提供 `ProofFact`、`ObservedFact`、`DiagnosticHint`、`UnknownFact`。`StaticDiagnosticSnapshot` 只接受静态 Proof/Unknown；`DynamicDiagnosticSnapshot` 只接受 trace-bound Observed/Unknown。`EvidenceSnapshot` 保留节点及 Unknown discharge，JSON 经显式、带版本的 serializer 读写。
2. **两条分析路线各自有 application service。** 静态 `analyze_with_evidence` 运行 ordinary recovery/checker、组装并 replay canonical static certificate；动态 `capture` 和 `analyze` 分别运行采集与 trace checker，返回 `DynamicCertificate`。
3. **两边都有通往诊断 snapshot 的 adapter。** 静态 `static_snapshot_from_certificate` 会重放并核对静态证书，然后生成只读快照。动态 `dynamic_snapshot_from_trace` 会校验 trace 完整性、归一化 module-relative PC，并流式形成 site/thread 级 `ObservedFact` 和动态 `UnknownFact`。
4. **已有保守相关器和 D4/D5 报告。** correlation 以稳定 subject 为首选，必要时按 module、ELF PC、effect、operand 回退，输出 `Exact`、`Ambiguous` 或 `Unmatched`。D4 `DiagnosticReport` 保留原静态 verdict、静态 Unknown、trace observations、动态 Unknown、相关理由和 `DiagnosticHint`。D5 用注册表给 hint 分类。
5. **E1 affine observation 已存在。** `ObservedAffinePattern` 复用 snapshots 和 correlation，记录有界地址/stride 观察，不形成 affine proof。
6. **soundness 边界已经由类型和 verifier 支撑。** 动态事实不能进入 static snapshot 或 static proof closure；diagnostic hint 不能 discharge Unknown；trace 不完整仍不能得到 `TRACE_SAFE`。

这些能力说明项目已有可复用的部件，但不等于端到端 workflow 已经接通。

## 2. 缺哪些连接环节

### 2.1 用户输入尚未贯穿两条路线

`bmo-check-static analyze` 目前通过 `analyze()` 输出兼容版静态 certificate；它不导出 diagnostic snapshot。静态 snapshot adapter 由代码提供，但目前没有从该 CLI 直接产出 snapshot 的路径。`bmo-check diagnose` 要求用户先准备静态 snapshot；它可接收动态 snapshot，或用 `--trace` 从 trace 生成动态 snapshot。因而用户必须手工串联文件，不能给一个 ELF/workload 后得到完整报告。

### 2.2 final dynamic verdict 没进入诊断报告

动态 application service 产生 `TRACE_SAFE`、`COUNTEREXAMPLE` 或 `UNKNOWN` 的 `DynamicCertificate`；但动态 snapshot 只含 observations、trace completeness 和动态 Unknown。当前 `DiagnosticReport` 只含 `static_verdict`，不含 `DynamicCertificate.verdict`。`diagnose --trace` 只生成用于 correlation 的 snapshot，不会顺便调用动态 checker。结果是现有报告无法同时回答 static verdict 与 dynamic verdict。

### 2.3 “static blocking Unknown”没有被准确选出

静态快照带有完整 evidence/discharge，但没有单独携带 certificate 的 `relevant_unknowns`。目前 D4 builder 默认遍历快照里的**全部** `UnknownFact`；它没有把已 discharge 或非当前 blocker 的 Unknown 与仍未证明的 obligation 分开。统一报告必须从经过 replay 的 static certificate 取得当前相关、未闭合的 Unknown 集合；其他历史 Unknown 可以保留为 provenance，但不能误列成 blocking obligation。

### 2.4 E1 和 E2 结果目前是并列文件，不是一个可读结论

`--affine-output` 会另外写 `AffineValidationReport`。主 D4 JSON 只含聚合 `ObservedFact` 与 hints，不含 `ObservedAffinePattern` 细节。用户要追踪“某个 static Unknown → 哪些动态观察 → affine pattern/缺口分类”，现在需要跨文件按 ID 拼接。

### 2.5 当前 root-cause 是诊断分类，不是已证实的因果根因

D5 分类器根据 `UnknownKind`、reason/context 和 correlation status 选择 registry 项；它没有遍历 Unknown provenance 来建立 `A → B` 的因果链。因此目前的 `MissingLoopBound`、`OpaqueCallBoundary` 等只能叫**诊断候选分类**，不能说成 first/root blocker。

审计还发现一个需先加 regression 的边界：分类器会把“没有 observation 的任意 `Unmatched`”标成 `NotExecutedInObservedTrace`；correlator 的 `Unmatched` 也可能代表 binary closure 不匹配或缺少稳定位置，并不等于该指令未执行。修复时必须区分这些原因。只有静态位置可匹配、binary/scope binding 兼容、trace 完整且目标 site 确实无记录时，才可输出受限的“本 trace 未观察到”；否则标为 unmatched/原因未定。

### 2.6 证书和 snapshot 的绑定还需闭环

动态证书用 capture manifest 的 trace ID 和 trace digest；诊断 snapshot 的 `TraceId` 是 adapter 根据格式、manifest、模块和记录 digest 派生的稳定 ID。两者不能假设字符串相同。workflow 必须证明动态证书和诊断 snapshot 来自同一 trace、同一 executable/module closure、同一 DBT contract，并检查 static 与 dynamic 的 binary closure、scope 和 workload 参数兼容性。binding 不兼容时可保留两个各自有效的 verdict，但不得给出 `Exact` correlation。

### 2.7 缺少 root-blocker 因果图输出

`UnknownFact.provenance` 保存了静态 evidence ID，但当前没有把每条 provenance 关系标成明确的 `derived-from`、`supports` 等 edge kind；分类器也没有遍历它来划分 root/downstream。因此仅凭当前 ID 链不能自动宣称因果。workflow 应先复用已有来源；只有共同出现、没有明确因果 edge 的事实必须标作 `co-occurring` / `possible upstream` / `causal relation unresolved`，不能按数量或名称猜根因。若要建立严格 root-cause graph，先单独定义 edge 语义及正反例。

## 3. 哪些是正式 service，哪些仍是脚本/手工串联

| 部件 | 当前性质 | 目前的边界 |
|---|---|---|
| `bmo_check_static.application.analyze_with_evidence` | 正式静态 application service | 产生静态 legacy/canonical result；CLI 目前调用兼容 `analyze()`，没有导出静态 snapshot |
| `bmo_check_dynamic.application.capture/analyze` | 正式动态 application services | 分别采集和分析 trace；彼此没有自动接静态分析或 diagnostics |
| 两个 `diagnostic_snapshot` adapter | 正式的 route adapter | 转换证书/trace 为只读 snapshot；尚无共同 application service 编排它们 |
| `bmo_check_diagnostics.build_diagnostic_report` | 正式 diagnostics service | 收两个 snapshots；不运行任何 analyzer，也不读取 dynamic certificate verdict |
| E1 affine builder/serializer | 正式 diagnostics component | 作为可选独立报告输出，没有并入主诊断报告 |
| `bmo_check_cli.diagnose` / `bmo-check diagnose` | CLI adapter + 文件级组合 | 读取静态 snapshot、读取或构造动态 snapshot、写 D4；不能从 workload 开始，也没有 DynamicCertificate |
| `bmo_check_evaluation.parsec`、`bmo_check_evaluation.litmus` | 正式但有明确领域边界的评测 service | 评 PARSEC 或 E2.5 fixture，不是通用用户 workload workflow；litmus oracle projection 不能成为生产 proof 路径 |
| `scripts/run_e2_5_corpus_sweep.py`、`scripts/report_e2_5_corpus.py` | 可复现 measurement driver | 用于冻结静态 corpus 数据，不是交互式产品服务，不应成为 hybrid 主流程 |
| `.experiments/`、E 盘 traces/certificates/临时汇总 | 本地实验产物 | 不进入 Git，不作为生产 workflow 接口 |

## 4. E3 应如何拆成 atomic commits

每个 commit 单一意图，先 characterization，再实现；每个代码 commit 都跑相应 focused tests、`git diff --check` 和默认回归。不在这条主线重写 checker、proof model、E2.5 oracle 或 2,595 corpus runner。

| 顺序 | commit 意图 | 变更范围 | 怎么运行、失败和验收 |
|---|---|---|---|
| E3-H0 | `Characterize hybrid evidence bindings` | 只增加 characterization tests：static certificate→snapshot、dynamic certificate↔trace snapshot 的实际 binding、scope/closure 不同、D4 当前字段、discharged Unknown、E1 独立输出。同步记录 workflow service 的 dependency 归属决策。 | 完成。测试固定现状和缺口，不改变 verdict，也不把任何 Unknown 降级。记录见 `e3-h0-characterization.md`。 |
| E3-H1 | `Classify unmatched diagnostics conservatively` | 保留 D5 registry 和现有 correlation schema。Unmatched 的 hint 先归为 `UnknownRootCause`，并在 rationale 中说明闭包、位置或 trace 完整性缺口；当前 snapshots 没有 workload/scope compatibility binding，因此即使 trace 完整也暂不输出 `NotExecutedInObservedTrace`。H3 提供经过验证的 binding 后再开放该分类。 | 完成。closure mismatch、缺 subject、incomplete trace、完整但 binding 未验证均有回归覆盖。Unmatched 不会冒充“未执行”；实现记录见 `e3-h1-unmatched-classification.md`。 |
| E3-H2 | `Expose unresolved static obligations` | 从经过 replay 的 static certificate 显式导出 `relevant_unknowns`/未闭合 obligations；扩展 snapshot 或其 typed adapter，让 D4 默认只把仍阻塞当前结论的 Unknown 当作 blocking。已 discharge 的 Unknown 可保留为历史 provenance，但必须另行标记。 | 完成。v2 snapshot 的 blocker ID 与 replay 后未闭合集合一致；D4 报告分列全部 blocking、所选 blocking 和 proof-discharged history。v1/手工快照缺少可信分区时按保守候选 blocker 展示。实现记录见 `e3-h2-unresolved-obligations.md`。 |
| E3-H3 | `Bind dynamic certificate to trace observations` | 增加单一 typed bridge，核对 `DynamicCertificate`、manifest、trace digest、executable/libraries、DBT contract 与 snapshot；显式映射 manifest trace ID 和诊断 `TraceId`，不复制证据模型。增加通用 `CorrelationBinding`，让 diagnostics 能接收 binary、translation policy、analysis scope 的逐项比对。 | 完成。动态 bridge 只从原 trace 重建 snapshot，并核对 certificate 的 manifest ID、内容 digest、模块闭包、命令、工作目录和 contract hash；跨路由不兼容会输出 `Unmatched`，缺材料会降为 `Ambiguous`。H4 将从两条 route 的 application result 生成实际比对项。实现记录见 `e3-h3-trace-binding.md`。 |
| E3-H4 | `Compose existing route services` | 新增一个 model-free workflow application service，组合 `StaticRequest`/`analyze_with_evidence`、dynamic capture/analyze、现有 adapters、D4 和 E1。只新增编排 request/result；不实现新 MemoryEvent、solver、correlator、certificate 或 evidence ledger。 | 用隔离服务测试验证顺序和 artifact binding。分析边界内的 incomplete/unsupported/resource limit 使用该 route 已有的 typed Unknown；配置、I/O 或工具启动失败则保留明确 workflow error，不伪造一张分析证书，也不静默跳过失败的一侧。 |
| E3-H5 | `Emit one versioned hybrid report` | 建立 workflow 外层报告，将 static verdict/未闭合 obligations、dynamic verdict/trace scope、D4 correlation/hints、E1 affine observations、root-cause confidence/causal status 放在一个 JSON 下。保留原 D4/E1 子 schema，不把 DynamicCertificate 塞进 diagnostics evidence。 | round-trip 与 schema negative tests；closure/scope mismatch 必须显式；每个 observation 带 `TraceId`；每个 hint 仍只引用 Unknown/Observed IDs。不得输出一个含糊的 hybrid `SAFE`。 |
| E3-H6 | `Expose one-workload CLI` | 增加薄 CLI 子命令和 versioned generic workload manifest。CLI 只解析/渲染，调用 H4 service；保留现有 snapshot-based `diagnose`、static/dynamic 独立命令。 | CLI integration tests 检查普通输入、无效 manifest、缺失 DBT binding、DynamoRIO 不可用、trace incomplete、输出路径失败；结果 JSON 仍分别显示两种 verdict。 |
| E3-H7 | `Validate hybrid workflow on real workloads` | 用少量真实 ELF/应用验证同一输入身份、观察相关、harness 事件可见、产物预算和可复现命令；只记录结果和限制，不按 workload 名改变语义。 | 先跑 canneal 和 E2.5 代表 ELF，再选一个已有动态完整 trace 的 PARSEC workload。若 trace 过大、依赖缺失、closure mismatch 或过预算，结果如实为 `UNKNOWN`/unmatched；不通过过滤 harness 获得成功。 |

### Workflow service 的归属决策

当前没有一个已有 service 同时拥有这三个 route 的编排职责。静态和动态 service 必须保持互不依赖，diagnostics 只消费 snapshots，CLI 必须保持薄层；`bmo_check_evaluation` 当前是 PARSEC/litmus 评测域，不应借它给所有普通 workload 加 benchmark 语义。H0 已把 `bmo_check_workflow` 记录为后续中性编排 owner，见 `e3-h0-characterization.md`；在 H4 前更新 dependency tests 和架构文档。

推荐在 H0 的架构决策中加入一个很薄的 `bmo_check_workflow`（或在仓库认可的中性 application 层实现）：依赖 static、dynamic、diagnostics 和 core，只负责调用既有 service 并串接不可变结果。它不得拥有第二套 analyzer、memory model、evidence ledger、Unknown registry 或 correlator。对应的 dependency DAG、`AGENTS.md` 和 architecture map 在 H4 前先更新并通过 architecture test。若仓库维护者决定复用其他现有 application owner，则 H0 记录理由后替换此提议。

## 5. 完成后用户如何运行、看到什么

建议的单 workload 入口（命令名和 YAML 字段在 H0 定稿）：

```text
bmo-check hybrid --workload workload.yaml --output-dir E:/bmo-check-e3-hybrid/run-001
```

manifest 提供同一程序的 executable 与 argv、working directory、environment、library roots、静态 DBT/function-effect/pthread 契约与 revision、static scope/checker limits、动态 DynamoRIO/client/trace limits，以及输出位置。动态命令必须由 executable+argv 形成，不经 shell 拼接。大 trace、DuckDB 和临时物留在用户指定的 E 盘目录，不复制进仓库或 D 盘。

workflow 复用现有分析路径：先取得 static `StaticAnalysisResult` 和 canonical snapshot；再 capture 一次 workload、分析同一 trace 得到 `DynamicCertificate`，从该 trace 建立 dynamic snapshot；核对绑定后调用现有 D4 correlator 和 E1 affine builder。

单份 report 至少分开呈现：

- static verdict：`SAFE` / `COUNTEREXAMPLE` / `UNKNOWN`，并列出**仍未闭合**的 static obligations（稳定 EvidenceId、kind、PC/operand/object/thread role、provenance、阻塞范围）；
- dynamic verdict：`TRACE_SAFE` / `COUNTEREXAMPLE` / `UNKNOWN`，附 trace ID、trace hash、命令/参数、模块闭包、DBT contract、trace completeness 和资源限制；
- 每个 static obligation 对应的 `Exact` / `Ambiguous` / `Unmatched`、使用的 correlation key、理由及 ObservedFact IDs；需要时附有界地址/stride/thread pattern；
- D5 registry 分类、置信度，以及“因果已由静态 provenance 支持 / 仅 co-occurring / possible upstream / causal relation unresolved”；
- 明确的范围说明：动态观察只描述该 trace；所有仍未 discharge 的 static obligations 仍未证明；dynamic facts/hints 没有改变 static proof/verdict。

report 不给一个合并的 `SAFE`。`TRACE_SAFE` 与 static `SAFE` 是不同 scope 的两项结果；例如 dynamic `TRACE_SAFE` + static `UNKNOWN` 时，用户应看到 trace-bound 检查完成而 static obligations 仍未证明。binary/contract/scope 不匹配时，两项原 verdict 可以分别保留，但 correlation 必须为 unmatched/不兼容，不能伪装 Exact。

## 6. 使用哪些真实 workload 验证

1. **canneal：首个 integrated diagnostic case。** 复用已有 canneal static Unknown、E1 `ObservedAffinePattern` 和已记录的 dynamic run（`1 5 100 10.nets 1` 的历史 `TRACE_SAFE` 是 application-scope 结果，不是全进程证明）。验收重点是 static Unknown 与真实 trace site/线程观察可追踪地并列，affine 仍叫 observation，D4/D5 不消除 Unknown；保留 full/application scope 的区别。
2. **E2.5 真实 litmus ELF：checker correctness 交叉保护。** 从已固定的 SB、MP、LB、2+2W、CoWW、MP+mfence+po profile 选少量实际 ELF；优先选一个普通 SB/MP 和一个 MFENCE variant，并保留 LB target-only / CoWW model-boundary regression。分析必须走普通 binary/CFG/thread/MemoryEvent/recovery；profile 的 critical-event projection 与 herd 只作 oracle/regression，不进入 workflow proof。先 characterise iteration 参数和 trace 体积，避免一次运行写爆 E 盘。
3. **PARSEC 第二种应用形状：优先 blackscholes。** 已有 `in_4.txt`、1/2 worker 的 application-scope `TRACE_SAFE` 记录，trace 规模小于 streamcluster/canneal；适合作为第二个真实 workflow 结合点。实际命令/输入以已记录 manifest 为准，不把程序名放入 semantic branch。若本地 binary/dependency hash 与旧记录不同，重新绑定并如实报告，不复用旧 verdict。
4. **不对全部 2,595 个 ELF 做动态 campaign。** 它们是冻结的静态 measurement/reference corpus，仍用于分析 E3 覆盖分布；逐个动态运行成本与产物不符合本阶段目标。选定未来 E3 static improvement 后，再按原脚本与参数重跑相同 2,595 静态 campaign，比较 before/after。

### E3 hybrid workflow 退出标准

- 用户通过一个 workload input 得到一个可重放/可审计的 versioned report；底层静态、动态证书仍分别保存、分别验证。
- report 同时包含两个 verdict 和 trace-bound scope；每个 blocking static Unknown 均被准确纳入，非 blocking/discharged Unknown 不冒充 blocker。
- 每个 correlation 状态及不匹配理由可重算；root-cause 线索不会把共现说成因果。
- E1 affine observations 能在同一报告沿 Unknown ID 回查。
- property/contract/integration tests 证明 ObservedFact/DiagnosticHint 无法进入 static SAFE closure，任何 incomplete/binding-mismatch/resource-limit 路径不升格。
- E2.5 litmus/herd regression 与默认全套测试通过；canneal 和至少一个不同形状的真实 workload 有端到端报告。
- E2.5 与 2,595 ELF baseline 不被改写。完成后另做静态 precision 选择评审；只挑 1–2 个有真实诊断支撑的 generic gap，再正式恢复静态能力实现。

## 后续架构评审：policy-parameterized cross-ISA verification

**状态：延期讨论，不属于当前 E3 hybrid 实施。** 这项方向不得打断当前
workflow，也不得改变 E2.5 correctness baseline、2,595 ELF measurement 或
任何现有 DBT6 实验配置。

当前所有静态、动态、diagnostics、canneal、litmus 和 blackscholes 验证继续
使用现有 DBT6 canonical `mo-off` rule/contract。当前阶段不实现 Box64 policy，
不修改 DBT6 contract、E2.5/herd oracle 或 `SAFE` / `TRACE_SAFE` / `UNKNOWN` 的
含义。

hybrid workflow 完成并稳定后，可以单独评审是否把 translation/lowering rule
抽象为显式、版本化的输入：

```text
guest binary
+ source memory model
+ translation policy
+ target memory model
    -> BMoCheck
```

未来可考虑 DBT6 `mo-off`、Box64-like TSO Level 0–4，以及其他 x86-to-RISC-V
fence/lowering policy。后续设计应让 policy 提供可审计的指令 lowering/order
rule，并在证书中绑定 policy identity/version 与 source/target model 版本；
不能让 policy 名称本身代表或推断排序强弱。

对实际应用的结论应绑定完整分析对象：

```text
application + loaded library closure + workload/input + translation policy
```

例如 `Foo + libjvm + workload W under P1 -> TRACE_SAFE` 只描述该绑定的执行
轨迹，不能外推为 `libjvm` 在 P1 下普遍安全。比较多个 policy 时，应在共同支持
范围内比较它们实际诱导的 target-ordering relation；只有关系集合确实满足包含
或等价，才能称一个 policy 提供了更强或等价的排序，不能根据 Level 数值推断。

进入这个方向前需要单独 review：policy schema 与版本兼容、DBT lowering 覆盖面、
证书绑定、缺失/不支持规则的 fail-closed 行为，以及 Box64 Level 0/1 作为第二
case study 的独立 characterization。无论后续 policy 数量如何增加，动态观察仍只
能提供 trace-bound 结论和诊断，不能成为静态 `ProofFact` 或关闭 static Unknown。
