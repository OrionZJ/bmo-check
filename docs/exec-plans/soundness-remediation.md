# Soundness remediation execution plan

## 目标与当前检查点

本计划从 `dev` 分支提交 `5cfab59`（`Improve dynamic trace scope and syscall effects`）开始。该提交保存了当前动态通信、作用域、系统调用效果和模块权限工作；`.experiments/`、`.tmp*`、大型 trace、PARSEC 临时结果和其他实验产物继续留在工作区，不属于本计划的提交内容。

本轮目标是修复可能造成 false `SAFE` 或 false `TRACE_SAFE` 的证据闭包问题，而不是提高某个 benchmark 的通过率。E2.5 correctness baseline、2595 个 litmus ELF 的 corpus measurement 和现有 E3 precision roadmap 均保留。

当前测试状态必须如实记录：在本检查点上曾从 WSL 启动默认 pytest，收集到 478 项并运行到约 70% 时按用户要求停止，因此这次没有完整测试通过结论。后续每个 remediation unit 都要先运行对应的小型 adversarial tests，再运行完整默认 suite。

## 不可改变的 soundness invariant

以下规则是本计划的验收边界：

1. 信息减少不能提高 proof confidence。
2. event/object/scope identity 不能代替 proposition、obligation、thread 或 trace identity。
3. 删除或投影 verdict-relevant 事件，必须有保持 legality 的证明；没有证明只能返回 `UNKNOWN`。
4. verifier 必须独立检查 event/obligation completeness，不能相信 producer 提供的空列表或 `complete=True`。
5. 一个 memory-model primitive 只有一个 canonical semantic definition；static、dynamic 和 oracle 的差异必须先形成 characterization failure。
6. `ProofFact` 才能进入 static `SAFE` proof closure；`ObservedFact`、`DiagnosticHint` 永远不能变成 `ProofFact`。
7. 不能观察到 alias、线程或路径不等于已经证明 NoAlias、线程私有或不可达。
8. 旧 schema 如果不能证明新的 completeness，只能作为 legacy report 读取，不能静默验证为 `SAFE` 或 `TRACE_SAFE`。

## 已确认的风险清单

### Scope、projection 与通信

- static application scope 目前会按 module 删除 dependency-library events；这可能删除 library function 对 application-owned shared object 的访问。
- application-scope 删除没有统一进入 canonical `RemovalDecision` ledger，verifier 可能看不到删除理由。
- dynamic application-only fast path 在通信图没有完整枚举时可能给出 `TRACE_SAFE`。
- 同一 allocation 的不重叠字段、mixed-width partial overlap 和跨模块事件必须保持精确范围语义，不能由粗粒度对象或裸地址替代。

### Thread、lifecycle 与同步

- pthread join 目前可能按 worker/join 出现顺序配对，而不是按 `pthread_t` handle identity 配对。
- lifecycle completeness 只覆盖已经恢复的线程子集，缺失第三线程的 START/END 可能被误当作完整。
- `FUTEX_WAIT` 目前被无条件建成 full ordering，但 DBT contract 未证明该 ordering；`SYNC_ACQUIRE/RELEASE/FULL` 的下游语义也没有统一定义。

### Certificate、Unknown 与 provenance

- `SAFE` certificate 缺少完整 event universe、obligation 集合和 Unknown completeness binding。
- Unknown discharge 只按 event coverage，没有 proposition identity；无关 `ProofFact` 可能错误消除 relevant Unknown。
- legacy Unknown filtering 使用裸 PC，不同 module 的同一 PC 可能发生错误过滤。
- canonical `ProofFact` 没有重放 rule/premises，legacy `supporting_facts` 被压成不可审计的 context。
- `TRACE_SAFE` certificate 缺少 trace import、communication、window 和 Unknown completeness evidence。
- canonical `COUNTEREXAMPLE` 没有 replayable PO/RF/CO/FR witness。
- certificate binding 没绑定全部 contract/config/spec 内容。

### Trace identity 与模型漂移

- TraceStore 没有稳定 trace identity 和完整 import ledger，旧 trace 可能混入新分析。
- static/dynamic PPO、same-address、FUTEX 等 semantics 存在漂移风险。
- static/dynamic checker 当前各自维护部分 x86/RVWMO/DBT lowering 规则；本轮先建立 canonical primitive 和 characterization，不直接 big-bang 合并两个 checker。

## Remediation units 与依赖

```text
RU1 canonical memory-semantics kernel + independent oracle
  ↓
RU2 typed event universe / obligation / proposition identity
  ↓
RU4 thread-lifecycle-synchronization identity
  + RU5 TraceStore subject/completeness
  ↓
RU3 legality-preserving projection
  ↓
RU6 independently replayable certificates
  ↓
经过证明的 fast path 才能重新启用
  ↓
RU7 adversarial regression 与完整 suite
```

RU4 与 RU5 可在 RU2 的 identity 接口稳定后并行推进，但任何 verifier 或 certificate 的完整性变更都必须等待它们提供稳定输入。RU3 依赖 RU1 的语义和 RU2 的 obligation，RU6 依赖 RU1～RU5 的 canonical ledger。旧的 application-only fast path 在 RU3、RU5、RU6 完成前视为停用或只能走保守边界。

## 审计发现到修复单元的追踪矩阵

本表是后续提交的范围依据。每个提交必须引用至少一个 finding ID；不能只写“提高完整性”而不说明关闭了哪条错误接受路径。

| ID | 已确认问题 | 当前错误接受路径 | 永久修复单元 | 完成证据 |
| --- | --- | --- | --- | --- |
| F01 | static application scope 按 module 删除 dependency-library event | library event 消失 → conflict/Unknown 消失 → structural `SAFE` | RU2、RU3、RU6 | W1；每个 event 都 retained 或 removed-with-proof |
| F02 | application-scope removal 没进入 canonical `RemovalDecision` | slice 已删除，但 certificate 不记账 | RU2、RU3、RU6 | 删除任一 decision 都让 replay 失败 |
| F03 | dynamic application-only fast path 不枚举完整 communication graph | empty edges/windows → `TRACE_SAFE` | C0、RU3、RU5、RU6 | W2/W10；不完整 graph 必须 `UNKNOWN` |
| F04 | FUTEX_WAIT 被无条件当 full boundary | target relation 被增强 → target-only execution 消失 | C0、RU1 | W4；ordering 只能来自 versioned contract rule |
| F05 | pthread join 按出现顺序配对 | 错 worker 获得 join HB → 边被错误删除 | RU4 | W3；handle→thread instance→join 可追踪 |
| F06 | lifecycle completeness 只覆盖已恢复线程子集 | 未记录 worker 不在 completeness universe | RU2、RU4、RU5 | W14；每个发出 event 的 thread 都有状态 |
| F07 | SAFE certificate 无 event universe completeness | producer 漏 event 后仍可 `SAFE` | RU2、RU6 | W7；universe digest/count/accounting replay |
| F08 | SAFE certificate 无 obligation completeness | producer 不产生 obligation 即视为不存在 | RU2、RU6 | obligation inventory 可独立核对 |
| F09 | Unknown inventory 由 producer 控制 | producer 漏 Unknown 后仍可 `SAFE` | RU2、RU6 | W8；Unknown manifest 与 analysis stage 对账 |
| F10 | Unknown discharge 只按 event coverage | 不相关 proof 覆盖同 event 即 discharge | RU2、RU6 | W9；proof conclusion 必须匹配 proposition |
| F11 | legacy Unknown filtering 使用裸 PC | 不同 module/operand/event 同 PC 相互污染 | RU2 | W13；稳定 instruction+operand identity |
| F12 | `ProofFact` 不重放 rule/premises | 任意 producer rule string 可进入 closure | RU2、RU6 | rule registry、premise replay、mutation test |
| F13 | TRACE_SAFE certificate 无 import/graph/window completeness | `complete=True` + 空 roots 即通过 | RU5、RU6 | W10；逐层 manifest 与 digest 对账 |
| F14 | COUNTEREXAMPLE 无 replayable witness | producer verdict 无法独立复核 | RU1、RU6 | W11；PO/RF/CO/FR 与双模型 legality replay |
| F15 | binding 未绑定全部 semantic inputs | contract/config/spec 改变后证书仍有效 | RU1、RU5、RU6 | W12；canonical content digests |
| F16 | TraceStore 无 subject identity/import ledger | 旧新 trace 混合但证书只绑定当前 trace | RU5 | stale/partial/repeated import fixtures |
| F17 | static/dynamic memory semantics 漂移 | 同 fixed execution 得到不同 legality | RU1 | shared primitive matrix + herd oracle |
| F18 | native `SYNC_*` 没有统一 consumer semantics | 同步被遗漏或由底层访问碰巧替代 | RU1、RU4 | API sync contract fixtures；无 contract 时 `UNKNOWN` |
| F19 | zero-run campaign 可聚合为 `TRACE_SAFE` | 空集合上的 all 被当 proof | C0、RU6 | zero-run 必须 `UNKNOWN`/input error |
| F20 | contract/spec 多次读取导致 TOCTOU binding | 分析 bytes 与最终 digest 可能不同 | RU1、RU6 | immutable artifact snapshot test |

## 立即止血阶段 C0

永久迁移会跨多个提交。在此期间，已知 unsound fast path 不能继续产生确定 verdict。C0 只把错误接受路径收紧为 `UNKNOWN`，不在旧抽象上伪造 proof。

### C0.1 禁止 incomplete communication 产生 TRACE_SAFE

- `communication_edges_complete == false` 时，无论 windows 是否为空，都生成 typed Unknown 并返回 `UNKNOWN`。
- application partition 的 `status == safe` 只能作诊断，不能替代 graph completeness。
- 覆盖 W2/W10；禁止再组合 `thread_handoffs_complete`、无 application atomic、地址不重叠形成 bypass。

### C0.2 暂停无 proof 的跨 module static pruning

- `module_sha256 != executable_sha256` 本身不构成 removal proof。
- effect/object ownership 不能证明无关时，保留 event 或生成 relevant Unknown。
- 覆盖 W1；禁止增加 libc、libpthread 或 benchmark 白名单。

### C0.3 FUTEX ordering fail closed

- 只有 immutable contract 中显式、可绑定的 syscall rule 才可生成 ordering。
- contract 未说明时生成 `UnknownSynchronization`/unsupported boundary，不能默认 full Fence。
- 覆盖 W4。

### C0.4 旧 certificate 降级

- 缺完整 universe/obligation/window ledger 的旧 schema 只能 explain，不能 replay 成 `SAFE`/`TRACE_SAFE`。
- 使用 schema major version 明确拒绝，不能通过补空列表“升级”。

**状态：已完成。**

- `verify_static_certificate` 和 `verify_trace_certificate` 对确定性旧 schema
  一律拒绝 replay；`UNKNOWN` 旧证书仍可用于解释。
- `*-certificate-v2` 但没有 completeness ledger 的占位证书同样拒绝，避免用
  空列表或 `complete=True` 伪造新格式。
- 静态应用服务遇到旧证书无法 replay 时把对外结论降级为 `UNKNOWN`，并保留
  `canonical_error`；旧证书只作为报告输入，不能继续驱动 `SAFE`。
- 覆盖 F07/F08/F09/F13 的第一道 schema 门禁；完整 universe、obligation、
  window ledger 仍由 RU2/RU5/RU6 提供。
- focused evidence/bridge/application tests: `22 passed`。
- 提交：`60e7b13`（replay gate）、`7ddbb19`（由 verifier 统一构造保守降级）。

### C0.5 空 campaign 与空 subject

- zero-run campaign 返回 input error 或 `UNKNOWN`。
- 空 universe 只有在 subject manifest 证明没有 memory-order obligation 时才允许确定 verdict。

**状态：已完成。**

- campaign manifest 的 `runs` 必须非空，且每项 `repeat >= 1`；`repeat: 0`
  不再经过空集合聚合成 `TRACE_SAFE`，CLI 返回输入错误。
- 动态 trace 预检已经把无 event file 或空 event file 记为不完整并返回
  `UNKNOWN`，不会把空窗口当作安全证明。
- 静态空 universe 的确定性 replay 仍被 C0.4 的 schema/completeness 门禁拦截；
  只有 RU2 提供 subject obligation manifest 后才允许判断“确实没有义务”。
- focused dynamic/invariant tests: `24 passed`。
- 提交：`557db2f`。

C0 可拆成 4～5 个原子提交。后续永久实现必须删除临时 gate，不能让两套判定规则并存。

## 目标领域模型

名称可按仓库约定调整，但职责不能重新混合。

```text
AnalysisSubject
  subject_id
  executable_closure_digest
  immutable_contract_digest
  analyzer_config_digest
  specification_digests

EventUniverse
  universe_id / subject_id
  ordered event identities
  producer stage inventory
  completeness status or UnknownFact

MemoryEventIdentity
  module + instruction + operand index
  object generation + byte range
  thread instance / role

ProofObligation
  obligation_id / proposition_id / kind / subjects
  semantic model and policy version

ProofFact
  conclusion proposition_id
  registered rule id/version
  premise evidence ids
  scope/subject

UnknownFact
  unresolved proposition_id
  originating pass and stable reason kind
  affected subject and relevant scope

ProjectionLedger
  input and retained universe ids
  removed events/relations and proof per removal
  preservation rule

TraceImportLedger
  trace id/digest and chunk inventory
  expected/imported counts
  start/complete/failure state
  event/object/thread inventories

ExecutionWitness
  events, PO, RF, CO, FR
  fences/atomic/synchronization
  source and lowered-target legality
```

### Identity 与 completeness 规则

- ID 不得依赖 Python object address、遍历顺序、临时 row id 或随机编号。
- PC 必须和 module/load identity 一起使用；memory event 还要带 operand index。
- 数值 thread ID 与稳定 `ThreadInstanceId` 分离。
- object identity 包含 lifetime/generation；地址复用生成新对象。
- proposition identity 包含 kind 和参数，不能用 event identity 代替。
- 各层 completeness 使用 `COMPLETE`、`INCOMPLETE(reason, scope)`、`UNSUPPORTED(reason, scope)`，不能只用 bool。
- 只有 `COMPLETE` 可进入确定 verdict；其余状态生成 typed Unknown。

## 分单元详细实施方案

### RU1：canonical memory-semantics kernel

RU1 只规范 fixed execution legality，不负责 ELF recovery、alias proof、window选择或 certificate completeness。

1. **RU1.1 Characterize vocabulary**：建立 `AccessRange`、`MemoryOperation`、`OrderingClass`、`RelationKind`、`ExecutionRelations`；先记录差异，不改 verdict。
2. **RU1.2 Canonical byte-location**：统一 exact/overlap/disjoint/partial；static 暂不支持 mixed-width 时保持 `UNKNOWN`。
3. **RU1.3 Canonical source PPO**：依据 x86-TSO specification与 herd oracle定义，删除 route-specific source legality 豁免。
4. **RU1.4 Versioned translation policy**：plain、Fence、LOCK/XCHG/RMW、syscall规则来自同一 immutable parsed contract，其canonical内容进入digest。
5. **RU1.5 Canonical RF/CO/FR**：共同 exact-width子集必须一致；byte-partial扩展带明确 capability。
6. **RU1.6 Migrate consumers one at a time**：每迁移一个route都与旧实现differential；随后删除被替代的旧primitive。

herd7只作独立execution oracle，不产生 BMoCheck `ProofFact`。无法由contract或oracle确定的ordering保持`UNKNOWN`。退出条件是W4～W6通过、E2.5 oracle不回归、共同支持范围不存在route-specific legality exception。

### RU2：typed universe、obligation、proposition 与 evidence

1. **RU2.1 Stable identities**：subject/event/instruction/operand/thread/object/proposition/obligation IDs及序列化。
2. **RU2.2 Event universe ledger**：每个producer stage输入/输出对账，event只能retained、removed-with-proof或unresolved。
3. **RU2.3 Obligation inventory**：checker前显式枚举 conflict/execution/projection obligations。
4. **RU2.4 Typed Unknown propositions**：Unknown指向未证明命题，替换裸PC和字符串context。
5. **RU2.5 Registered proof rules**：`ProofFact`带registered rule、premises和明确conclusion。
6. **RU2.6 Typed discharge**：proof conclusion必须匹配Unknown proposition，或用registered rule证明obligation不再relevant。
7. **RU2.7 Compatibility adapter**：旧模型只能转成legacy/incomplete representation，不能合成缺失proposition。

`covered_events`只保留解释用途，不再具有discharge语义；`supporting_facts`迁移为真实premises。退出条件是W7～W9、W13通过，并有property test证明删除任意event/obligation/Unknown都会使verification失败。

### RU4：thread/lifecycle/synchronization identity

1. lifecycle characterization覆盖create/start/end/join/detach、失败返回、handle复用、反序调度。
2. trace schema记录create operation id、pthread_t handle、callback、parent `ThreadInstanceId`；START绑定create。
3. join通过handle解析唯一thread instance；ambiguous/missing保留typed Unknown。
4. 任意产生event的thread必须进入lifecycle ledger，即使缺START/END。
5. `SYNC_*`、futex、mutex/cond/barrier分别声明ordering来源，不依赖调度ticket。
6. 只有精确create/join proof才能删除HB覆盖的communication edge。

旧trace缺correlation字段时不能猜测，必须`UNKNOWN`。退出条件是W3/W14通过，且`thread_handoffs_complete`被全universe lifecycle state替代。

### RU5：TraceStore subject 与 import completeness

1. metadata schema记录trace ID/digest、schema、config、chunk ledger和state。
2. transactional import从`CREATING`到`COMPLETE`；异常保持`FAILED/INCOMPLETE`。
3. 复用store前严格比对subject；不匹配拒绝，不静默混入或清空。
4. manifest、raw chunk、decoded event、object/thread inventory逐层count/digest对账。
5. communication scan和window partition记录输入universe、输出覆盖和resource-limit状态。

退出条件：partial、stale、mixed、duplicate、truncated store均保守失败；同trace复用完全可重现；W10在certificate前被拒绝。

### RU3：legality-preserving projection

projection按effect/object ownership与relation closure证明，不按module判断。

1. W1/W2及runtime/harness/shared-object characterization。
2. projection ledger对retained/removed event和relation逐项记账。
3. static只有`ProofFact`证明thread-local、readonly、lifecycle-disjoint或contract-closed effect时才删除。
4. dynamic保留所有与application-owned object或retained event连通的library-mediated communication。
5. preservation checker验证source/target obligation closure；证明不了用full graph或`UNKNOWN`。
6. 删除旧module-only scope与独立fast-path verdict规则。

退出条件：F01～F03关闭，所有removal进入canonical ledger，application-only只是有证书的projection policy。

### RU6：independently replayable certificates

Static SAFE必须绑定immutable subject、complete event universe、retained/removal partition、complete obligation/Unknown inventory、registered proof graph、semantic digests和checker conclusion。

TRACE_SAFE还必须绑定trace/chunk/import ledger、executable/library/argv/environment/thread config、tracer/client/analyzer identities、event/object/thread universe、communication/project/window coverage及trace-scoped Unknown。

COUNTEREXAMPLE必须包含events、PO/RF/CO/FR、Fence/atomic/sync、source/target legality和translation rule。

提交顺序：schema vNext与strict parser → immutable binding → static universe/obligation replay → proof rule replay → trace import/graph/window replay → counterexample replay → legacy reader → 删除旧verifier确定verdict入口。

退出条件：W7～W12均被独立verifier正确拒绝；mutation tests覆盖所有mandatory field；contract/spec只读取一次immutable bytes。

### RU7：回归、架构约束与恢复优化

- W1～W14成为长期测试，不依赖benchmark名称。
- core semantics不得导入static/dynamic/evaluation。
- 未知schema major version必须失败。
- Unknown不丢、removed event必有proof、ObservedFact不进入SAFE。
- differential共同支持范围要求exact match；差异只能是显式capability/`UNKNOWN`。
- fast path恢复时证明与reference path产生同一universe/obligation/verdict。
- 最后运行完整suite、E2.5 representative+herd、2595 ELF和PARSEC；corpus只衡量回归/性能，不定义正确答案。

## 建议 atomic commit 序列

| Commit intent | 必须验证 | 失败时行为 |
| --- | --- | --- |
| Record detailed soundness remediation design | `git diff --check` | 不进入生产实现 |
| Reject incomplete dynamic communication proof | W2/W10 | `UNKNOWN` |
| Stop unproved cross-module static pruning | W1 | 保留event/Unknown |
| Make FUTEX ordering contract-driven | W4+oracle | unsupported→`UNKNOWN` |
| Introduce canonical range primitives | W5/W6 | 暂不迁移consumer |
| Unify source PPO | herd/source fixtures | mismatch阻止提交 |
| Unify target policy semantics | DBT contract+target oracle | missing rule→`UNKNOWN` |
| Add stable subject/event/proposition IDs | roundtrip/stability | 旧adapter标legacy |
| Add event/obligation ledgers | deletion mutation tests | incomplete→`UNKNOWN` |
| Enforce typed Unknown discharge | W8/W9/W13 | 不匹配拒绝 |
| Bind lifecycle by handle identity | W3/W14 | ambiguity→typed Unknown |
| Bind TraceStore to one subject | stale/mixed fixtures | mismatch拒绝 |
| Add projection ledger/preservation | W1/W2 | 无proof不投影 |
| Add certificate schema vNext | strict version/binding | 旧证书legacy-only |
| Replay SAFE/TRACE_SAFE completeness | W7～W10 | omission拒绝 |
| Replay counterexample witness | W11 | 缺witness拒绝 |
| Re-enable proven fast paths | optimized==reference | 不等价保持关闭 |
| Run full soundness regression | full suite+E2.5 | 不修改预期掩盖失败 |

每个提交至少运行focused unit/invariant/contract tests和`git diff --check`；涉及依赖边界时运行architecture tests。每个unit结束时运行完整pytest。大型corpus只在RU7执行。

## 进度记录协议

每个commit必须在本文末尾记录：日期、hash、finding IDs、witness IDs、修改的abstraction、测试结果、仍保留的Unknown/unsupported、删除的旧结构、下一提交边界。

若暂时引入xfail，必须写明对应bug、为何不算完成、由哪个后续commit关闭，以及哪个gate阻止unit完成。

## Atomic commit plan

### RU1：canonical memory-semantics kernel

先写 fixed-execution characterization，覆盖 source PPO、target PPO、same-address、LOCK/RMW、LFENCE/SFENCE/MFENCE、FUTEX 和 native synchronization marker。为 static `encoding.py` 与 dynamic `relations.py` 建立同一组明确的 primitive 输入/输出边界；不改变最终 verdict，不把 dynamic observation 接入 proof closure。

第一个 atomic commit 只引入 characterization fixtures、semantic primitive 的类型边界和对当前两条实现差异的 failing/expected-difference 记录，不重写 checker。第二个 commit 才迁移一个 primitive，并用 herd7/DBT contract 复核。无法由 contract 或独立 oracle 决定的 ordering 必须显式保留 `UNKNOWN`。

退出条件：共同支持范围的 primitive 有单一命名和版本化输入；static/dynamic/oracle 差异均有测试；FUTEX 不再被无依据地扩大为 full ordering。

### RU2：typed event universe、obligation 与 proposition identity

引入稳定的 event identity、object/range identity、thread/trace identity、obligation identity 和 proposition identity。把 `UnknownFact`、`ProofFact`、`ObservedFact` 的 discharge 关系从裸 dict/裸 PC/coverage bool 改为 typed relation。保留旧 JSON 的显式 adapter，并标出删除条件。

退出条件：每个 relevant event、Unknown 和 proof obligation 都能稳定定位到 module、PC、operand、object、thread role 和 analysis scope；无关 proof 不能 discharge Unknown；缺 identity 只返回 `UNKNOWN`。

### RU4：thread/lifecycle/synchronization identity

按 pthread handle、create call-site/context、实际 callback target、START/END 和 join/detach operation 建立关系。对 wrapper、多 caller、函数指针和不同出现顺序使用 context identity；不能唯一确定的关系继续 typed `UnknownThreadEntry`、`UnknownJoinRelation` 或 `UnknownSynchronization`。

最小 witnesses 包括 W3、W4、W14。退出条件：线程生命周期完整性覆盖整个 recovered event universe，而非只覆盖已恢复子集；pthread handle 不再依赖 worker 出现顺序配对。

### RU5：TraceStore subject 与 completeness

为 trace、导入批次、module closure、event ledger、communication graph、window 和终止状态建立稳定 subject identity。导入时记录缺失、截断、未知记录、旧 trace 混入和 resource limit；producer 的 `complete=True` 必须由 verifier 重新核对。

退出条件：任何 trace 缺少必要 ledger 都只能 `UNKNOWN`；完整性证据可被 certificate replay 使用；W10 不会生成 `TRACE_SAFE`。

### RU3：legality-preserving projection

统一 application scope、library-mediated communication、shared-object range、field overlap 和 communication-window projection。所有被移除事件进入 canonical `RemovalDecision`，并附 legality-preserving rule/premises；不能证明投影保持 source/target execution legality 时保留完整事件或返回 `UNKNOWN`。

最小 witnesses 为 W1、W2、W5、W6。退出条件：不能通过 module 白名单、benchmark 名称或 fast path 删除 library/harness 事件。

### RU6：independently replayable certificates

扩展 `SAFE`、`TRACE_SAFE` 和 `COUNTEREXAMPLE` certificate binding。`SAFE` 必须绑定完整 event universe、obligation、Unknown closure、rule/premises 和 contract/config/spec 内容；`TRACE_SAFE` 还必须绑定 trace import、communication、window 和 completeness ledger；`COUNTEREXAMPLE` 必须包含可重放的 PO/RF/CO/FR witness。

退出条件：W7～W12 全部拒绝非法 certificate；旧 certificate 只能显示为 legacy、不可静默验证为新语义。

### Fast path re-enablement

只有在 RU3、RU5、RU6 对对应路径给出完整证明后，才允许重新启用 application-only 或其他 projection fast path。fast path 必须通过同一 canonical verifier；它不能拥有独立 verdict 规则。

### RU7：adversarial regression 与完整 suite

加入 W1～W14 的最小测试，并加入 architecture/dependency、schema、proof-closure、stable-ID、semantic differential 和 certificate replay 检查。先运行针对 unit 的小套件，再运行完整默认 suite；不以 `TRACE_SAFE`/`SAFE` 数量增加作为成功标准。

## 最小 regression witnesses

| 编号 | 必须防止的错误 |
| --- | --- |
| W1 | library function 访问 application-owned shared object 被 scope 删除 |
| W2 | application-only projection 跳过 library-mediated communication |
| W3 | worker 启停顺序与 pthread_join handle 顺序不同仍被错误配对 |
| W4 | store/load → FUTEX_WAIT → store/load 被错误扩大为 full ordering |
| W5 | 同 allocation 的不重叠字段被当作 same-address |
| W6 | mixed-width partial overlap 被错误裁剪 |
| W7 | SAFE certificate 漏一个 recovered event |
| W8 | SAFE certificate 漏一个 relevant Unknown |
| W9 | 无关 ProofFact discharge Unknown |
| W10 | TRACE_SAFE `complete=True` 但缺 universe/windows/communication evidence |
| W11 | COUNTEREXAMPLE 缺 replayable witness |
| W12 | contract 内容变化但 version/revision 不变 |
| W13 | 不同 module 的同裸 PC 错误过滤 Unknown |
| W14 | 存在 memory events 但缺 START/END 的第三线程 |

## Schema 与迁移策略

- 新 schema 明确版本、producer、contract revision、analysis config digest 和 identity namespace。
- 旧 report/trace 通过显式 legacy reader 读取；reader 只能生成不可验证的 legacy view，不得填充缺失字段或推断 completeness。
- 新 writer 同时保留必要的旧 JSON adapter，直到所有 application service 和 certificate verifier 迁移完成；adapter 必须在代码中写明依赖者和删除条件。
- 不在同一个 commit 中同时迁移 producer、checker、certificate 和 CLI；每次迁移后做 old/new differential comparison。

## 进度日志与风险

### 已完成

- `5cfab59` 保存当前动态 trace scope、communication、syscall effect 和 module permission 工作。
- E2.5 correctness baseline 已冻结，litmus corpus measurement 和 E3 roadmap 保留。
- 本文件建立 RU1～RU7 的边界、风险和退出条件。

### 未关闭

- RU1 已建立 primitive 身份和 byte-range 关系边界，但 static/dynamic PPO、
  RF/CO/FR、Fence 和 atomic boundary 仍未迁移到 canonical consumer。
- event universe、obligation、proposition identity 尚未贯穿所有 certificate 路径。
- application scope、trace completeness、lifecycle identity 和 certificate replay 仍可能产生 false confidence。
- C0 后完整默认 suite 已通过；后续仍需按 RU1～RU7 的 unit 逐步补齐。

### C0.1 已完成

- 提交：`3d98045`。
- finding：F03、F13；witness：W2、W10。
- `DynamicCertificate` 新增 typed `unknown_kinds`；不完整 communication graph
  现在会记录 `IncompleteRecovery`，并阻止 `TRACE_SAFE`/`COUNTEREXAMPLE`。
- pipeline 不再把 application partition、thread handoff 或空 windows 当成
  graph completeness；application-only fast path 未新增，原有不完整路径只会收紧为
  `UNKNOWN`。
- focused/invariant tests：`25 passed`（pipeline、dynamic trace binding、current
  verdict baseline）；`git diff --check` 通过。
- 剩余风险：C0.1 只关闭 dynamic incomplete-graph 的错误接受路径；static
  cross-module pruning、FUTEX ordering、certificate ledger 和 TraceStore identity
  仍未修复。完整默认 suite 尚未在本 unit 结束时运行。

### C0.2 已完成

- 提交：`5ce5994`。
- finding：F01；witness：W1。
- application scope 不再因 `module_sha256 != executable_sha256` 自动删除事件；
  只有 `runtime_internal` effect/object provenance 才能进入 runtime boundary
  removal。普通 dependency-library load/store、opaque call、syscall 和未知对象
  继续留在 slice 中。
- focused tests：`26 passed`（partition/slice 与 portability verifier）；相关
  invariant/architecture tests：`14 passed`；`git diff --check` 通过。
- 删除的旧结构：无；这是止血收紧，永久 projection ledger 仍待 RU3。
- 剩余风险：runtime_internal 标记本身还没有接入 canonical removal ledger，
  library-mediated communication 的 legality-preserving proof 仍待 RU3/RU6。

### C0.3 已完成

- 提交：`658d2a4`。
- finding：F04/F18；witness：W4。
- `FUTEX_WAIT` 不再由 dynamic relation 自动生成 full-order edges；只有绑定
  contract 显式声明 syscall ordering 时才允许后续实现提供该语义。当前
  `dbt6-mo-off` contract 未声明时记录 typed `UnknownSynchronization`，并阻止
  `TRACE_SAFE`/`COUNTEREXAMPLE`，包括单线程 shortcut。
- `TraceValidation` 记录 event kind，contract parser 显式识别可选 syscall rule；
  未声明 rule 不会被默认成 relaxed 或 full。
- focused tests：`49 passed`（pipeline、relation differential、trace format）；
  contract/invariant tests：`8 passed`；`git diff --check` 通过。
- 剩余风险：显式 syscall ordering 尚未进入 canonical semantic kernel；
  `SYNC_ACQUIRE/RELEASE/FULL` 与 lifecycle ordering 仍需 RU1/RU4 统一。

## 当前执行点

RU1.1 的 `SemanticPrimitive`/`SemanticPrimitiveRef` 身份边界由 `8ac64a0`
引入；C0.1～C0.5 已分别在 `3d98045`、`5ce5994`、`658d2a4`、
`60e7b13`/`7ddbb19` 和 `557db2f` 收紧为保守失败。

RU1.2 已在 `4608221` 完成：新增 core-owned `AccessRange`、`RangeRelation`、
`relate_ranges` 和 `ranges_overlap`。它只描述带 object identity 的精确字节范围，
尚未迁移 static/dynamic checker；W5/W6 characterization 明确覆盖不同对象、
同对象不重叠、完全相等、包含和 partial overlap。focused differential/contract
tests 为 `30 passed`，identity/architecture/verdict invariant tests 为
`24 passed`，C0 收口后的完整 suite 为 `480 passed, 10 skipped`。

RU1.3 已在 `0a70c89` 完成：新增 core-owned `MemoryAccessKind`、
`MemoryOperation` 和 `source_ppo_preserved`。普通 Load/Store 的 source PPO
现在有独立 characterization：同址或 partial-overlap Store→Load 保留，异址
Store→Load 可放松，跨线程不产生程序顺序；Fence、LOCK/XCHG、同步事件仍不在
这个窄接口内。现有 static/dynamic same-address 路由差异不再标为“预期例外”，
而是显式记录为 `UNRESOLVED_MODEL_DRIFT`，对应 F17 的后续迁移边界。focused
differential/characterization/oracle tests 为 `35 passed`，identity/architecture/
verdict invariant tests 为 `24 passed`。本提交没有迁移 consumer，也没有修改
最终 verdict 或 ProofFact。

RU1.4 已在 `6c215d6` 完成：`TranslationContract` 新增 typed
`LoweringOperation`/`FenceOperation` 查询，plain load/store、LOCK/RMW、XCHG、
syscall 和 LFENCE/SFENCE/MFENCE 都只能从同一个 immutable contract 取值；未声明
syscall ordering 继续是 `UNKNOWN`，调用方不能用字符串或 API 名称猜排序。新增
`MemoryOrderContract.semantic_digest()`，把 schema、revision、source/target model
和所有 lowering 字段绑定到 canonical SHA-256 内容摘要，覆盖 W12 的 contract
内容边界，但尚未把 digest 接入 certificate binding。RU1.4 focused contract、
characterization、repository-boundary 和 verdict tests 为 `26 passed`；未修改
static/dynamic checker consumer、最终 verdict 或 ProofFact。
RU1.4 focused tests 为 `26 passed`，随后完整默认 suite 为 `491 passed, 10 skipped`；
跳过项仅依赖未配置的 DynamoRIO/native capture 或显式 opt-in 的真实 litmus ELF。

RU1.5 的 characterization 已在 `f98a0bf` 完成，core typed relation 边界在
`b2f0325` 完成：新增 `RelationKind`、`MemoryRelation` 和 `ExecutionRelations`，
显式区分 RF/CO/FR 方向、初始写、端点访问类型和 proposition key。已提交的
partial/disjoint relation 不会被当作 exact-width；`all_exact_width` 只检查已提交
命题的范围，刻意不声称 RF/CO/FR universe 完整。静态和动态 fixed-execution
characterization 对共同 exact-width RF/CO/FR fixture 均为 allowed；新增 relation
unit/differential tests 与 architecture/verdict tests 通过，完整默认 suite 为
`496 passed, 10 skipped`。本阶段没有迁移 checker consumer、没有改变 verdict，
也没有把 relation observation 变成 ProofFact。

RU1.6 的第一步已在 `0c5cd71` 完成：static fixed-execution characterization
新增 `canonicalize_fixed_relations()` 和 typed `relations=` 入口。adapter 只把
能够唯一绑定到同一 `SharedMemorySlice` 的 RF/CO/FR 命题转回现有 tuple/dict
encoder；typed 与 legacy 参数禁止混用，端点、object/range 或 exact-width
不匹配时返回 `UNKNOWN`。旧入口仍保持原行为，dynamic consumer 和正式 verdict
路径尚未迁移。focused static/characterization/model tests 为 `26 passed`，
完整默认 suite 为 `498 passed, 10 skipped`。

RU1.6 的第二步已在 `028857e` 完成：dynamic fixed-execution characterization
增加与 static 对称的 `canonicalize_fixed_relations()` 和 typed `relations=`
入口。动态地址只能绑定到唯一 `object_locations` 或稳定的地址/宽度标签；
FUTEX、歧义 object label、端点不属于当前 window、partial-width 和 typed/legacy
混用都会保守返回 `UNKNOWN`。旧 dynamic tuple/dict 入口和原有 window verdict
保持不变；static/dynamic exact-width fixture 的 typed/legacy differential
测试通过，完整默认 suite 为 `499 passed, 10 skipped`。

下一步不扩大 consumer 迁移面：先为两个 adapter 增加统一的 relation
completeness/obligation characterization，确认“all exact”不会被误解为
RF/CO/FR universe 完整；随后才评审是否迁移正式 checker consumer。

RU2.1 第一窄步已在 `5642332` 完成：identity 层新增稳定
`PropositionId`/`ObligationId`，`MemoryRelation.proposition_id` 和
`ExecutionRelations.proposition_ids` 使用有向端点、对象和范围材料生成可重算
的命题身份。`all_exact_width` 只表示当前提交的 relation 没有超出 exact-width
支持集，不表示 obligation 或 relation universe 完整；event universe、obligation
ledger 和 proof discharge 仍未迁移。focused identity/semantics/boundary tests
为 `39 passed`，完整默认 suite 为 `502 passed, 10 skipped`。

RU2.2 第一窄步已在 `4a5b694` 完成：新增 core-owned
`EventUniverseLedger`、`EventUniverseEntry`、`EventDisposition` 和显式
`CompletenessState`。每个已识别输入 event 只能是 retained、removed-with-proof
或 unresolved；COMPLETE ledger 缺项会拒绝，INCOMPLETE/UNSUPPORTED 必须带
scope/reason 并暴露 `missing_event_ids`。这是独立对账值对象，尚未把旧
`covered_events`、静态 slice 字符串 event id 或任何 verdict 路径强行映射进来；
旧字段不能承担 universe completeness 或 Unknown discharge 语义。focused
universe/identity/certificate tests 为 `35 passed`，完整默认 suite 为
`509 passed, 10 skipped`。

RU2.2 的 static slice 接入已在 `524f85f` 完成：`StaticSliceEvidence` 新增可选
`event_universe`。新 builder 用 canonical event link、实际 retained report 和
逐事件 removal decision 生成 `EventUniverseLedger`；legacy Unknown 没有唯一
canonical subject 时不猜测 UnknownFact，而是省略 entry、暴露 `missing_event_ids`
并设为 `INCOMPLETE`。旧 certificate bridge 构造没有 universe 时保持
`None`，因此没有借空字段升级旧报告。focused slice/bridge/universe tests 为
`24 passed`，完整默认 suite 为 `511 passed, 10 skipped`。

RU2.3 的目标仍是为 static portability checker 建立显式
execution/projection obligation inventory；旧 `covered_events` 只保留回查用途，
不能单独 discharge Unknown 或证明 event universe 完整。

RU2.3 core foundation 已在 `48e2b72` 完成：新增 `ObligationKind`、
`ProofObligation` 和 `ObligationInventory`。每个 obligation 绑定稳定
`ObligationId`、`PropositionId`、kind、scope 和 subject 集合；inventory 的
`is_enumerated` 只反映枚举 completeness，不是 ProofFact closure。focused
obligation/universe/closure tests 为 `32 passed`，完整默认 suite 为
`516 passed, 10 skipped`。

RU2.3 static fixed-execution inventory 已在 `f0b333f` 完成：
`build_execution_obligation_inventory()` 为 RF/CO/FR 生成带稳定
`PropositionId`、`ObligationId` 和 canonical event subjects 的
`ObligationInventory`，并独立检查 read coverage、per-object CO 全序和
由 RF/CO 导出的 FR。exact-width 不足、端点 identity 缺失或 relation universe
不闭合时 inventory 保持 `INCOMPLETE`；static typed adapter 没有 inventory
或 inventory 未枚举完整时只能返回 `UNKNOWN`。这一步没有接入最终 SAFE
certificate，也没有改变 legacy tuple/dict route。

本提交 focused characterization/portability/obligation tests 为 `27 passed`；
随后完整默认 suite 为 `517 passed, 10 skipped`，跳过项仍仅依赖未配置的
DynamoRIO/native capture 或显式 opt-in 的真实 litmus ELF；`git diff --check`
通过。`f0b333f` 的剩余风险：conflict/projection obligations、typed Unknown
proposition 与 registered proof rule 尚未接入；dynamic fixed-execution route
尚未拥有同等 obligation inventory。

RU2.3 的 static/dynamic shared inventory 已在 `7c55207` 完成：execution
obligation 枚举迁移到 core 的单一实现，两个 route 只负责将自身事件归一化为
`MemoryOperation`。两边都要求 caller 提供 trace/binary-bound 的
`MemoryEventId`；缺少 identity、relation endpoint 或 exact-width universe
时保持 `INCOMPLETE`，typed adapter 保守返回 `UNKNOWN`。RF/CO 已给定时，
core 会把由它们唯一导出的 FR 命题列为 obligation，即使 legacy 输入省略
FR；它不会把 FR 观察伪装成 producer 提交的 relation 或 ProofFact。

本提交 focused tests 为 `28 passed`，随后完整默认 suite 为
`518 passed, 10 skipped`；`git diff --check` 通过。剩余风险仍是 conflict/
projection obligations、typed Unknown proposition、registered proof rule 和
最终 SAFE certificate replay 尚未迁移；旧 legacy route 仍只受既有检查约束。

RU2.3 的 conflict/projection inventory 已在 `d92aa36` 完成：core 新增
`build_conflict_obligation_inventory()` 与
`build_projection_obligation_inventory()`。通信候选按 stable event pair
生成对称 conflict proposition；候选扫描、event universe 任一不完整时，已
观察到的 obligation 会保留，但 inventory 只能是 `INCOMPLETE`。projection
obligation 从 `REMOVED_WITH_PROOF` ledger entry 逐项绑定 event 与 EvidenceId；
它不把 removal entry 当成 ProofFact closure，也不改变现有 scope/checker 路径。

本提交 focused obligation/universe tests 为 `25 passed`；随后完整默认 suite
为 `522 passed, 10 skipped`；`git diff --check` 通过。剩余风险：这些 inventory
目前还没有接入 static SAFE certificate 的 replay verifier；typed Unknown
proposition、registered proof rule 和 conflict/projection 的 route consumer
仍未迁移。

RU2.4 的首个 typed Unknown proposition 边界已在 `a594a03` 完成：新增
`UnknownProposition`，由注册命题 kind、analysis scope 和稳定 subjects 计算
`PropositionId`；`UnknownFact` 可绑定该 proposition，且 proposition scope 必须
与 Unknown scope 相同。带 proposition 的 Unknown 会把 proposition 内容纳入
自身 EvidenceId，旧 schema 的 `proposition=None` 仍按 legacy identity 生成，
不会靠补空字段升级。现有 ledger 仍只允许静态 provenance，ObservedFact 与
DiagnosticHint 没有新入口进入 Unknown 或 SAFE closure。

本提交 focused evidence/diagnostic tests 为 `25 passed`；随后完整默认 suite
为 `523 passed, 10 skipped`；`git diff --check` 通过。剩余风险：现有 static
producer 尚未为每个 Unknown 生成 proposition，旧 `supporting_context` 仍可能
是唯一定位信息；因此本提交没有收紧旧 SAFE 路径，也没有声称 RU2.4 已完成。

RU2.4 的 static recovery adapter 已在 `3486b8a` 完成：
`emit_static_unknown()` 增加显式 `canonical_subject`/
`canonical_proposition` 输入；只有 caller 已经拥有稳定 identity 时才创建
`UnknownProposition`，模块路径、函数名或裸 PC 不会在 adapter 内被猜成
instruction identity。旧调用点不传 subject 时仍生成 legacy/incomplete
Unknown，未改变旧 producer 的 verdict。

本提交 focused static evidence tests 为 `13 passed`；随后完整默认 suite 为
`524 passed, 10 skipped`；`git diff --check` 通过。剩余风险：当前正式
recovery producer 大多仍未把 event/object/thread identity 传入 adapter，因而
其 Unknown 仍只能作为 legacy/incomplete view；typed proposition 还不能参与
SAFE discharge。

RU2.4 的 typed/legacy bridge 已在 `479b753` 完成：core 新增
`match_unknown_to_obligation()` 及 `ObligationMatchStatus`。legacy
`UnknownFact` 没有 proposition 时只返回 `INCOMPLETE`；typed Unknown 必须同时
匹配 obligation 的稳定 `PropositionId` 和 scope，命题不一致或 scope 不一致
返回 `MISMATCH`。该接口只报告 identity binding，不执行 discharge，也没有
修改 SAFE/UNKNOWN/COUNTEREXAMPLE 规则。

本提交 focused obligation/evidence/closure tests 为 `29 passed`；随后完整默认
suite 为 `526 passed, 10 skipped`；`git diff --check` 通过。剩余风险：正式
certificate verifier 仍未要求所有 relevant Unknown 都具备 typed proposition，
已有 legacy producer 仍会通过旧 adapter 进入报告；RU2.4 还需要在 verifier
边界增加显式 legacy 降级检查。

RU2.4 的 certificate-side audit 已在 `79e2930` 完成：
`audit_unknown_propositions()` 和 `UnknownPropositionAudit` 在 replay 输入上
单独盘点 typed、legacy、missing Unknown。`StaticVerification` 保留这份审计
结果，但不把 legacy Unknown 变成 typed，也不把它从 unresolved 集合移除；
真正的 SAFE gate 仍由既有 proof closure、discharge 和 schema 门禁执行。

本提交 focused certificate/evidence/obligation tests 为 `30 passed`；随后完整
默认 suite 为 `527 passed, 10 skipped`；`git diff --check` 通过。剩余风险：
certificate schema 尚未携带完整 event/obligation universe，因而 audit 不能替代
RU6 独立 replay；typed Unknown 也还没有 registered proof rule 可供 discharge。

RU2.5 的 typed proof 基础已在 `63ef502` 完成：`ProofFact` 可选绑定版本化
`RegisteredProofRule` 和带 scope 的 `ProofConclusion`。这两个字段进入
ProofFact 的 content-bound identity；旧 proof 未提供它们时仍保留 legacy
identity，不能靠空字段升级。`EvidenceLedger` 原有 premise 检查继续只允许
ProofFact，因此 ObservedFact/DiagnosticHint 不能成为 proof premise；本提交
没有把新 rule 接到旧 SAFE verdict 入口。

本提交 focused evidence/obligation/certificate tests 为 `31 passed`；随后完整
默认 suite 为 `528 passed, 10 skipped`；`git diff --check` 通过。剩余风险：
尚无 rule registry/replay evaluator 来核对 conclusion 是否真正由 premises
推出，旧 certificate 仍可能只携带裸 rule 字符串；RU2.5 尚未完成。

RU2.5 的最小 rule registry/replay contract 已在 `9726583` 完成：新增不可变
`ProofRuleRegistry`、`ProofRuleDefinition` 和 `replay_proof_rule()`。replay
要求 registered rule 的 name/version 已注册、与 legacy rule name 对应、
conclusion 已存在且 scope 相同，并重新检查每个 premise 仍是 ProofFact；
legacy、未注册和 typed 字段冲突分别保留为 `INCOMPLETE` 或 `MISMATCH`。这个
接口只检查输入 contract，不执行规则定理，也没有接管旧 certificate verdict。

本提交 focused proof-rule/evidence/certificate tests 为 `23 passed`；随后完整
默认 suite 为 `531 passed, 10 skipped`；`git diff --check` 通过。剩余风险：
registry 目前只验证身份和 premise 类别，没有声明每条 rule 的具体证明语义；
现有 SAFE certificate 仍未绑定 rule registry digest，RU6 replay 仍待完成。

RU2.5 的 conclusion/obligation identity 检查已在 `9fdb53a` 完成：新增
`match_proof_to_obligation()` 和 `ProofObligationMatch`。只有带
`RegisteredProofRule`、带 typed `ProofConclusion`，并且 conclusion proposition
与 obligation 的 `PropositionId`、scope 同时相等时才返回 `MATCH`；legacy
proof 或任一字段缺失返回 `INCOMPLETE`，不一致返回 `MISMATCH`。该检查仍是
只读 contract，不执行 proof 定理，也不会单独升级 SAFE。

本提交 focused obligation/evidence/rule tests 为 `25 passed`；随后完整默认
suite 为 `532 passed, 10 skipped`；`git diff --check` 通过。剩余风险：
`match_proof_to_obligation()` 尚未被 `EvidenceLedger.add_discharge()` 或
certificate verifier 调用，registered rule registry 也未绑定到 certificate
digest；这些属于 RU2.6/RU6 的迁移边界。

RU2.6 的 typed discharge gate 已在 `85b3b3b` 完成：
`EvidenceLedger.add_typed_discharge()` 先检查 Unknown 与 obligation 的稳定
proposition/scope，再检查 ProofFact 的 `ProofConclusion`、registered rule
registry 和 premise 类型，最后才写入已有 discharge 表。legacy Unknown、裸
rule proof、ObservedFact/DiagnosticHint 或 proposition mismatch 都会在 ledger
状态改变前返回 `LedgerError`；旧 `add_discharge()` 保留为 legacy reader 接口，
没有改变旧 certificate schema 的 explain-only 行为。

本提交 focused proof-rule/evidence/obligation/certificate tests 为 `37 passed`；
随后完整默认 suite 为 `534 passed, 10 skipped`；`git diff --check` 通过。剩余
风险：certificate verifier 尚未强制所有 SAFE discharge 使用 typed gate，且
typed inventory 尚未绑定到 certificate 的完整 obligation universe；RU6 replay
仍需独立重算这些输入。

RU2.6 的 certificate-side typed discharge replay 已在 `2dcc508` 完成：新增
`verify_typed_discharge()`，在不修改 ledger 的前提下重新检查 discharge 是否
存在、Unknown/Proof 是否匹配同一 obligation、rule registry 是否可 replay，
并拒绝 legacy proof 或 ObservedFact/DiagnosticHint 路径。该接口仍是
certificate-side characterization，尚未替换旧 `verify_static_certificate()`
的 schema/verdict 入口。

本提交 focused certificate/evidence/obligation/rule tests 为 `28 passed`；随后
完整默认 suite 为 `535 passed, 10 skipped`；`git diff --check` 通过。剩余风险：
旧 static certificate verifier 还没有 obligation inventory 参数，不能独立核对
所有 discharge 是否覆盖完整 obligation universe；RU6 仍需把这个只读 gate
绑定到新 schema。

下一提交离开 RU2 的 core identity 增量，进入 RU4 前的 characterization：先
审计并固定 lifecycle/synchronization identity 的输入契约（create/start/end/
join/handle/futex），为 W3/W4/W14 建立 typed ledger 缺口，而不修改 pthread
恢复算法或按调度顺序猜 join 关系。

### RU4.0 生命周期/同步身份 characterization 已完成

- 提交：`8ba29ef`（`Characterize lifecycle identity contract`）。
- finding：F05、F06、F18；witness：W3、W4、W14。
- core 新增 `ThreadHandleId`、`LifecycleContextId` 和
  `LifecycleOperationId`。句柄身份显式绑定 subject、token 和 generation；
  生命周期操作显式绑定 site、caller/callback context 和 producer 提供的
  occurrence，不能用调度 ticket 或遍历顺序替代。
- 新增 `ThreadLifecycleRecord`、`LifecycleJoinRelation` 和
  `LifecycleLedger`。账本先接收产生事件的完整 thread universe；缺少某条
  START/END 或第三线程记录时只能是 `INCOMPLETE`，不会把空记录解释成没有线程。
  `resolve_handle()` 只按 `ThreadHandleId` 找唯一 child，不读取 worker/join
  出现顺序。
- 新增 `SynchronizationIdentity` 和 `SyncOperationKind`。它们只记录同步
  对象与 immutable contract digest/rule 的绑定，不定义 acquire/release/full
  ordering；FUTEX 缺少 contract rule 时不能构造 COMPLETE identity。
- 未修改 static pthread recovery、dynamic TraceEvent/TraceStore、通信窗口、
  checker 或任何 SAFE/TRACE_SAFE verdict 路径；这些类型目前是迁移输入契约，
  不是现有 producer 的自动证明。
- focused lifecycle/identity/universe tests：`23 passed`；完整默认 suite：
  `540 passed, 10 skipped`；`git diff --check` 通过。
- 仍保留的风险：现有 static `ThreadRole`/`ThreadJoinFact` 和 dynamic
  `TraceEvent` 尚未填充这些身份；旧 trace 没有 handle generation、callback
  context 或完整 lifecycle universe 时仍必须走 typed `UNKNOWN`。下一窄步应
  先为现有 static/dynamic 输入做只读 adapter characterization，再决定如何
  让 producer 逐字段提供身份；不能直接按当前字段猜测 join 或同步排序。

### RU4.1 static legacy adapter characterization 已完成

- 提交：`d0acfc9`（`Characterize static lifecycle adapter boundary`）。
- finding：F05、F06；witness：W3、W14。
- 新增 `characterize_thread_discovery()`，把旧
  `ThreadDiscoveryReport` 的 role、create site 和 join candidate 转为
  `LifecycleLedger`。静态 `handle_locations` 被保留在旧报告中，但不伪造
  `ThreadHandleId`；缺少运行时 generation、ThreadInstanceId、START/END 时，
  record/join/ledger 均保持 `INCOMPLETE`。
- wrapper/callback 的旧字符串 `context_id` 只用于操作 occurrence；适配器不
  把它升级为 `LifecycleContextId`，因此多 caller 或 callback target 未闭合时
  不会产生静态 proof。
- 未修改 static recovery、shared-state slice 或 checker；该函数是显式 legacy
  reader，调用者必须检查 ledger completeness。
- focused static lifecycle/线程证据 tests：`10 passed`；完整默认 suite：
  `542 passed, 10 skipped`；`git diff --check` 通过。
- 剩余风险：静态 producer 仍未输出带 context/handle generation 的新字段；
  下一窄步是 dynamic legacy trace adapter characterization，之后才评审
  producer schema 扩展。任何只按静态 role/slot 的 join 仍只能是 UNKNOWN。

### RU4.2 dynamic legacy adapter characterization 已完成

- 提交：`d541efa`（`Characterize dynamic lifecycle adapter boundary`）。
- finding：F05、F06、F18；witness：W3、W4、W14。
- 新增 `characterize_trace_lifecycle()`，为每个出现在 TraceEvent 中的裸
  `thread_id` 建立 trace-bound `ThreadInstanceId`，并保留可见 START/END 的
  定位操作。缺少 CREATE→START callback、parent、pthread_t generation 或
  完整 thread universe 时，所有 record 和 ledger 仍为 `INCOMPLETE`。
- `THREAD_JOIN` 的 `address/aux` 不再被适配器解释为 handle；join relation
  保留为无 handle 的 incomplete 状态，不能按 ticket 或出现顺序建立 HB。
- `FUTEX_WAIT` 与 native `SYNC_*` 只生成 `SynchronizationIdentity`；没有
  contract digest/rule 时标为 `UNSUPPORTED`，没有任何默认 ordering。
- 未修改 TraceEvent wire format、TraceStore、dynamic pipeline、通信扫描或
  verdict；这是旧 trace 的显式 legacy reader，不能把 observed trace 提升为
  static ProofFact。
- focused dynamic/trace/pipeline tests：`22 passed`；完整默认 suite：
  `545 passed, 10 skipped`；`git diff --check` 通过。
- 收集阶段曾发现 static/dynamic 测试同名导致 pytest import mismatch，已将
  dynamic fixture 改为唯一模块名并纳入同一提交。
- 剩余风险：新 trace schema 尚未携带 handle generation、callback context、
  parent ThreadInstanceId 或 import-level lifecycle completeness；下一步应
  先写 schema characterization/strict rejection，再讨论 producer 扩展，不
  允许从现有 aux/address 推断生命周期关系。

### RU4.3 lifecycle sidecar schema characterization 已完成

- 提交：`d05ec2a`（`Add strict lifecycle sidecar schema`）。
- finding：F05、F06、F18；witness：W3、W4、W14。
- 新增 versioned `TraceLifecycleMetadata`、`TraceLifecycleRecord`、
  `TraceLifecycleJoin` 和 `TraceSynchronizationRecord` wire model。sidecar
  明确列出 thread universe、operation identity、parent/child、handle token
  与 generation、callback context/targets、join candidates 和 contract
  digest/rule；未知字段由 strict model 拒绝。
- complete sidecar 必须覆盖非空 thread universe，所有 record/join/sync 都
  complete；缺 generation 的 handle、非唯一 join、缺 contract binding 的
  FUTEX 或缺 record 的 universe 都不能标为 complete。旧 TraceEvent/manifest
  不会通过补空字段进入此 schema。
- wire model 只定义身份和完整性，不实现 ordering，也没有接入 native writer、
  TraceStore 或 dynamic verdict；后续 producer 若不能填写字段必须返回 typed
  `UNKNOWN`。
- focused schema/lifecycle tests：`13 passed`；完整默认 suite：`550 passed,
  10 skipped`；`git diff --check` 通过。
- 剩余风险：sidecar 尚无 writer/import ledger，也没有把 wire identity 转成
  core `LifecycleLedger`；下一原子边界应先做只读 wire→core adapter，验证缺失
  或 schema major mismatch 保守失败，然后再评审 TraceStore 集成。

### RU4.3a 修正 sidecar 生命周期基数已完成

- 提交：`bfa3364`（`Require explicit lifecycle origin`）。
- finding：F05、F06；witness：W3、W14。
- `TraceLifecycleMetadata` 现在按 `operation_id` 去重，而不是按
  `thread_instance_id` 去重；同一线程的 CREATE/START/END 可以同时存在，
  但同一 operation 不能重复。
- 每条 lifecycle record 必须显式携带 `ThreadOrigin`。适配器不再从
  `parent_thread_instance_id == None` 猜测 root/created；origin 缺失只能在旧
  schema/输入错误路径保留 UNKNOWN。
- focused schema tests：`6 passed`；完整默认 suite：`551 passed, 10 skipped`；
  `git diff --check` 通过。
- 剩余风险不变：sidecar 尚无 wire→core adapter 和 import ledger；下一提交
  只实现严格的只读转换，schema major mismatch 或 identity 不可解析时拒绝，
  不修改 TraceStore/verdict。

### RU4.4 lifecycle sidecar → core ledger 适配已完成

- 提交：`7e40a90`（`Adapt lifecycle sidecar to core ledger`）。
- finding：F05、F06、F18；witness：W3、W4、W14。
- 新增只读 `lifecycle_metadata_to_ledger()`。它只接受 v2 sidecar，严格解析
  `TraceId`、`ThreadInstanceId`、`ThreadHandleId`、callback context/target、
  join 和 synchronization contract；未知 major 版本、身份无法解析、handle
  token/generation 不成对或同一线程的事实互相冲突时直接返回 typed
  `LifecycleMetadataError`，不降级成 COMPLETE。
- sidecar 顶层不完整会传递到每个已导入的 thread record；sidecar 声明的
  thread universe 仍由 core ledger 保留，因此缺失的线程、START/END、join
  target 或同步 contract 不会被空列表解释成“没有关系”。callback target
  候选不一致时保留并集，同时把 record 标为 `INCOMPLETE`。
- `ThreadLifecycleRecord` 现在显式保留 `callback_targets`，并校验其
  `FunctionId` 身份唯一性；该字段仍只描述候选事实，不定义内存序。没有
  新增任何 benchmark/application-only 分支，也没有修改 checker、TraceStore
  或 SAFE/TRACE_SAFE verdict。
- focused adapter/lifecycle tests：`14 passed`；随后完整默认 suite：
  `554 passed, 10 skipped`；`git diff --check` 通过。
- 剩余风险：sidecar 还没有绑定单一 TraceStore subject、完整 import ledger
  和 producer 端的丢失/截断证明。下一原子边界进入 RU5 前，应先审计现有
  TraceStore/import 流程并建立其 subject/completeness characterization；
  在 import ledger 完成前，不能把 sidecar 的 COMPLETE 直接当作
  `TRACE_SAFE` 的完整 trace 证明。

### RU5.0 TraceStore 导入账本契约已建立

- 提交：`2ac397e`（`Add typed trace import ledger`）。
- finding：F13、F16；witness：W10 以及 stale/partial/mixed store 场景。
- core 新增 `TraceImportLedger`、`TraceImportState`、`TraceChunkRecord` 和
  `TraceLayerRecord`。账本同时绑定 `TraceId`、原始 trace digest、schema
  version、config digest、raw chunk 列表，以及 manifest/raw chunk/decoded
  event/object/thread 五个必需层的 count/digest；chunk 和 layer identity
  重复时直接拒绝。
- `COMPLETE` 必须有非空 raw chunk 且逐层覆盖全部必需层；`CREATING`、
  `FAILED`、`INCOMPLETE` 的状态语义不同，失败/不完整必须携带原因。
  `matches()` 只有在 subject、schema、config 完全相同时才允许 store 复用；
  缺层不会被空列表解释成“没有事件”。
- 这次没有修改 `TraceStore`、pipeline、communication scan 或任何 verdict
  入口；新类型是后续 storage integration 的 canonical input contract，尚
  不能单独使旧 trace 具备 `TRACE_SAFE` 资格。
- focused import/lifecycle tests：`9 passed`；完整默认 suite：`558 passed,
  10 skipped`；`git diff --check` 通过。
- 下一原子边界：为现有 `TraceStore` 增加 subject-bound open/import state，先
  用 stale、mixed、duplicate、truncated fixture 验证拒绝路径，再把 pipeline
  的导入过程接到这个账本；不能先修改 verdict 或增加新的 application-only
  shortcut。

### RU5.1 TraceStore subject-bound import reservation 已完成

- 提交：`a1855ef`（`Bind TraceStore to import subject`）。
- finding：F16；witness：stale/mixed store 与 duplicate active import。
- `TraceStore` 新增持久化 binding、chunk/layer ledger 表和只读
  `import_ledger()`。`begin_import()` 只接受 `CREATING` ledger；已有 store
  的 subject、schema 或 config 任一不匹配即拒绝，同一绑定重复占用也拒绝。
  这防止不同 trace 在同一个 DuckDB 文件中静默混合。
- `record_import_layers()` 在单事务中替换当前导入的 chunk/layer 行，但只允许
  `CREATING` 状态；失败会回滚。没有 binding 的旧 store 明确返回 `None`，不被
  当作“空而完整”的 trace，也没有新增 legacy fast path。
- 本提交没有让 pipeline 自动声明 `COMPLETE`，也没有改变
  `SAFE/TRACE_SAFE/COUNTEREXAMPLE`。raw chunk 实际 digest、decoded/object/
  thread inventory 的独立核对，以及 CREATING→COMPLETE 的最终状态转换仍待
  后续窄步完成。
- focused storage/import tests：`7 passed`；完整默认 suite：`561 passed,
  10 skipped`；`git diff --check` 通过。
- 下一原子边界：实现 import ledger 的分层计数/digest verifier，从实际 raw
  chunk、DuckDB events、objects 和 thread inventory 重算输入；不接受 producer
  单独提交的 `complete=True`。在此之前，旧 pipeline store 仍只能作为
  legacy/unbound storage 使用。

### RU5.2 独立重算 TraceStore 导入完整性已完成

- 提交：`bce27ce`（`Verify trace import completeness`）。
- finding：F13、F16；witness：W10 以及 tampered/truncated/producer-claim
  fixtures。
- `TraceStore.complete_import()` 不接受 producer 的 `complete=True` 作为结论，
  而是从实际 `manifest.json`、每个 raw event chunk、DuckDB `events`、
  `objects` 和 distinct thread inventory 重新计算 count/digest。raw chunk
  内容、trace digest、每层 ledger 任一不匹配，或解码事件为空，都会把绑定置为
  `INCOMPLETE` 并拒绝 COMPLETE。
- 完整状态转换与 chunk/layer 行写入在同一事务中完成；异常路径不会留下可复用的
  COMPLETE 状态。截断记录由 `TraceReader` 拒绝，篡改文件由 trace digest 拒绝，
  伪造 layer count/digest 与重算结果不一致时拒绝。
- 该提交仍未把 `complete_import()` 接入动态 pipeline，也没有修改
  `TRACE_SAFE` 构造；未绑定旧 store 和尚未完成 import 的 store 仍不能作为
  完整 trace 证明。下一窄步才评审 pipeline 如何创建 binding、导入事件、物化
  object 后调用这个 verifier，并在失败时输出 typed `UNKNOWN`。
- focused storage/import tests：`7 passed`；完整默认 suite：`565 passed,
  10 skipped`；`git diff --check` 通过。

### RU5.3 dynamic pipeline 绑定并闭合 TraceStore import 已完成

- 提交：`b43ff9`（`Gate dynamic analysis on trace import`）。
- finding：F13、F16；witness：旧 single-thread shortcut、临时 DuckDB 与固定
  `database_path` 场景。
- `analyze_trace()` 现在在所有动态路径（包括 single-thread shortcut）先建立
  CREATING subject binding，导入事件并物化 object 后调用
  `TraceStore.complete_import()`。import completeness 失败时直接返回
  `UNKNOWN`，不再让空窗口、单线程 shortcut 或局部 event 计数产生
  `TRACE_SAFE`。
- binding 的 subject 由 manifest/module fingerprints、trace digest、trace
  marker 和分析配置摘要组成；database path 不进入语义 digest。已有不同
  subject/schema/config 的 store 被拒绝，旧 unbound store 不会被静默复用。
- 没有改变 memory-model checker、SAFE/TRACE_SAFE 定义或 application-only
  规则；新增 pipeline 测试只检查已绑定 store 最终存在 COMPLETE ledger。
- focused pipeline/storage tests：`24 passed`；完整默认 suite：`566 passed,
  10 skipped`；`git diff --check` 通过。
- 剩余风险：`database_path` 的同 trace read-only reuse 尚未实现，当前重复启动
  会保守拒绝；TraceStore import ledger 尚未进入 dynamic certificate/schema，
  也尚未重放 communication/window 输入 universe。下一步应先把 reuse/mixed/
  failed-state 行为定为 typed `UNKNOWN` 或显式 legacy reader，再进入 RU5 的
  communication/window import coverage。

### RU5.4 communication/window coverage ledger 已接入 dynamic pipeline

- 提交：`b24ead0`（`Record dynamic coverage ledgers`）。
- finding：F03、F13、F16；witness：communication scan 的 candidate/scoped
  edge 差异、窗口未归属边和 resource-limit 路径。
- 新增 typed `TraceCoverage`、`CommunicationCoverage`、`WindowCoverage` 与
  `CoverageState`。coverage 绑定 COMPLETE TraceStore 的 `TraceId`、trace
  digest 和 decoded-event count/digest；通信阶段记录 event universe、候选
  边数、scoped 边数/摘要、外部边数；窗口阶段记录输入边全集、已归属边摘要、
  window 数和 event 数。输入/输出 digest 或 count 对不上时 model 直接拒绝。
- dynamic pipeline 在 single-thread、普通多线程和 application scope 都生成
  coverage。旧 `DynamicCertificate` 的 coverage 字段暂为可选，保持历史手工
  certificate 的 legacy reader 行为；本提交没有把 coverage 缺失直接改写成
  新 verdict，也没有改 checker 语义。
- focused coverage/pipeline tests：`19 passed`；完整默认 suite：`568 passed,
  10 skipped`；`git diff --check` 通过。
- 剩余风险：coverage 目前还没有成为 `TRACE_SAFE` certificate 的强制 replay
  条件，`CoverageState` 也尚未由独立 verifier 重算；旧手工证书仍可能只有
  `communication_edges_complete`。下一原子边界应先给 certificate verifier
  增加 coverage closure/legacy downgrade tests，再决定如何对旧 schema 保守
  返回 `UNKNOWN`。

### RU5.5 determinate dynamic certificate coverage gate 已完成

- 提交：`cff890a`（`Reject unbound determinate trace certificates`）。
- finding：F13、F16；witness：旧 schema/手工 `TRACE_SAFE` certificate 没有
  event、communication、window coverage。
- `verify_dynamic_certificate_coverage()` 现在是 dynamic evidence binding 的
  只读 gate：`TRACE_SAFE` 或 `COUNTEREXAMPLE` 缺 coverage、trace digest、event
  count、candidate edge count 任一不匹配，或 communication/window state 不是
  `COMPLETE`，都会被拒绝并标为 legacy explain-only；UNKNOWN certificate 仍可
  读取和诊断。
- `bind_dynamic_certificate_to_trace()` 在构造 `ObservedFact` snapshot 前调用
  该 gate，因此诊断链不能把不可独立验证的确定性证书当作完整 trace evidence。
  没有改变 dynamic pipeline 的 checker、verdict 计算或 static SAFE closure。
- focused binding/coverage tests：`9 passed`；完整默认 suite：`569 passed,
  10 skipped`；`git diff --check` 通过。
- 剩余风险：gate 还没有重算 communication/window ledger 本身，也没有进入
  CLI `explain` 或独立 certificate replay 命令；旧动态 schema 仍可被普通
  Pydantic reader 载入，但不得通过此 determinate binding gate。下一窄步是
  为 coverage ledger 增加从 trace/store 的独立 replay，并覆盖 mutation cases。

### RU5.6 decoded-event inventory 独立 replay 已完成

- 提交：`ba8451a`（`Replay dynamic event inventory`）。
- finding：F13、F16；witness：coverage event digest/count mutation。
- `TraceStore.event_inventory()` 暴露 canonical decoded-event count/digest；
  dynamic binding 使用临时 store 从原始 `events-*.bin` 重新导入后核对
  `TraceCoverage.event_count/event_sha256`，不信任证书提交的字段。重放失败、
  count 不同或 digest 不同都会阻止 determinate evidence binding。
- replay 不调用 memory-model solver，也不生成 ProofFact；它只验证 trace
  event universe，ObservedFact 仍绑定原始 trace identity。旧 UNKNOWN certificate
  不要求 coverage replay，保持 explain/diagnostic 路径可用。
- focused binding/pipeline tests：`25 passed`；完整默认 suite：`570 passed,
  10 skipped`；`git diff --check` 通过。
- 剩余风险：communication edge 和 window partition 的输出尚未在 binding 阶段
  独立重算，当前仍依赖 pipeline 写入的 coverage state；下一原子边界应增加
  小型 trace 的 reference edge/window replay，并覆盖 dropped/filtered/
  resource-limit mutation，不能把 event replay 当作完整 TRACE_SAFE replay。

### RU5.7 coverage 重建逻辑集中化已完成

- 提交：`86d1207`（`Centralize dynamic coverage reconstruction`）。
- finding：F03、F13、F16；witness：coverage 构造逻辑原先只在 pipeline 内部，
  后续独立 replay 若复制这段逻辑会再次形成 route-specific completeness 判断。
- 新增 `bmo_check_dynamic.analysis.coverage` 作为唯一 coverage 构造入口，集中
  `TraceImportLedger` 到 `TraceCoverage` 的绑定、edge/window 摘要和状态判定；
  pipeline 只提供实际扫描结果，不再保留第二份私有实现。该模块没有放宽
  `COMPLETE` 条件，也没有改变 verifier 或 verdict。
- focused coverage/pipeline/binding tests：`27 passed`；完整默认 suite：
  `570 passed, 10 skipped`；`git diff --check` 通过。
- 剩余风险：这一步只消除了 coverage 重建的重复实现，还没有独立重放通信
  edge 和 window partition。下一原子边界必须从原始 trace/store 重建两者，
  对 dropped/filtered/resource-limit 变体保守拒绝；不能把集中化本身当作
  TRACE_SAFE completeness proof。

### RU5.8 communication/window coverage 独立重放已完成

- 提交：`d071449`（`Replay dynamic communication coverage`）。
- finding：F03、F13、F16；witness：producer 可能提交完整的 event ledger，
  但通信边或窗口分区被删改后仍保留 `COMPLETE` 状态。
- `replay_dynamic_coverage()` 从原始 event chunk 建立临时、subject-bound
  TraceStore，独立物化对象 generation，并从 manifest、模块闭包、trace digest
  和传入的同一 `DynamicConfig` 重建 import subject。随后按应用范围重新扫描
  communication edges、重新执行 window partition，并逐字段比较 event、边和
  window coverage；任何 resource limit、模块范围不一致、subject 不一致或
  dropped/filtered 结果不一致都会拒绝 determinate evidence。
- hybrid workflow 把原分析使用的 `DynamicConfig` 传给 binding replay，避免
  用默认预算伪造同一个 subject。`replay_dynamic_event_inventory()` 复用同一
  完整导入边界；没有产生 `ProofFact`，也没有改变 verifier 或 verdict。
- adversarial/focused tests：`14 passed`；完整默认 suite：`571 passed,
  10 skipped`；`git diff --check` 通过。测试覆盖通信 coverage 篡改和
  伪造 trace subject。
- 剩余风险：certificate 仍没有独立暴露 analyzer config digest 字段，当前
  通过 trace subject 间接绑定配置；未来 RU6 应把 immutable config/spec
  digest 作为显式 mandatory field 并纳入独立 replay。下一步可进入 RU5.9，
  覆盖同 trace 的复用、mixed/failed import 状态和多次重放一致性；在此之前
  不恢复任何 application-only fast path。

### RU5.9 dynamic replay config digest 与重复性边界已完成

- 提交：`4bf7295`（`Bind dynamic replay to config digest`）。
- finding：F15、F16；witness：仅由 `TraceId` 无法区分相同 trace bytes 在不同
  analyzer budget/config 下生成的 coverage，旧 coverage 可能被误用于 determinate
  binding。
- `TraceCoverage` 新增可选的 `config_sha256`。当前 pipeline 从完整
  `TraceImportLedger` 写入真实 digest；determinate certificate 缺失该字段时
  立即按 legacy explain-only 拒绝。replay 从传入 `DynamicConfig` 重算 digest
  并核对，不能用默认配置替代原分析配置。
- 同一 certificate 使用同一配置可以重复 replay；配置不匹配、coverage 字段
  缺失或 import 状态不完整都只能失败/UNKNOWN。没有改变 memory-model
  semantics、solver 或任何 SAFE/TRACE_SAFE 判定规则。
- focused coverage/replay tests：`30 passed`；完整默认 suite：`573 passed,
  10 skipped`；`git diff --check` 通过。
- RU5 当前剩余事项：TraceStore 自身的 stale/mixed/duplicate/truncated
  fixtures 已覆盖，但 certificate schema 仍把 config digest 放在 coverage
  中而不是顶层 immutable binding；RU6 需要把 executable/library/argv/
  contract/config/spec digest 统一提升为强制、可独立重放的 certificate 输入。

### RU3.1 应用作用域删除进入 canonical ledger 已完成

- 提交：`5e403dc`（`Record application projection removals`）。
- finding：F02；witness：应用作用域在最终 `SharedMemorySlice` 中删除了
  runtime-internal event，但 `shared_state.removed_event_ids` 没有记录这次后续
  projection，导致旧 bridge 生成的 `StaticCertificate` 缺少对应
  `RemovalDecision`。
- `build_static_certificate_from_report()` 现在同时读取 shared-state 的显式删除
  和 final-slice `ProofObject.event_ids`，去重后逐项解析为 canonical
  `MemoryEventId`，并要求每项都被同 scope 的 `ProofFact` 覆盖。删除事件不会
  因 module hash 自动消失；仍只有 runtime-internal provenance 产生这类
  application projection proof。
- 新增 characterization 覆盖：应用作用域删除 runtime event 时，UNKNOWN
  certificate 也必须携带一条 `RemovalDecision`。测试使用 UNKNOWN 路径是为了
  尊重 C0.4：旧 static-certificate schema 仍不能把该结果验证成 SAFE。
- focused static tests：`23 passed`；完整默认 suite：`574 passed, 10 skipped`；
  `git diff --check` 通过。
- 剩余风险：这一步只修复 removal ledger 的桥接缺口，尚未证明 projection
  保留了所有 source/target obligation，也没有让 static SAFE 重新可 replay。
  RU3.2 必须增加 retained/removed event 与 relation 的完整 universe，以及
  legality-preserving preservation check；证明不了的 projection 仍返回
  `UNKNOWN`，不能由这条 `RemovalDecision` 单独推出 SAFE。

### RU3.2 投影关系账本基础已完成

- 提交：`e36c1ef`（`Add projection relation ledger`）。
- finding：F01/F02 的关系闭包缺口；witness：W1/W2 的 library-mediated
  communication、program-order 和 synchronization 边在投影后不能只靠事件
  数量回推。
- core 新增稳定 `RelationId`，显式区分有向关系和对称关系；新增
  `ProjectionRelationEntry`/`ProjectionLedger`，逐项记录 retained、
  removed-with-proof 和 unresolved 关系，并暴露 missing relation universe。
  removed relation 必须带 `EvidenceId` 和 versioned preservation rule；完整账本
  缺少任一输入关系会拒绝。该账本只是 canonical completeness input，不会把
  entry 自动当作 legality proof，也没有接入 checker 或任何 verdict 入口。
- focused core/identity/obligation/closure tests：`54 passed`；完整默认 suite：
  `580 passed, 10 skipped`；`git diff --check` 通过。
- 剩余风险：static application projection 还没有生成这份关系账本，现有
  `SharedMemorySlice` 仍会过滤边后只保留事件级 proof object。下一原子边界应
  先为 program-order/conflict/synchronization 建立从旧切片到 `RelationId` 的
  characterization 和无损 adapter；relation universe 不完整时只能保留 full
  graph 或返回 `UNKNOWN`，不能仅凭新增类型恢复 SAFE。

### RU3.3 静态切片关系 adapter 已完成

- 提交：`4e6329b`（`Audit static projection relations`）。
- finding：F01/F02；witness：W1/W2 的 PO、conflict 和 synchronization 边在
  application projection 后被过滤，但旧 report 没有 relation identity 或删除
  账本。
- 新增 `build_projection_ledger()`，用 canonical `MemoryEventId` 为三类旧切片
  关系生成有向/对称 `RelationId`，对照 source 与 projected relation universe。
  未改变的关系才登记为 retained；被投影删除的关系保持为
  `missing_relation_ids`，账本状态为 `INCOMPLETE`。adapter 不把 event-level
  `ProofObject` 猜成 relation-level legality proof，也不使用模块名或测试名。
  端点缺少稳定 event identity 时直接拒绝，不能任选一个关系端点。
- focused projection/certificate/scope tests：`22 passed`；完整默认 suite：
  `583 passed, 10 skipped`；`git diff --check` 通过。
- 剩余风险：关系 adapter 目前是只读 characterization sidecar，尚未接入
  `StaticCertificate` replay；因此它不会改变现有 verdict。下一原子边界应为
  removed relation 设计并验证真正的 preservation `ProofFact`/premise，只有
  relation universe、event universe 和 source/target obligation 都闭合时才
  允许 projection 进入确定性证书，否则保留完整图或 `UNKNOWN`。

### RU3.4 bridge 携带 projection coverage 已完成

- 提交：`6f54419`（`Bind static projection coverage`）。
- finding：F01/F02；witness：application-scope static bridge 只携带 event
  removal decision 时，relation projection 的缺失无法被 certificate-side
  consumer 看到。
- `StaticSliceEvidence` 和 `StaticCertificateEvidence` 现在可携带只读
  `ProjectionLedger`。bridge 从原始 `MemoryEventReport`、`SharedStateReport`
  和最终 `SharedMemorySlice` 重建 source/projected relation universe，缺少
  event identity 或关系端点时直接失败；PO/conflict/synchronization 删除仍被
  标为 `INCOMPLETE`，不会被空列表解释成“没有 obligation”。
- focused bridge/projection tests：`11 passed`；完整默认 suite：
  `584 passed, 10 skipped`；`git diff --check` 通过。
- 剩余风险：账本目前仍是 sidecar，`StaticCertificate` replay 尚未检查它，
  因而这一步没有重新开放 SAFE。下一原子边界必须把 relation-level
  preservation proposition 与 ProofFact/premise 绑定，并在 verifier 中拒绝
  incomplete projection；不能用 bridge 携带账本替代 legality-preserving proof。

### RU3.5 relation preservation proof contract 已完成

- 提交：`ad404d5`（`Verify projection preservation proofs`）。
- finding：F01/F02；witness：把 event-level proof、未注册 scope 或 unresolved
  relation 当成 projection legality proof。
- core 新增 `projection_proposition_id()`、`ProjectionVerification` 和
  `verify_projection_ledger()`。删除关系的 proof 必须以同一个 `RelationId`
  为 subject，绑定 ledger 的 scope、同一 `RegisteredProofRule` 和稳定的
  `projection-preserved` proposition；verifier 同时要求 relation universe
  COMPLETE、ProofFact closure 完整，并拒绝 unresolved relation。事件 proof
  不能替代 relation proof，ObservedFact/DiagnosticHint 没有进入入口。
- focused projection/evidence/closure tests：`42 passed`；完整默认 suite：
  `587 passed, 10 skipped`；`git diff --check` 通过。
- 剩余风险：当前 application adapter 还没有生成上述 relation-level
  preservation ProofFact，因此真实 projection 仍是 `INCOMPLETE`，不会被误判
  为 SAFE。下一原子边界应把 preservation rule 的实际 producer 接到
  application boundary，并用 source/target obligation closure 验证它；rule
  未注册或 premise 不足时继续 `UNKNOWN`。

### RU3.6 关系连接的 runtime effect 保守保留已完成

- 提交：`43f745f`（`Retain relation-connected runtime effects`）。
- finding：F01/F02；witness：application scope 原先可以删除带有
  `runtime_internal` 标记、但仍参与 program-order、conflict 或
  synchronization 的事件，随后把被过滤的关系当成不存在。这样会缩小
  relation universe，却只有 event-level boundary proof，不能支持
  legality-preserving projection。
- `restrict_to_application_scope()` 现在只移除没有参与任何现有 PO、conflict
  或 synchronization 关系的 runtime-internal 事件。关系端点保持在完整切片中，
  因而不会通过删除一端来伪造空边或闭合 projection；真正移除的孤立事件仍保留
  `APPLICATION_RUNTIME_BOUNDARY` proof object。该规则不检查 module 名称、库白名单
  或 benchmark 名称，也没有新增 application-only verdict fast path。
- 新增回归覆盖：关系连接的 runtime effect 必须保留；孤立 runtime effect 才能
  进入 event-level removal proof；projection adapter 对手工缺失关系仍返回
  `INCOMPLETE`，不能把旧式过滤升级成 relation proof。
- focused static tests：`38 passed`；完整默认 suite：`588 passed, 10 skipped`；
  `git diff --check` 通过。
- 剩余风险：这只是保守止血，不是 relation-level preservation theorem。连接的
  runtime effect 仍可能让切片保持 `UNKNOWN`；只有后续 producer 能为每条被删除的
  relation 提供注册规则、premise 和 source/target obligation closure 后，才可
  由 `verify_projection_ledger()` 接受 `REMOVED_WITH_PROOF`。下一窄步应继续审计
  projection consumer/replay 是否真正调用该 verifier，不能用本次事件保留重新开放
  SAFE 或 TRACE_SAFE。

### RU3.7 静态证书 bridge 重放 projection 完整性已完成

- 提交：`e83f0b0`（`Replay static projection completeness`）。
- finding：F01/F02；witness：`ProjectionLedger` 已经被 bridge 携带，但此前
  只作为 sidecar 返回，certificate consumer 没有调用独立 verifier；不完整
  relation universe 因而可能在未来确定性 schema 接入时被忽略。
- `build_static_certificate_with_evidence()` 现在对存在的 projection ledger
  调用唯一的 `verify_projection_ledger()`，核对 scope、输入 relation universe、
  retained/removed disposition 和 relation-level proof closure。账本不完整时，
  确定性 verdict 直接拒绝；已经是 `UNKNOWN` 的结果保留不完整账本供诊断，不能
  被改写成 SAFE。没有新增 memory-model rule、application-only fast path 或
  benchmark 分支。
- 新增 bridge adversarial test：确定性 portability result 携带不完整 projection
  ledger 必须失败；现有不完整 projection 的 UNKNOWN 报告仍可构造并暴露缺口。
- focused projection/bridge tests：`34 passed`；完整默认 suite：`589 passed,
  10 skipped`；`git diff --check` 通过。
- 剩余风险：当前 `StaticCertificate` schema 还没有把 projection ledger 和
  source/target obligation inventory 作为可独立序列化字段；本提交只在内存 bridge
  处止住确定性出口。下一步需在不发明 preservation theorem 的前提下，characterize
  projection obligation 与 event universe 的绑定；缺少 relation-level ProofFact、
  premise 或 obligation closure 时继续保留完整图/`UNKNOWN`，再进入 RU6 的可重放
  certificate schema。
