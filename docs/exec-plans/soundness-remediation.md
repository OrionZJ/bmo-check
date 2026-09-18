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

- RU1 的 canonical primitive 尚未实现；static/dynamic semantics 漂移仍可能存在。
- event universe、obligation、proposition identity 尚未贯穿所有 certificate 路径。
- application scope、trace completeness、lifecycle identity 和 certificate replay 仍可能产生 false confidence。
- 完整测试在当前检查点没有本轮通过结论；后续必须按 unit 逐步补齐。

## 当前执行点

下一提交只做 RU1 的 characterization 和 semantic primitive 边界，不修改 memory-model checker 的 verdict 规则，不改变 E2.5 baseline，不运行大规模 PARSEC 或 2595 corpus。该提交完成后再检查 diff、运行 RU1 小型测试并更新本日志。
