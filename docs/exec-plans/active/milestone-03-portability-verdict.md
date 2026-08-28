# Milestone 03 — Portability Proof, Verdict and Certificate

## Goal

在受支持的 shared-memory slice 上比较 x86-TSO 与 DBT6 mo-off + RVWMO，并生成可解释 verdict 和证书。

## Non-goals

- 不把 bounded no-counterexample 宣称为无条件 SAFE；
- 不支持 mixed-size、misaligned、MMIO 或无限动态事件；
- 不实现 DBT launcher。

## Input

`SharedMemorySlice`、DBT contract、binary scope 和 checker limits。

## Output

```text
SAFE / UNKNOWN / COUNTEREXAMPLE
Certificate
CounterexampleTrace
explain report
```

## Implementation

- 先建立 checker backend decision record。
- 用 Z3 编码首版支持集：普通对齐 Load/Store、固定 alias class、AcqRel 原子、显式 Fence、有限线程和事件。
- Source 使用 x86-TSO；Target 使用 RVWMO 加 DBT6 lowering。
- 结构证明完全闭合且无 relevant Unknown 时才允许 SAFE。
- target-only execution 输出 COUNTEREXAMPLE；timeout、unsupported 和 bounded no-counterexample 输出 UNKNOWN。
- 提供 `analyze` 和 `explain`，证书绑定全部 binary/library/DBT/config 指纹。

## Soundness hazards

- target 模型过强导致漏掉反例；
- source 模型过弱导致伪反例；
- checker timeout 变成 SAFE；
- stale certificate 被复用。

## Tests

- plain Store message publication；
- aq/rl publication；
- explicit Fence；
- missing library、unresolved indirect、profile-only closure；
- timeout、unsupported event 和 stale certificate；
- counterexample PC 与 outcome 解释。

## Acceptance criteria

- plain Store publication可产生 target-only 反例；
- bounded no-counterexample 只能是 UNKNOWN；
- 只有 proof/verifier 层能创建最终 verdict；
- explain 能显示对象、线程、PC、source/target ordering 和证明原因。

## Implemented design

- `proof/encoding.py` 使用 Z3 枚举 target 的 read-from/coherence 关系，并把同一关系交给
  x86-TSO source 模型复核。
- source 保留 L→L、L→S、S→S，放松 S→L；target 使用同地址顺序、已恢复依赖、
  AcqRel 和显式 Fence。
- 首版只接受有限、线性、对齐、exact-Global 事件。mixed-size、未知地址、循环事件图和超界
  输入显式返回 `UNKNOWN`。
- 没有跨线程 conflict 且全部 Unknown 闭合时，proof verifier 可根据 Milestone 2 的 proof
  object 生成结构性 `SAFE`。
- 有 conflict 时，bounded no-counterexample、timeout 和 unsupported 都只能生成 `UNKNOWN`。
- `analyze` 输出绑定 binary/library/DBT/config 的 certificate；`explain` 展示 proof、Unknown
  或反例中的线程、PC、对象、rf 和缺失顺序。

Backend 选择与 soundness 边界见：

```text
docs/decisions/0001-z3-bounded-portability-checker.md
```

## Completion evidence

- 全量测试：46 passed；
- plain Store publication：`COUNTEREXAMPLE`，trace 包含 PC、rf、x86 cycle 和缺失顺序；
- 双侧 full Fence、AcqRel publication：反例被排除，bounded 结果保持 `UNKNOWN`；
- missing/indirect/synchronization/unsupported/timeout/stale certificate：全部阻止 `SAFE`；
- 本地 blackscholes + `x86lib` 端到端：634 memory events、417 shared events、64 proof
  objects，因 380 个 relevant Unknown 输出 `UNKNOWN`，没有进入有限 checker 冒充安全证明。
