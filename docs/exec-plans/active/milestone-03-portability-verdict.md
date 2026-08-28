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
