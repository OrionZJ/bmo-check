# Active dynamic milestones

动态主线合并为四个 milestone：

1. D0 repository split and contracts — complete
2. D1 complete trace and streaming storage — accepted
3. D2 communication and portability proof — first strict loop accepted
4. D3 campaigns and large-program evaluation — campaign/replay implementation complete;
   large PARSEC/open_posix runs remain opt-in evaluation

The diagnostics workstream is tracked separately after the repository split:

- D1 read-only snapshots — complete
- D2 trace operand identity — complete
- D3 static Unknown / dynamic observation correlation — complete
- D4 versioned diagnostic report and CLI — complete
- D5 generic root-cause registry — complete

Static evidence/provenance foundation:

- Phase C1–C8 — complete on `dev`; the static application service now replays a
  canonical certificate and compares it with the legacy compatibility verdict.
- Native replacement of legacy report producers remains a follow-up migration and
  cannot bypass the canonical ledger.

Affine diagnostic workstream:

- E1 bounded `ObservedAffinePattern` summaries — complete
- E2 canneal validation and static-verdict preservation — complete
- E2.5 real litmus ELF and memory-model correctness baseline — frozen and
  complete. The six-case representative profile, all-2,595 source herd7 sweep,
  real-ELF recovery profile, and static/dynamic characterization are the
  correctness baseline; see `e2-5-litmus-elf-correctness.md`.
- E3-H0–H7 — hybrid workflow implementation and real-workload validation complete.
  H7 produced versioned reports for SB, MP+MFENCE, canneal and blackscholes; all
  static/dynamic verdicts remain `UNKNOWN` for documented recovery, scope or trace
  limits. The 2,595-ELF static measurement and the original thread/lifecycle E3.1 plan
  remain preserved; the E3.1 implementation stays paused pending a priority review
  that combines hybrid diagnostics, canneal and corpus evidence. See
  `e3-hybrid-workflow.md` and `e3-h7-real-workload-validation.md`.
  Policy-parameterized cross-ISA verification (including a possible Box64 case study)
  remains deferred; all current analyses use the DBT6 `mo-off` contract.

Latest WSL2 validation (2026-09-19): the default repository suite passes
`604 passed, 10 skipped, 0 failed`; nine skips require the native-capture environment
and one is the opt-in real-ELF profile. The dynamic binding/replay focused suite passes
`13` cases, the campaign/verify CLI focused suite passes `7`, and the full dynamic
suite passes `188 passed, 9 skipped`. The separately recorded E2.5 herd7 and real-ELF
results remain the frozen baseline. No large PARSEC/open_posix campaign was run as part
of this code-level closure; those runs remain resource-controlled evaluation inputs.

每个阶段都以“不完整证据只能产生 UNKNOWN”为共同验收条件。

## Memory-model solver research: P1–P18

P1–P18 的候选搜索、PPO 压缩、全局约束和固定候选求解记录见
[`symbolic-scaling.md`](symbolic-scaling.md)、P16、P17 和
[`P18 固定候选环报告`](p18-fixed-candidate-global-solving.md)。P18 已完成
固定十个候选的 shadow study；六个 `SAT` 仅代表完整窗口符号模型，不是已验证的
真实执行反例，候选空间也没有穷尽。

下一项近期计划为 [P19：二进制依赖恢复与执行证据闭合](p19-binary-dependence-and-execution-evidence.md)。
当前它仍是 plan-only；不要在本索引更新时将其描述为已实现或已实验。

两条研究路线、Origami/Kling 相关工作状态，以及 Litmus Pattern → Principle →
Diagnostic Rule 的长期提案，统一见 [`docs/research/README.md`](../../research/README.md)。
