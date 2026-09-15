# Active dynamic milestones

动态主线合并为四个 milestone：

1. D0 repository split and contracts — complete
2. D1 complete trace and streaming storage — accepted
3. D2 communication and portability proof — first strict loop accepted
4. D3 campaigns and large-program evaluation

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
- E3 — first complete the static + dynamic + diagnostics workflow. The 2,595-ELF
  static measurement and the original thread/lifecycle E3.1 plan remain preserved;
  E3.1 implementation is paused while the integrated workflow is built. See
  `e3-hybrid-workflow.md` and `e3-corpus-measurement.md`. Policy-parameterized
  cross-ISA verification (including a possible Box64 case study) is deferred
  until this workflow is stable; current experiments remain on the DBT6
  `mo-off` contract.

Latest WSL2 validation (2026-09-15): the default repository suite passes
`386 passed, 10 skipped, 0 failed`; the skips are native-capture requirements and
the opt-in real-ELF profile. E3-H0 focused characterization tests pass `49` cases.
The separately recorded E2.5 herd7 and real-ELF results remain the frozen baseline.

每个阶段都以“不完整证据只能产生 UNKNOWN”为共同验收条件。
