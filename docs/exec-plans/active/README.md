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
- E2.5 real litmus ELF and memory-model correctness baseline — repository
  implementation complete; representative profile, route differential baseline and
  WSL herd7 7.58 source/target oracle records are present;
  see `e2-5-litmus-elf-correctness.md`
- E3 generic static precision improvement — not started

Latest WSL2 validation after the Phase C closure (2026-09-12): DynamoRIO native
capture tests `10 passed`; full suite `316 passed, 0 skipped, 0 failed` with
`DYNAMORIO_HOME=/home/hezhj/.local/opt/dynamorio` exported for the test process.

每个阶段都以“不完整证据只能产生 UNKNOWN”为共同验收条件。
