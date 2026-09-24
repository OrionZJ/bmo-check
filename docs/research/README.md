# BMoCheck research notes

This directory is the canonical entry point for BMoCheck's research position,
related work, and longer-term research directions. It separates established
implementation/evaluation evidence from proposals that have not yet been
validated.

- [Research positioning and current evidence](positioning.md)
- [Related work and literature-review ledger](related-work.md)
- [Litmus Pattern → Principle → Diagnostic Rule roadmap](pattern-to-diagnostic-roadmap.md)
- [P18 fixed-candidate experiment record](../exec-plans/active/p18-fixed-candidate-global-solving.md)
- [P1–P15 solver-scaling and candidate-search records](../exec-plans/active/symbolic-scaling.md)
- [P16 witness closure](../exec-plans/active/p16-local-witness-closure.md)
- [P17 global-constraint validation](../exec-plans/active/p17-incremental-global-constraints.md)
- [P19 binary-dependence and execution-evidence plan](../exec-plans/active/p19-binary-dependence-and-execution-evidence.md)

## Evidence labels

- **Implemented / measured** means the repository contains an implementation or
  a recorded experiment. The claim applies only to that implementation and
  experiment binding.
- **Source-confirmed** means the statement is supported by a cited primary
  source. It is not a claim that BMoCheck implements the same capability.
- **Proposed** means a research question or future workflow, not a current
  result.
- **Needs verification** means the cited work or artifact must be checked before
  using the statement as a thesis or paper claim.

The repository soundness contract remains authoritative for verdicts and
evidence categories: [soundness specification](../spec/soundness.md).
