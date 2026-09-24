# BMoCheck research positioning

## Overall question

BMoCheck studies whether a concrete x86-64 program, under a specified binary
translation policy, can exhibit a memory behavior that its source memory model
forbids. The current experimental policy is DBT6 `mo-off`; its target side is
the DBT6 lowering contract followed by RVWMO. The current work must not be
described as a policy-independent verifier.

The research now has two connected routes. They share litmus tests, binary
analysis, memory-model semantics, and the dynamic verifier, but their evidence
and claims are different.

## Route 1: dynamic verification of real binaries

**Question.** Given a real x86 ELF, its loaded library closure, workload, and a
specific translation contract, can BMoCheck find and validate an execution
allowed by the translated target but forbidden by x86-TSO?

The route is aimed at binaries where source may be unavailable. It must recover
enough executed machine-level behavior to connect dynamic events, memory
locations, control flow, and reads-from choices, then compare the source and
target models under the selected lowering contract. The central open issues are
execution-evidence closure and scalable handling of highly connected
communication windows.

P1–P18 provide the current algorithmic and experimental foundation. The
solver/candidate-search work is diagnostic or shadow-only unless a document
explicitly says otherwise. P18's six SAT results are complete-window symbolic
models with independent replay, **not validated execution counterexamples**:
trace completeness, control-flow closure, read-value validation, and binding to
an observed execution remain open. The next planned unit is [P19](../exec-plans/active/p19-binary-dependence-and-execution-evidence.md).

The route's conclusion is always bound to its concrete evidence. A result for
`application + loaded libraries + workload + DBT6 contract` is not a universal
claim about the executable, a library, or all inputs. A fixed set of candidate
cycles is not proof that the candidate space has been exhausted.

## Route 2: dynamic-discovery-driven static diagnostics

**Question.** Can validated litmus experiments reveal recurring binary-level
structures that can be turned into conservative static diagnostic rules, so
that the existing dynamic verifier can inspect concrete candidates in real
ELFs?

This is a **proposed research route**, not an existing end-to-end capability.
The repository currently has a static analyzer, dynamic trace verifier,
diagnostic snapshots/correlation, and hybrid workflow, but it does not yet have
a validated method that transforms dynamic violations into general static
diagnostic rules.

The intended conceptual chain is:

```text
Pattern
    → validated Principle with explicit conditions and exceptions
    → Diagnostic Rule with binary-level matching conditions
    → candidate locations in real ELF
    → dynamic validation of a concrete candidate/workload
```

The terms are deliberately distinct:

- **Pattern**: one concrete violation structure observed in a specific test,
  model pair, and execution.
- **Principle**: a proposed general rule, supported by multiple controlled
  variants and a stated domain of validity, including counterexamples and
  exceptions.
- **Diagnostic Rule**: an executable static query with explicit instruction,
  dependency, communication, aliasing, and ordering preconditions. Its output
  is a candidate or `DiagnosticHint`, not a proof or verdict.

A single litmus result does not establish a Principle. Failure to observe a
violation does not establish that one is impossible. A Diagnostic Rule must
account for cross-thread communication, aliases/overlaps, existing fences,
atomics, synchronization, and the actual translation contract; otherwise it
could generate many irrelevant candidates or miss the relevant behavior.

The detailed staged proposal and survey questions are in the [Pattern →
Principle → Diagnostic Rule roadmap](pattern-to-diagnostic-roadmap.md).

## Relationship between the routes

```text
Route 1: binary + workload → dynamic model checking → trace-bound evidence
                                      ↑
Route 2: litmus evidence → static candidate rule ─┘
```

Route 2 may prioritize where Route 1 spends effort. It cannot promote an
observation into `ProofFact`, close a static `UnknownFact`, or change either
route's verdict. Static `SAFE`, dynamic `TRACE_SAFE`, and a replayed symbolic
candidate are different claims with different scopes; see the
[soundness contract](../spec/soundness.md).

## Recorded results and their scope

These are representative measurements, not general performance claims. Each
number must travel with its input/window, configuration, baseline, and
limitations in the linked report.

| Result | What was measured | Scope and limitation | Record |
|---|---|---|---|
| PPO relation representation: 114,478 → 11,089 edges | Full versus certified reachability-summary PPO on the frozen large SB window | Diagnostic/shadow encoding only; certificate-backed relation reduction, not a change to formal verdicts | [symbolic scaling, P8–P9](../exec-plans/active/symbolic-scaling.md) |
| Candidate-search memory: about 5.8 GiB → about 460 MiB | P14 structured search versus P15 bounded-memory search at a 1,000-state budget on the frozen 3,720-event SB trace | Search prefix was truncated; P15 found 4 canonical candidates versus P14's 53, so this is a memory-control result, not equivalent coverage or a complete search | [symbolic scaling, P14–P15](../exec-plans/active/symbolic-scaling.md) |
| Fixed-cycle solving: 233.251 s → 12.007 s total | Ten fixed candidate queries, P17 independent full queries versus P18 fixed-cycle queries | Same frozen ten candidates; 6 `SAT` models independently replayed at full-window symbolic level, 4 `UNSAT`; no actual execution counterexample and no candidate-space completeness | [P18 report](../exec-plans/active/p18-fixed-candidate-global-solving.md) |

P18's six models still lack validated trace completeness, control-flow
closure, read-value execution validation, and observed-execution binding. Do
not write “six real bugs found” or “program is unsafe” from these results.
Similarly, the four `UNSAT` results only close those exact fixed-candidate
queries; they do not prove the program safe.

## Claim discipline

Do not claim BMoCheck first introduced dynamic cross-architecture weak-memory
checking, RF changes to explore unobserved behaviors, source/target model
differential analysis, dependency-based candidate filtering, or suggestions for
strengthening order. These topics have prior work; see the [related-work
ledger](related-work.md).

The potential contribution must be established by comparison on relevant axes,
not by broad slogans such as “binary support” or “large traces”. In particular,
compare communication complexity, RF domain size, event density and window
shape, evidence completeness, memory-model pair, semantics of the translation
policy, and hardware/solver configuration. Event totals alone are not a fair
scalability comparison.
