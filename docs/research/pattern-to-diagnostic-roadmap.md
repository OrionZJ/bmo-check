# Litmus Pattern → Principle → Static Diagnostic Rule

Status: long-term research proposal; no end-to-end method or result is claimed
yet. This route does not interrupt P19 and does not alter the E2.5 oracle,
DBT6 contract, checker, or current experiments.

## Research objective

Study whether repeated, model-checked litmus counterexamples can be generalized
into precise machine-code diagnostics that find candidate structures in real
x86 ELF programs, then use BMoCheck's dynamic verifier to validate concrete
candidates under a specified workload and translation policy.

The output of this route is initially a ranked set of candidate sites and
explanations. A rule is not a proof that the full executable is unsafe, and a
dynamic run that does not trigger a violation does not prove a rule or program
safe.

## Three levels of result

### Pattern

A concrete event/dependency/relation structure from a named test instance and
memory-model pair, with an independently checked execution outcome. Store:

- exact test source and version;
- source and target model names/versions;
- target lowering contract, if the target is translated code;
- event graph, `po`, `rf`, `co`, `fr`, dependencies, fences, and atomics;
- which outcome is allowed/forbidden by each oracle;
- whether the result is a model-level outcome, a symbolic execution, or a
  physically observed run.

### Principle

A general statement derived from a family of Patterns, with explicit
preconditions, proof/validation argument, known counterexamples, and scope. A
single test outcome is insufficient. Vary at least the relevant dimensions:

- thread count and event placement;
- data, address, and control dependencies, including false dependencies;
- addresses, aliases, byte overlap, and access widths;
- source/target fences, atomic ordering, and synchronization;
- RF source and initial-write alternatives;
- call/function boundaries and intervening operations;
- DBT lowering rule and target memory model.

Use independent model checking or a proof argument for each claimed condition;
do not treat “not seen in N runs” as absence.

### Static Diagnostic Rule

An executable query over binary facts with typed inputs and a documented match
condition. It must state which instructions, dependency facts, memory objects,
thread roles, and ordering facts it requires; what incomplete facts do; and
what exact candidate it emits. The initial consequence is `DiagnosticHint` or
candidate selection only, never `ProofFact`, `SAFE`, or `COUNTEREXAMPLE`.

## Proposed research stages

### R2.0 — Literature and capability map

Complete the [related-work backlog](related-work.md#4-literature-survey-backlog).
For every nearby tool, map input representation, memory models, candidate
search, dependency handling, proof/evidence scope, repair, and scale. Identify
which parts can reuse BMoCheck's static binary recovery, typed evidence, and
dynamic workflow, and which require new algorithms.

Exit condition: a reviewed literature matrix and a written, narrow research
question. No claim of novelty before this gate.

### R2.1 — Litmus pattern corpus

Select tests from actual local corpora and create a versioned manifest rather
than a new name-sensitive checker. For every expected behavior, consult an
independent oracle. For DBT6, evaluate:

```text
x86 program
→ DBT6 mo-off lowering contract
→ RISC-V ordering
→ RVWMO
```

Do not substitute x86→Arm herd results for this target. Preserve E2.5's
distinction between an outcome oracle, execution legality, and BMoCheck's final
verdict.

Exit condition: every corpus row has a reproducible source/target expectation
and an explanation of which part of the binary behavior it represents.

### R2.2 — Pattern extraction and principle validation

Represent violations as typed event/dependency structures. Group structurally
similar instances, propose a Principle, and generate nearby positive/negative
variants. Include tests where adding an existing fence, synchronization edge,
alias, or dependency changes the result. Keep the Principle provisional until
its validity conditions and exceptions are independently checked.

Exit condition: a finite family of variants that either supports a bounded
Principle or shows that the apparent pattern is not general.

### R2.3 — Binary facts needed for matching

Characterize how to recover each rule's required facts from x86 instructions:

- memory instruction and operand identity;
- register/flags dataflow into store values and effective addresses;
- control dependence and branch feasibility;
- call/return and interprocedural context;
- thread-entry/lifecycle role;
- alias/overlap and object provenance;
- existing fences, LOCK/RMW/XCHG, and synchronization implementation;
- relevant loaded-library and DBT lowering facts.

Prefer existing recovery/evidence services. If a fact is not recoverable or
closed, report an unresolved match rather than assuming the relation is absent.

Exit condition: a typed, versioned rule schema and a soundness argument for
every fact the matcher treats as required or absent.

### R2.4 — Candidate-only static diagnostics

Implement a first rule only after R2.0–R2.3 review. Run it on real ELFs and
report Exact/Ambiguous/Unmatched evidence and rule preconditions. Do not let
benchmark/test/function names choose semantics. A missing dependency, alias,
thread, or fence fact must weaken the diagnostic or produce an explicit
unknown.

Exit condition: synthetic positive/negative/adversarial tests show the rule
does not silently ignore cross-thread communication, synchronization, aliases,
or existing ordering.

### R2.5 — Dynamic feedback evaluation

For each emitted candidate, select a concrete workload and run the existing
dynamic verifier with a certificate bound to the binary/library closure,
arguments, environment, trace, and DBT contract. Dynamic results can validate
that one candidate execution occurred or did not occur in that trace; they
cannot upgrade a static verdict or establish a Principle by themselves.

Measure candidate precision, ambiguity/unknown rates, verification cost, and
the trace-bound result distribution. Keep untriggered candidates as
unconfirmed, not disproved.

## False-positive and soundness hazards

Before accepting a diagnostic rule, test that it accounts for:

- communications through libraries, callbacks, and multiple callers;
- source/target order already provided by fences, atomics, or synchronization;
- exact byte-range overlap, mixed widths, and possible aliases;
- data/address/control dependencies and their effect on alternate RF values;
- conditional paths and instructions that disappear or appear under a changed
  read value;
- DBT-specific lowering beyond the nominal target ISA rule;
- incomplete binaries, library closure, and trace import.

Never equate “the rule did not match” or “no violation was observed” with
`SAFE`. The canonical evidence boundary is in [soundness.md](../spec/soundness.md).
