# P19：二进制依赖恢复与执行证据闭合

Status: planned only; implementation and experiments have not started.

## Goal

Determine whether the six P18 full-window symbolic models can be closed into
validated candidate executions by recovering the necessary machine-level data,
address, and control dependencies. The purpose is to establish what the models
mean and what evidence is missing, not to force all six to become
counterexamples.

P18 fixed ten already discovered candidate cycles; it did not exhaust the
candidate space. Its six `SAT` results were independently replayed as
full-window symbolic models but were not bound to a validated concrete
execution. The four `UNSAT` results apply only to their exact frozen candidate
queries. Preserve these distinctions and all P18 input bindings; see the
[P18 report](p18-fixed-candidate-global-solving.md).

## Stage 0 — Freeze and audit the six models without modifying them

Inputs: the six P18 `SAT` model snapshots, ten-candidate report, 3,720-event
window, PPO certificate, trace manifest, and DBT6 `mo-off` contract. Record
hashes and exact artifact paths before deriving any result.

For each model, produce an event-indexed audit table containing:

- event identity, thread instance/role, module+PC, instruction and operand;
- byte range, object/lifetime identity, observed value if present;
- symbolic read value and selected RF writer for each byte/read part;
- whether the source is an ordinary write or initial write;
- RF/FR/CO relation IDs and required versus merely available relation groups;
- address-calculation inputs, data dependencies, flags/branch condition, and
  the executed successor path;
- relevant fences, atomic/RMW operations, synchronization, and DBT lowering;
- trace completeness and the validation state for each fact.

Do not compare a model RF choice to the single RF relation in the observed
trace and immediately reject the candidate. A symbolic model describes a
possible alternative execution. If the changed value flows into an address,
store value, flags, or branch, the corresponding machine semantics and path
must be reevaluated. A mismatch may require extending/reconstructing an
execution; it is not automatically proof that every candidate with that RF
choice is impossible.

Classify discrepancies as `observed-match`, `valid-alternative-needs-replay`,
`semantic-conflict`, or `unresolved`. `semantic-conflict` is permitted only
after the relevant instruction semantics, dataflow, and path obligations have
been checked. Incomplete trace or missing binary facts remain `UNKNOWN`.

**Exit condition:** six independently reproducible model audits with no
unclassified evidence field. This stage does not modify the SMT model or
verdict.

## Stage 1 — Reproduce Kling's dependency examples under the correct models

Read Toon Kling's official [TU Delft thesis record](https://resolver.tudelft.nl/uuid:83916d74-6728-421a-9f30-fb21db597fec)
and obtain the thesis PDF/artifact. Verify §4.3 and the `LB+ctrl`, `LB+datas`,
and conditional-fence LB examples directly. Record source program, generated
IR, optimization/debug configuration, dependency edges, path conditions,
and exact source/target result. The repository record abstract is not enough
to substantiate detailed claims about `-O0`, debug info, or cross-function
limits; record those only after checking the primary text.

For each reproduced case, establish expectations independently for:

1. x86-TSO source legality;
2. DBT6 `mo-off` lowering of the x86 operations;
3. RISC-V ordering and RVWMO target legality;
4. whether the `po;rf`-related candidate satisfies the program dependencies
   and control path.

Do not carry an x86→Arm outcome over to x86→RISC-V. Preserve the exact DBT6
contract digest used by the experiment. Use herd7 or another independent
model oracle for the model-level questions; its result is not a BMoCheck
certificate or a static proof.

**Exit condition:** a reviewed reproduction manifest with explicit outcomes
for both x86-TSO and DBT6 `mo-off` + RVWMO, including unsupported cases.

## Stage 2 — Characterize binary dependency recovery requirements

Before choosing an implementation, map candidate events to x86 instruction
semantics and identify which dependencies are necessary to preserve the
candidate's execution:

- register and flags def-use across instructions;
- load value → store data dependency;
- load value → effective-address dependency;
- load/compare/flags → conditional branch and control dependence;
- call/return, context, and cross-function dataflow;
- aliasing, partial overlap, and memory-value propagation;
- synchronization and atomic boundaries;
- dynamic library and helper behavior.

Build a support matrix for the instructions and control-flow constructs in the
six frozen candidates first. Do not claim general binary dependency recovery
from support for those six cases. Do not create a second memory-model
definition; dependency facts feed the existing source/target model queries.

Where dependency or value recovery is incomplete, the query must remain
diagnostic-only/`UNKNOWN`. Trace-observed facts can bind the analyzed execution
and guide recovery but cannot become static `ProofFact` or close static
Unknowns.

**Exit condition:** a reviewed, typed dependency fact inventory, provenance
design, and explicit unsupported cases before implementation is proposed.

## Stage 3 — Validate alternative executions, not only a fixed model snapshot

Choose the least invasive prototype only after Stages 0–2 establish what must
be checked. It may require replaying instructions, symbolic execution over a
bounded dependence slice, or another justified method; P19 does not preselect
one. The consumer must independently check:

- selected RF/CO/FR consistency and byte-level values;
- instruction data/address semantics;
- flags and branch conditions;
- that each claimed event and control-flow edge belongs to the reconstructed
  candidate execution;
- trace identity/completeness and binary/library/contract binding;
- target legality and source illegality under the bound models.

Distinguish these states in data and reports:

```text
SYMBOLIC_MODEL_VALIDATED
DEPENDENCE_CLOSED_CANDIDATE
TRACE_BOUND_EXECUTION_VALIDATED
COUNTEREXAMPLE
UNKNOWN
```

Do not infer the latter states from a status string or successful graph replay.
Any new evidence field needs an explicit producer, consumer, identity, and
independent validation rule. Timeout, unsupported instruction, missing
dependency, or incomplete trace cannot produce `COUNTEREXAMPLE` or `SAFE`.

## Stage 4 — Bounded validation on frozen candidates

Run the six original candidates only after the small dependency regressions
pass. Do not rerun candidate discovery. For each query report:

- model and execution validation states separately;
- RF changes, dependency/path checks, and any added events/constraints;
- full-window query size, construction and solver time, peak RSS, and exact
  timeout/resource reason;
- independent replay result and failed obligation, if any;
- trace, binary/library closure, candidate, PPO certificate, and DBT contract
  identities.

Do not use an unbounded solver run. Do not interpret timeout as UNSAT. A new
`UNKNOWN` may be the correct outcome if the candidate requires behavior that
the current binary semantics cannot establish.

## P19 acceptance criteria

- Each P18 model has an auditable RF/value/address/dependency/path assessment.
- Kling's requested examples are read from the primary text and independently
  classified under x86-TSO and DBT6 `mo-off` + RVWMO.
- Binary dependency facts have stable identity/provenance and explicit
  unsupported cases.
- An alternate RF assignment is neither accepted blindly nor rejected merely
  because it differs from the observed execution.
- Independent replay distinguishes a full symbolic model from a
  trace-bound execution witness.
- No dynamic observation becomes static proof; no verdict definition or memory
  model contract changes implicitly.
- The P18 candidate set and E2.5 correctness baseline remain bound and
  reproducible.

P19 is not an automatic gateway to the separate [Litmus Pattern → Principle →
Diagnostic Rule route](../../research/pattern-to-diagnostic-roadmap.md). That
route remains a proposal and requires its own literature and soundness review.
