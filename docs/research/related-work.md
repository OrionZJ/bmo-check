# Related work and literature-review ledger

## Purpose and status

This is the source-backed starting point for an eventual thesis/paper Related
Work section. It is not yet a complete literature survey and does not establish
that an unstudied capability is novel. Claims marked **Needs verification**
must be checked against the full text, artifact, or primary bibliographic
record before being used as a contribution boundary.

## 1. Sprokholt: Origami and cross-architecture robustness

**Verified bibliographic record.** Dennis Guido Sprokholt, *Correct Translation
between Weak Memory Model Architectures*, PhD dissertation, Delft University of
Technology, 2025, 148 pages, DOI [10.4233/uuid:8dc4a658-85bf-4243-993c-2bb511abe5f1](https://doi.org/10.4233/uuid:8dc4a658-85bf-4243-993c-2bb511abe5f1).
The [TU Delft record](https://research.tudelft.nl/en/publications/correct-translation-between-weak-memory-model-architectures/)
is the institutional citation source. Chapter 6 is titled “Porting Programs
with Dynamic Analysis” and introduces Origami. The dissertation lists the
related paper *Porting Concurrent Programs between Weak Memory Architectures*
by Dennis Sprokholt, Anish Yogesh Kulkarni, Yifan Song, S. Krishna, and Soham
Chakraborty as under submission in the dissertation's paper list; do not invent
a venue or publication status. The thesis also lists Origami's [robustness
analysis](https://github.com/sourcedennis/c11tester-x86-arm) and
[enforcement](https://github.com/sourcedennis/enforce-robustness) repositories.

**What the dissertation supports.** Origami simulates a program step by step
under x86 and Arm weak-memory semantics, explores executions randomly on top of
C11Tester, reports mismatching executions, and proposes program-specific
strengthenings to remove a detected robustness violation. The analysis is
under-approximate: randomized exploration may miss violations. Its repair
algorithm identifies weak program-order paths involved in a violation and
selects a low-cost strengthening. Thus dynamic cross-architecture analysis,
finding unobserved-on-source-model behaviors, and suggesting ordering
strengthening are not by themselves new BMoCheck claims.

The evaluation reports Phoenix trace lengths from 2,486 to 10,524 in Figure 32
of Chapter 6; its caption describes these as trace lengths averaged over 1,000
runs, with smaller 100-run samples for marked expensive programs. Section 6.6
also reports C11Tester/Fency benchmark traces and states that a much larger
analysis took 31 minutes per trace. The experiment used an AWS c7gd.metal with
a 64-core Graviton3 for the reported runtime comparison. These figures are
**not directly comparable** to BMoCheck's 3,720-event communication window or
its 3,690 RF choices: trace construction, event definition, model pair,
algorithm, input, completeness target, and hardware differ. A fair comparison
must characterize communication complexity and solver work, not only event
count.

**Boundary to investigate, not assume.** Chapter 6 describes a C/C++ testing
tool built on C11Tester. The material checked here does not establish whether
Origami accepts arbitrary stripped x86-64 ELF files, recovers arbitrary
binary-level control flow, or analyzes a DBT-specific lowering contract. These
are comparison questions for the full artifact/code review, not evidence of an
algorithmic gap. Conversely, BMoCheck must not imply equivalent execution
coverage or evidence completeness unless it demonstrates it.

Primary sources: [TU Delft dissertation record](https://research.tudelft.nl/en/publications/correct-translation-between-weak-memory-model-architectures/),
[DOI/full dissertation](https://doi.org/10.4233/uuid:8dc4a658-85bf-4243-993c-2bb511abe5f1),
[dissertation PDF](https://dennis.life/pubs/phd_thesis.pdf),
[Origami analysis artifact](https://github.com/sourcedennis/c11tester-x86-arm),
[enforcement artifact](https://github.com/sourcedennis/enforce-robustness).

### “WARDEN” citation status

The research notes supplied “Origami / WARDEN” together. The checked
dissertation record and full dissertation identify Origami, and a full-text
search of that dissertation did not find “WARDEN”. No distinct weak-memory
verification work with this exact name and intended scope has yet been
identified in the sources checked for this document. **Do not cite WARDEN as
an Origami alias or describe it as a verified related system.** Add the exact
title, author, DOI/URL, or artifact when identified; then review it separately.

## 2. Kling: dependence analysis for dynamic translation verification

**Verified bibliographic record.** Toon Kling, *Verifying Memory Model
Translations with Dependence Analysis*, TU Delft Master's thesis, 2026,
graduation date 16 July 2026. The official repository record is
[uuid:83916d74-6728-421a-9f30-fb21db597fec](https://resolver.tudelft.nl/uuid:83916d74-6728-421a-9f30-fb21db597fec)
and lists the file `Thesis_toon_final.pdf`.

**Verified from the official abstract.** The work extends dynamic x86-to-Arm
translation verification with dependence analysis on source code. The abstract
says dependence information can prevent false-positive robustness violations
and enable construction of alternative executions involving `po;rf` cycles
that earlier techniques could not find. This establishes important overlap:
program dependencies matter when considering alternate reads-from choices;
neither “change RF and call it a counterexample” nor “reject every RF change
that influences later operations” is sound without evaluating the resulting
dependencies and execution.

**Full-text checks required before making detailed claims.** This planning
round did not obtain a readable copy of the thesis PDF through the repository
viewer. Therefore these supplied review points are recorded as verification
tasks, not as independently checked facts:

- inspect §4.3 and the `LB+ctrl`, `LB+datas`, and conditional-fence LB examples;
- verify the exact reliance on source plus matching LLVM IR, `-O0`, and debug
  information;
- verify the stated cross-function dependency limitation and its exact scope;
- record each experiment's source/target memory model and expected outcome.

Do not state these implementation/evaluation details as established facts in a
thesis introduction until checked against the PDF and, where relevant, the
artifact. Any reproduction for BMoCheck must independently evaluate x86-TSO
and the DBT6 `mo-off` lowering followed by RVWMO. An x86-to-Arm result cannot be
copied as an x86-to-RISC-V result.

Primary source: [TU Delft repository record and abstract](https://resolver.tudelft.nl/uuid:83916d74-6728-421a-9f30-fb21db597fec).

## 3. Overlap boundary for BMoCheck

Do not present any of the following alone as a BMoCheck first:

- dynamically identifying cross-architecture weak-memory violations;
- changing RF or constructing alternate executions to explore behavior not
  observed in an original run;
- using source and target memory-model differences to find a violating cycle;
- using data/address/control dependencies to rule out infeasible candidates;
- recommending stronger ordering, fences, or program repairs based on a
  violation.

The open comparison is whether BMoCheck can make a sound, useful contribution
for **binary-only x86 programs under a concrete DBT lowering policy**, while
handling communication-heavy windows and explicitly closing evidence from
candidate model to executable behavior. This is a hypothesis to validate, not
yet a proven novelty claim. The comparison must distinguish front-end inputs
and guarantees from the core memory-model algorithm.

| Comparison dimension | What the survey must establish |
|---|---|
| Input representation | Source/C program, LLVM IR, binary, dynamic instruction trace, or a combination |
| Dependence information | Source-derived, IR-derived, binary-recovered, trace-observed, or absent; soundness and path scope |
| Memory-model pair | x86→Arm, x86→RISC-V, or a translator-specific intermediate/lowering model |
| Translation semantics | Generic target ISA mapping versus concrete DBT instruction/fence/atomic contract |
| Candidate generation | Exhaustive/model-checked, bounded, randomized, trace-guided, or heuristic |
| Evidence | Candidate consistency, replayable model, actual-execution witness, or universal proof |
| Scale | Event counts plus RF domains, communication density, per-window size, runtime, memory, and hardware |
| Repair/diagnosis | Fence/access strengthening, witness explanation, static rule generation, or no remediation |

## 4. Literature survey backlog

The following are survey themes, not novelty assertions. Record the exact
queries/databases, inclusion criteria, primary sources, tool artifacts,
supported input, memory models, guarantees, and limitations in a future
survey appendix.

1. Litmus-guided verification and systematic weak-memory test generation.
2. Generalization of weak-memory counterexamples and extraction of recurring
   violation structures.
3. Automatic fence insertion, ordering inference, and program repair.
4. Static robustness/portability checking under weak memory.
5. Program-level dependence recovery and binary-level concurrent analysis.
6. Methods that turn dynamic evidence into static diagnostics or reusable
   rules, including their soundness and transfer assumptions.
7. Related robustness checkers, including the Fency/PORTHOS families already
   referenced by the older static research notes; identify precise versions,
   input languages, semantics, and primary citations before making comparison
   claims.

Use this review to decide what is already covered, what remains open, and what
concrete evaluation would support a narrower contribution claim. Do not frame
Route 2 as “unexplored” until this survey is complete.
