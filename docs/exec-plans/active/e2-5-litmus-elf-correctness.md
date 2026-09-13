# E2.5 — Real litmus ELF correctness baseline

Status: repository implementation complete for the checked-in baseline; the
representative ELF profile and independent herd oracle refresh both run in the
configured WSL environment. The fixed CoWW final-state query remains an explicit
execution-model boundary, not a silently accepted proof.

### Implementation checkpoint (2026-09-13)

The first correctness baseline is now present on `dev`:

- `specs/litmus/e2-5-representative.yaml` pins six real ELF/source pairs by corpus,
  source and ELF SHA-256, binary-bound worker entry/critical PCs, critical program
  order, and fixed `rf/co` assignments. The generated corpus remains external.
- `bmo_check_evaluation.litmus` contains strict fixture types, route-local static and
  dynamic execution-legality facades, a differential comparison classification, an
  evaluation-only critical-event projection, and a contract-aware herd invocation /
  replay report. None of these APIs constructs a SAFE certificate.
- Critical store values and target-specific outcome expressions are explicit in the
  fixture. The target exporter rejects either omission instead of reusing x86
  register names or inventing a store value.
- The target exporter rejects an underspecified `AtomicRMW`; it does not guess an
  `amoadd` for LOCK/XCHG. Atomic execution remains characterized by the route-local
  facades until the fixture carries an operation and value lowering.
- Critical roles can be correlated by recovered callback entry PC. A matched critical
  instruction can therefore be checked even when its abstract object identity is
  still unresolved; the case itself remains `UNKNOWN` until all recovery obligations
  close.
- The opt-in `litmus_elf` profile has passed against the pinned local corpus and
  `x86lib` for SB, MP, LB, 2+2W, CoWW and MP+mfence+po. The profile observed harness
  events and checked critical PC/thread/order alignment plus fixed source/target
  legality without deleting harness events from the production slice.
- WSL `herd7` 7.58 (Rev: exported) has refreshed all six source/target records. The
  source model is the installed X86_64-compatible `x86tso-mixed.cat`; target inputs
  use `riscv.cat`. The generated target files and raw reports stay under
  `.experiments/`; only their reviewed hashes and outcomes are checked in.

The profile currently leaves object-provenance gaps visible for some generated
workers (notably MP and the MFENCE variant). Their lower fixed-execution records are
useful characterization evidence, but they do not change the ordinary static
verdict or prove the full ELF safe. Each case report now also records that unchanged
full-slice static verdict and checker conclusion separately from the projection.
When an oracle record has concrete herd outcomes, the same case report also stores
an evaluation-only comparison for each fixed execution. `Unsupported` oracle data
remain `INCOMPLETE`; an actual legality mismatch is retained as an error and leaves
the case `UNKNOWN` without changing its static verdict.

### Implementation mapping

The repository-local implementation is split into bisectable commits: the typed
fixture and contract binding (`1427b75`, `42ff370`), route-local fixed legality and
static/dynamic differential checks (`fd92848`, `1a671a0`, `5f7350a`), real ELF
conformance and callback recovery (`838ded1`, `bf303c1`, `2579a82`, `ee647ed`,
`302eafb`), and the contract-aware herd/export/replay and expectation gates
(`3e12492`, `34f11c2`, `1a222b7`, `dab4668`, plus the follow-up boundary hardening).
The external oracle step is now recorded with the installed herd version and the
reviewed source/target outcomes. Future contract or corpus changes must regenerate
the target input and refresh these hashes; a missing or unparseable result remains
`Unsupported` rather than reusing the old record.

## 1. Intent

E2.5 sits between the completed dynamic-assisted diagnosis work and E3 static
precision work:

```text
E2     dynamic evidence locates a static precision gap
E2.5   real litmus ELFs validate the checker behavior already in scope
E3     a new static proof capability closes selected Unknowns
```

The phase answers a correctness question that PARSEC cannot answer precisely:

> For a small concurrent program recovered from a real x86-64 ELF, do BMoCheck's
> source and target models classify the same concrete execution relations that an
> independent oracle classifies, after the target has been interpreted through the
> DBT6 `mo-off` contract?

E2.5 does not seek more `SAFE` results. It establishes a regression baseline for
binary recovery and memory-model semantics before E3 changes static precision.

## 2. Non-goals and soundness boundary

E2.5 does not:

- compile `.litmus` files as a new BMoCheck input route;
- construct production `MemoryEvent`s directly from `.litmus` text;
- replace or merge the static and dynamic checkers;
- change the definitions of `SAFE`, `TRACE_SAFE`, `COUNTEREXAMPLE` or `UNKNOWN`;
- use herd output, generated source markers or a corpus manifest as `ProofFact`;
- let a test name, function name, path or source line select proof semantics;
- remove an event from the static slice without a proof-backed removal decision;
- implement E3 loop-bound, PHI-recurrence or canneal-specific precision work;
- validate the DBT6 implementation against the YAML contract;
- reduce `UNKNOWN` merely to make the corpus appear successful.

The normal static certificate remains authoritative. A bounded no-counterexample
result remains `UNKNOWN / BOUNDED_EXHAUSTED`. An E2.5 oracle or conformance report is
test evidence, not certificate evidence.

## 3. Audited local corpus

The sibling `litmus-tests-x86` tree already contains generated programs. Its
`build_all_elf.sh` maps every
`tests/non-mixed-size/<group>/<case>.litmus` to:

```text
elf-tests/<group>/<case>/<case>.c
elf-tests/<group>/<case>/<case>.t
elf-tests/<group>/<case>/<case>.exe
```

The script runs `litmus7 -o` and then the generated Makefile. The current local tree
contains 2,595 `.exe` files in eight top-level groups:

```text
BASIC_2_THREAD
BASIC_3_THREAD
BASIC_3_THREAD_EXTRA
BASIC_4_THREAD
BASIC_4_THREAD_EXTRA
CO
RELAX_2_THREAD
RELAX_3_THREAD
```

Each case directory also contains generated C, a compact `.t` listing, a Makefile,
build/run scripts, and generated utility, output and random-number sources/objects.
The main repository must not copy this full generated tree.

### 3.1 Confirmed generated-program shape

Source inspection of the generated `SB` and `MP+mfence+po` cases establishes the
following facts without executing or disassembling the ELFs:

- the critical operations are inline x86 assembly in worker functions;
- the generated C places `#START _litmus_*` and `#END _litmus_*` assembler markers
  around those operations, and the `.t` file contains their compact assembly;
- each worker calls a full `mfence` helper before and after its main loop;
- each loop iteration uses a generated spin barrier before the critical assembly;
- shared test locations, captured register outputs, barrier state and statistics are
  separate arrays/objects in a context structure;
- result checking, histogram merging, allocation, reinitialization and reporting are
  part of the same executable;
- `zyva` repeatedly creates and joins the critical workers;
- worker functions are stored in a local function-pointer array, may be permuted, and
  are passed through the generated `launch` wrapper;
- `launch`, compiled in a separate utility translation unit, forwards its function
  parameter to `pthread_create`.

The generated build uses `-O2 -pthread` and does not request stripping. Whether every
symbol and marker survives in each final ELF, and the exact optimized call graph, must
be characterized in the implementation phase with `file`, `readelf` and a narrow
`objdump` inspection. Source-level expectations alone do not decide proof scope.

### 3.2 Initial candidate cases

The first batch is deliberately small. Admission requires a completed characterization
record; names below are corpus labels only and have no semantic authority.

| Candidate | Local source and ELF | Intended validation dimension |
|---|---|---|
| SB | `BASIC_2_THREAD/SB/SB.{litmus,exe}` | ordinary Store-to-Load relaxation and no false target-only result |
| MP | `BASIC_2_THREAD/MP/MP.{litmus,exe}` | Store-to-Store and Load-to-Load source order |
| LB | `BASIC_2_THREAD/LB/LB.{litmus,exe}` | Load-to-Store source order and a target-only candidate |
| 2+2W | `BASIC_2_THREAD/2+2W/2+2W.{litmus,exe}` | Store order and cross-location coherence |
| CoWW | `CO/CoWW/CoWW.{litmus,exe}` | same-location coherence and final-state observation |
| MP+mfence+po | `BASIC_2_THREAD/MP+mfence+po/MP+mfence+po.{litmus,exe}` | an explicit MFENCE inside the critical instruction region |

The implementation phase may replace a candidate only by recording why its generated
ELF lies outside the first support intersection. It must not silently choose cases
because they happen to pass.

## 4. Current BMoCheck behavior

### 4.1 Static route

The static application service currently follows:

```text
StaticRequest
  -> ProgramManifest / ELF dependency closure
  -> CFG recovery
  -> pthread/OpenMP thread-role recovery
  -> library synchronization summaries
  -> instruction facts and MemoryEvent extraction
  -> address provenance and shared-state analysis
  -> shared-memory slice
  -> finite portability checker
  -> legacy certificate + canonical proof-closure replay
```

`bmo_check_static.proof.encoding` currently supports a bounded set:

- one finite occurrence per `MemoryEvent`;
- complete, acyclic per-role program order;
- aligned 1/2/4/8-byte accesses;
- exact `Global` alias classes;
- no partially overlapping mixed-size accesses;
- Load, Store, AcqRel atomic RMW, explicit Fence and complete synchronization edges;
- target rf/co enumeration followed by source checking with the same assignment.

Its source PPO preserves ordinary L-L, L-S and S-S and relaxes ordinary S-L. Its
target model adds same-object ordering, recovered dependencies, per-event target
ordering and synchronization. rf, coherence and from-read constraints are represented
with Z3 ranks. A target execution rejected by the source produces a counterexample;
exhausting the finite model produces `BOUNDED_EXHAUSTED`, not `SAFE`.

Static extraction recognizes:

- ordinary operands as Load/Store;
- LOCK-prefixed memory instructions and memory XCHG as `AtomicRMW`;
- LFENCE as `r,r`, SFENCE as `w,w`, and MFENCE as full ordering;
- pthread lifecycle/synchronization calls through recovered call sites and library
  summaries;
- unknown calls/syscalls as explicit events and Unknowns.

### 4.2 Dynamic route

The dynamic checker consumes concrete `TraceEvent`s in communication windows. It has
separate relation code for x86 source PPO and RVWMO target PPO, separate rf/co/fr
enumeration and a symbolic fallback. It additionally handles byte overlap for ordinary
mixed-width accesses and can validate a target-only witness from recorded values and a
closed control skeleton. Unvalidated candidates remain `UNKNOWN`.

The dynamic pipeline loads the complete YAML into the canonical
`bmo_check_core.contracts.MemoryOrderContract`, rejects unsupported fields, and then
runs relation code specialized to the one accepted `dbt6-mo-off-v2` contract.

### 4.3 Shared semantics and duplicated semantics

Already shared:

- the typed DBT contract value object and the supported `dbt6-mo-off-v2` field values;
- repository evidence categories, stable identities and certificate soundness rules;
- the requirement that incomplete inputs fail closed.

Still duplicated:

- static `MemoryEvent` versus dynamic `TraceEvent`;
- event-kind and ordering enums;
- source PPO construction;
- target PPO/Fence/atomic construction;
- rf/co/fr legality and cycle detection;
- target-only execution search and witness representation.

E2.5 characterizes this duplication; it does not merge it.

### 4.4 Confirmed model differences to freeze before fixing

These differences follow directly from the current code and must appear in the first
differential inventory. They are not automatically declared bugs:

1. Static source PPO relaxes every pure S-L pair, while dynamic source PPO restores an
   overlapping same-address S-L edge.
2. Static target PPO adds an edge for every same-object memory pair, while dynamic
   target PPO distinguishes overlapping order before a write and the nearest
   overlapping S-L pair; in particular, same-address L-L is treated differently.
3. Static accepts exact global objects only and rejects partial mixed widths; dynamic
   has byte-range splitting and overlapping write components.
4. Static rf candidates are defined over an exact object and later checked in Z3;
   dynamic excludes same-thread future stores up front and treats internal rf/store
   forwarding specially.
5. Static can consume recovered data/address/control dependency IDs; the dynamic
   certificate currently states that ordinary dependencies are omitted.
6. Static finite exhaustion stays `UNKNOWN`; a complete supported dynamic trace window
   may contribute to `TRACE_SAFE`.

The differential suite compares only the declared common subset. Every excluded
difference must have a typed reason instead of being ignored.

The checked-in route matrix now freezes all three explicit Fence kinds and an
AcqRel two-event atomic boundary. It also exercises the known same-address
Store-to-Load abstraction difference with an explicit route-specific classification;
the test does not hide that difference by forcing the two facades to agree.

### 4.5 DBT contract binding boundary

The canonical contract requires:

```text
plain load/store  -> relaxed
LOCK RMW          -> acq_rel
memory XCHG       -> acq_rel
LFENCE            -> fence r,r
SFENCE            -> fence w,w
MFENCE            -> fence rw,rw
syscall           -> unknown
```

The dynamic route validates all these fields before checking. The general static
application keeps its legacy `load_contract_version` path for existing CLI behavior,
but the E2.5 conformance service first loads `load_canonical_contract`, checks every
field and hash, and refuses to enter recovery on an unsupported or mismatched
contract. This is the deliberate E2.5 binding boundary; it does not silently claim
that every older static entry point has become a parameterized lowering engine.

The accepted first contract remains exactly `dbt6-mo-off-v2`. A future change to make
the ordinary static CLI consume the typed contract must add its own characterization
and certificate-binding commit rather than changing this corpus profile implicitly.

## 5. What existing tests prove, and what is missing

Existing hand-built tests remain useful:

- static tests cover a plain message-passing target-only execution, MFENCE blocking,
  AcqRel atomic publication, bounded exhaustion, Unknown propagation and application
  scope;
- dynamic tests cover MP, SB, LB and IRIW skeletons and fenced variants, all four
  ordinary PPO pairs, same-address order, compact-versus-dense relation reachability,
  atomic coherence adjacency, byte-overlap cases, enumeration/symbolic fallback and
  witness validation.

They start after a `MemoryEvent` or `TraceEvent` has already been constructed. There is
currently no test that jointly establishes:

```text
real ELF
  -> recovered threads and instruction operands
  -> abstract addresses and shared objects
  -> shared slice
  -> checker relations
  -> an independent execution-legality oracle
```

There is also no shared fixture that compares the common static/dynamic semantics and
no public diagnostic API that asks each checker whether one fixed po/rf/co/fr execution
is source-legal and target-legal independently of its final certificate verdict.

The principal missing asset is therefore independent validation and an end-to-end
conformance path, not another collection of manually constructed MP/SB tests.

## 6. Three distinct result layers

E2.5 introduces explicit vocabulary and never maps between these layers implicitly.

### 6.1 Herd outcome legality

For the `exists(...)` predicate in an original `.litmus` case:

```text
HerdOutcomeLegality = Allowed | Forbidden | Unsupported
```

This result is bound to the source litmus digest, herd version and model digest. It is
an external test oracle, never certificate evidence.

### 6.2 BMoCheck execution legality

For one explicit event skeleton and po/rf/co/fr assignment:

```text
ExecutionLegalityResult
  source = Allowed | Forbidden | Unknown
  target = Allowed | Forbidden | Unknown
  model revisions
  DBT contract version and digest
  relation assignment digest
  explanation or unsupported reason
```

The target side means `x86 operation -> canonical DBT lowering -> RVWMO`. It never
means “apply raw RVWMO directly to an x86 event.” This result explains model behavior;
it is not a static or trace certificate.

### 6.3 Final BMoCheck verdict

The existing certificate domains remain unchanged:

```text
static:  SAFE | COUNTEREXAMPLE | UNKNOWN
dynamic: TRACE_SAFE | COUNTEREXAMPLE | UNKNOWN
```

For example, herd may classify an outcome as Forbidden, BMoCheck may agree that one
source execution is illegal, and the full static ELF analysis may still correctly be
`UNKNOWN` because thread recovery, loop occurrence modeling or proof closure is open.

## 7. Proposed software boundary

### 7.1 Evaluation owns the corpus and oracle

The implemented `bmo_check_evaluation.litmus` subsystem owns:

- versioned corpus manifests;
- external-tool invocation used only to refresh oracle records;
- checked-in, small oracle records;
- route-neutral comparison and conformance reports;
- orchestration of normal static application services on selected ELFs.

The dependency direction is:

```text
bmo_check_evaluation.litmus
  -> bmo_check_static public application/characterization APIs
  -> bmo_check_dynamic public characterization APIs
  -> bmo_check_core.contracts
```

Static, dynamic and core code must not import the corpus, herd adapter or case manifest.
The existing repository-boundary test must be extended to enforce this rule.

### 7.2 Route-local characterization APIs

Each checker should expose a small, read-only characterization facade that reuses its
existing implementation:

- source and target preserved-order edges;
- normalized rf/co/fr edges for a fixed assignment;
- source and target legality for that assignment;
- explicit unsupported reasons and model version.

The facade must not construct a final verdict or certificate. E2.5 initially compares
the two facades; it does not create a third memory-model implementation.

### 7.3 Versioned validation fixture

A route-neutral validation fixture belongs to `specs/litmus/`, not to the proof model.
Its proposed fields are:

```text
schema version
case ID (display/evaluation only)
source .litmus digest
generated ELF digest and build provenance
canonical DBT contract digest/version
abstract critical events and per-thread po
one or more explicit rf/co assignments
expected source and target execution legality
external oracle provenance
declared static/dynamic support intersection
```

Adapters translate this fixture into route-local events. A fixture label such as `SB`
may select a test record but may not select relation behavior.

### 7.4 Real-ELF conformance manifest

A separate binary-bound manifest records expected recovery observations:

```text
module SHA-256
instruction PC
memory operand index
event kind and width
thread-role identity expectation
abstract-object expectation
required program-order/Fence relationship
human label and source provenance
```

Only module hash + PC + operand index + structural identities perform correlation.
Function names, source markers and `.t` lines are explanatory metadata. A binary hash
mismatch fails the corpus case instead of guessing a new match.

This manifest validates recovery; it cannot delete events or select the events used by
the production verdict.

## 8. Contract-aware herd oracle

The external oracle has two steps and two independently stored results:

1. run herd on the original x86 litmus and record the legality of the selected
   `exists(...)` outcome;
2. lower the supported abstract operations through the canonical DBT contract, export
   the resulting target test, run the RVWMO herd model, and record target legality.

The contract-aware exporter is evaluation-only. For the first corpus it supports only
plain aligned loads/stores and LFENCE/SFENCE/MFENCE mappings that the canonical
contract understands. Store immediates and the target register outcome are explicit
fixture fields; missing values produce an exporter error rather than a guessed
translation. Unsupported operations produce `Unsupported`, not a guessed lowering.

The parser uses the unique `Positive:` witness count for the `exists(...)` result;
the `Test ... Allowed` line only reports that herd completed the test. A zero
positive count is `Forbidden`, while a missing or duplicated count is `Unsupported`.
Default tests replay small reviewed oracle records and do not require herd. An explicit
refresh command runs herd into a temporary or `.experiments/` directory, records:

- herdtools version;
- source/target model paths and hashes;
- original litmus and DBT contract hashes;
- generated target-oracle input hash;
- command and normalized result;
- raw-output digest.

Refreshing and reviewing an oracle is separate from running BMoCheck. No herd result
may be serialized into `ProofFact`, a removal decision or a certificate premise.

## 9. Real-ELF path and harness pollution

### 9.1 Expected entry through existing services

Every selected ELF enters through `StaticRequest` and the existing `recover`,
`slice_report` and `analyze_with_evidence` services. The evaluation harness may observe
intermediate typed reports, but it must not reconstruct events from generated source.

The expected critical-event path is:

```text
executable segment instruction
  -> Capstone InstructionFact
  -> recovered role-reachable function/block
  -> memory operand or Fence fact
  -> role-bound MemoryEvent
  -> AbstractAddress / shared object
  -> shared-memory slice
  -> existing finite checker
```

### 9.2 First characterization gates

Before changing recovery, the implementation phase must record for each admitted ELF:

1. ELF type, symbols, sections, build ID and dependency closure;
2. CFG functions/blocks and incomplete indirect sites;
3. each recovered pthread call and callback target set;
4. whether the generated `launch` forwarding and function-pointer array are closed;
5. recovered critical instruction sites and operands;
6. role assignments, abstract addresses, shared objects and program order;
7. event counts before/after shared-state pruning and application scope;
8. Unknowns and checker support failures by originating stage;
9. the unmodified final static verdict.

If a fact cannot be established statically, the report says so. Dynamic execution or
generated source labels cannot complete it.

### 9.3 Why current application scope is insufficient

Current static application scope removes:

- events from modules other than the executable; and
- opaque calls whose function-effect contract proves a named runtime-internal object.

Generated litmus barriers, worker loops, result arrays, histogram code and most utility
code are ordinary instructions in the same main ELF. They therefore remain in the
slice. Module identity alone cannot distinguish them from the critical operations.

The generated wrapper also makes thread recovery a likely first gap: the
`pthread_create` callback at the wrapper call is a forwarded function parameter rather
than a block-local constant. The actual optimized binary behavior must be characterized
before deciding whether this gap exists for each fixture.

### 9.4 Generic pollution classification

The conformance report classifies pollution without removing it:

- incomplete thread-entry or callback-target recovery;
- repeated loop/call-context occurrence represented by one static event site;
- address provenance merging test, result, barrier or statistics objects;
- lifecycle initialization/finalization events around worker execution;
- synchronization and Fence boundaries inside the worker path;
- external or opaque helper effects;
- finite-checker event/thread/model limits.

This makes the next change respond to a measured generic gap rather than to a test
name.

### 9.5 Proof-carrying generic solution, if characterization requires it

E2.5 may add one narrowly justified generic capability after characterization. The
preferred order is:

1. reuse existing complete lifecycle edges to separate pre-create initialization and
   post-join observation from concurrent worker behavior;
2. reuse address provenance and shared-object proofs to separate test locations from
   barrier, output and statistics objects;
3. preserve every Fence, atomic and synchronization boundary on a program-order path
   between retained memory events;
4. compute a portability-relevance slice rooted at source-versus-target ordering
   differences and possible rf/co/fr cycle participation;
5. remove an event only when a static graph-separation `ProofFact` shows that it cannot
   participate in a target-only cycle; otherwise retain it and return `UNKNOWN`.

Any new proof-capable scope must be generic and certificate-bound. It cannot consume
the corpus's critical-event manifest. If call-context-insensitive worker recovery is
the first blocker, use a generic interprocedural callback-forwarding or finite
function-pointer-set proof. Do not add special knowledge of `launch`, `P0`, `P1` or a
litmus case name to semantic code.

Generated `#START` markers and `.t` files may validate that the analyzer found expected
sites, but they cannot justify event removal. Until a proof-capable generic slice is
closed, the full ELF result remains `UNKNOWN` even when lower-level legality agrees
with herd.

## 10. Differential baseline for static and dynamic models

The common fixture matrix must cover:

- L-L, L-S, S-S and S-L source PPO;
- overlapping and non-overlapping same-address rules;
- rf from initial state, external write and same-thread forwarding;
- coherence and from-read legality;
- LFENCE, SFENCE and MFENCE directional behavior;
- AcqRel LOCK/XCHG abstract atomic behavior;
- a source-legal execution;
- a source-forbidden but target-allowed execution;
- a target-forbidden execution;
- explicit unsupported cases.

For each case the test records one of:

```text
EQUIVALENT
INTENDED_ROUTE_DIFFERENCE(reason)
UNRESOLVED_MODEL_DRIFT(issue)
UNSUPPORTED_BY_STATIC(reason)
UNSUPPORTED_BY_DYNAMIC(reason)
```

The first commit freezes current behavior. A later commit may correct an externally
validated discrepancy, but it must update the model version and add a focused
regression. A green differential test must never be achieved by weakening both models
to the same wrong rule.

## 11. Test hierarchy

Future E2.5 tests are split by responsibility:

```text
tests/contract/
  corpus/oracle schema and contract-binding validation

tests/invariant/
  herd and corpus observations cannot enter ProofFact/certificate/removal paths

tests/unit/
  fixture normalization and route-local legality facades

tests/differential/
  static versus dynamic common relation/legality matrix

tests/static/integration/
  selected real ELF recovery and critical-site conformance

tests/certificate/
  final static verdict remains governed by normal proof closure
```

The existing hand-built tests stay in place. The new suite adds independent and
end-to-end coverage instead of replacing local unit tests.

The default suite replays small checked-in fixture/oracle metadata. A dedicated
`litmus-elf` profile is required for checker/recovery changes and must fail, not skip,
when its declared corpus root is absent. Ordinary developer runs may omit that profile.

## 12. Artifact policy

Do not commit the 2,595 generated case directories, object files, herd caches, raw
output, build trees or experimental BMoCheck reports.

Version only:

- the schema and small reviewed case manifest;
- hashes and tool/build provenance;
- normalized herd oracle records;
- expected recovery/legality assertions;
- reproduction and refresh commands;
- a decision record explaining corpus ownership and licensing.

The preferred first implementation references the sibling corpus through an explicit
root option or environment setting and verifies every selected ELF hash. The dedicated
CI profile must mount or reproducibly prepare the pinned corpus. Before deciding to
vendor even one ELF, the implementation phase must review the generated-code license,
compiler/runtime binding and whether a byte-identical artifact is necessary. This
decision is made in its own commit, not hidden in a test change.

## 13. Atomic implementation sequence for Luna Max

Each commit below has one purpose. The exact file names may be adjusted after the
preceding characterization, but dependency and soundness boundaries may not change.

### Commit 1 — Document the E2.5 contract and corpus policy

Suggested message:

```text
Plan real litmus ELF correctness validation
```

Changes:

- land this execution plan and a short decision record;
- add the E2.5 roadmap entry;
- document that corpus/herd data are evaluation inputs only.

Validation:

- documentation links resolve;
- no production source, generated ELF or experiment output is staged;
- full existing suite remains unchanged.

### Commit 2 — Add versioned memory-model validation fixtures

Suggested message:

```text
Define memory-model validation fixtures
```

Changes:

- add strict typed manifest/oracle loaders under `bmo_check_evaluation.litmus`;
- add the route-neutral fixture schema and the first abstract relation matrix;
- reject missing versions, duplicate IDs, foreign hashes and unsupported variants.

Failure behavior:

- malformed or unsupported fixture/oracle data fail the test tool explicitly;
- they never produce a BMoCheck verdict.

Validation:

- schema positive/negative tests;
- architecture test proves core/static/dynamic do not import evaluation fixtures;
- existing test suite passes.

### Commit 3 — Bind static analysis to the canonical DBT contract

Suggested message:

```text
Bind static ordering to the canonical DBT contract
```

Changes:

- characterize current hard-coded ordering first;
- parse static YAML through `bmo_check_core.contracts`;
- pass the accepted typed contract to event/checker boundaries or reject the request;
- keep the first supported contract exactly `dbt6-mo-off-v2`.

Failure behavior:

- a same-version YAML with changed load/store, atomic or Fence fields produces an
  explicit invalid/unsupported-contract Unknown;
- it cannot silently run the hard-coded model.

Validation:

- contract field mutation matrix;
- existing extraction semantics remain byte-for-byte equivalent for the accepted
  contract;
- legacy/canonical certificate replay remains equal;
- full existing suite passes.

### Commit 4 — Expose route-local execution-legality characterization

Suggested message:

```text
Expose checker execution-legality diagnostics
```

Changes:

- add typed, read-only characterization facades in static and dynamic proof packages;
- evaluate one fixed po/rf/co/fr assignment under source and target separately;
- report `Allowed`, `Forbidden` or `Unknown`, model version and contract digest;
- reuse the current encoders and relation builders.

Failure behavior:

- unsupported width, object, dependency, atomic or relation assignment returns a typed
  `Unknown`, never `Allowed` by omission;
- no facade constructs `SAFE`, `TRACE_SAFE` or a certificate.

Validation:

- focused source-allowed, source-forbidden, target-allowed and target-forbidden tests;
- existing checker search results remain unchanged;
- architecture/invariant tests forbid use from verdict construction.

### Commit 5 — Freeze static/dynamic common semantics

Suggested message:

```text
Differential-check static and dynamic memory models
```

Changes:

- run both characterization facades on the common fixture matrix;
- record intended differences and unresolved drift explicitly;
- cover PPO, same-address rules, rf/co/fr, all Fence directions, atomics and
  target-only execution.

Failure behavior:

- an unclassified difference fails the differential suite;
- an unsupported route is not coerced into equality.

Validation:

- enumeration and symbolic dynamic paths agree on the shared small cases;
- static fixed-assignment legality agrees with its search result;
- all previous synthetic tests remain.

### Commit 6 — Add the contract-aware herd oracle

Suggested message:

```text
Add contract-aware herd regression oracles
```

Changes:

- add explicit oracle refresh and replay services in evaluation;
- record source herd outcome and contract-lowered RVWMO outcome separately;
- check in only normalized small records with complete provenance.

Failure behavior:

- herd/model/version/hash mismatch invalidates the oracle record;
- unsupported lowering is recorded as `Unsupported`;
- default replay never invokes herd or reaches certificate code.

Validation:

- normalized result parser tests use captured tiny outputs;
- contract mutation invalidates target oracle records;
- an invariant test proves oracle data cannot be a proof premise.

### Commit 7 — Characterize selected real ELF recovery

Suggested message:

```text
Characterize real litmus ELF recovery
```

Changes:

- add the binary-bound conformance manifest and report;
- run selected ELFs through the unmodified static application stages;
- report thread targets, critical events, objects, PO/Fences, harness event classes,
  Unknown origins and final verdict.

Failure behavior:

- absent corpus in the dedicated profile, ELF hash drift, ambiguous correlation or a
  missing expected event fails that profile with an explicit reason;
- the normal analyzer still returns its own conservative verdict.

Validation:

- at least SB, MP, LB, 2+2W, CoWW and MP+mfence+po have reviewed conformance records,
  or a recorded admission failure explains a replacement;
- no source marker or case name is read by semantic code;
- full existing suite and the dedicated profile pass separately.

### Commit 8 — Close the first generic recovery blocker, if required

Suggested message depends on the measured capability, for example:

```text
Recover forwarded pthread callback target sets
```

Changes:

- implement only the highest-impact generic blocker from Commit 7;
- likely candidates are interprocedural callback forwarding, bounded function-pointer
  sets, or call-context occurrence identity;
- create stable proof/Unknown provenance for the capability.

Failure behavior:

- a non-forwarding wrapper, mutated pointer set, incomplete index bound or unresolved
  path remains Unknown;
- no symbol/test-name whitelist is allowed.

Validation:

- synthetic positive, negative and ambiguous cases;
- real ELF characterization demonstrates the newly closed boundary;
- old/new recovery differential report shows no silently removed Unknown.

Do not create this commit if Commit 7 shows the capability is unnecessary.

### Commit 9 — Add proof-carrying portability relevance slicing, if required

Suggested message:

```text
Prove harness events outside portability cycles
```

Changes:

- add only the generic relevance rule justified by measured harness pollution;
- retain/contract required Fence, atomic, synchronization and PO boundaries;
- attach a `ProofFact` and removal decision to every excluded event.

Failure behavior:

- incomplete lifecycle, object aliasing, call context or graph separation retains the
  event and produces `UNKNOWN`;
- the conformance manifest cannot authorize removal.

Validation:

- graph property tests with adversarial paths through Fence/synchronization nodes;
- removal proof-closure and Unknown-conservation tests;
- full-slice versus reduced-slice target-only differential on supported cases;
- selected real ELF pollution decreases only where proofs exist.

Do not create this commit merely to improve a result string. If E2.5 can reach and
validate the checker without proof-capable pruning, record the remaining pollution for
future work.

### Commit 10 — Establish the required correctness profile

Suggested message:

```text
Establish real litmus ELF correctness regressions
```

Changes:

- aggregate external oracle, route differential and real-ELF conformance results;
- document local/CI commands and bounded resource limits;
- add the required gate for future checker/recovery changes.

Failure behavior:

- any model drift, critical-event loss, contract mismatch or unexplained oracle
  disagreement fails the profile;
- conservative end-to-end `UNKNOWN` is accepted only when its expected typed cause is
  asserted and the lower execution-legality check is still testable.

Validation:

- default full suite passes;
- dedicated `litmus-elf` correctness profile passes with the pinned corpus;
- no generated build/trace/cache artifact is staged;
- documentation and expected hashes are current.

### 13.1 Planned command matrix

Exact test file names may follow the repository convention chosen in Commit 2, but
each commit must publish an equivalent narrow command and then run the unchanged full
suite. The intended WSL command shape is:

| Commit | Narrow validation command |
|---|---|
| 2 | `uv run pytest tests/contract/test_litmus_fixture_schema.py tests/invariant/test_litmus_evidence_boundary.py` |
| 3 | `uv run pytest tests/contract/test_dbt_contract.py tests/static/unit/test_instruction_facts.py tests/static/unit/test_portability_verifier.py` |
| 4 | `uv run pytest tests/unit/test_execution_legality_facades.py` |
| 5 | `uv run pytest tests/differential/test_memory_model_routes.py` |
| 6 | `uv run pytest tests/contract/test_herd_oracle_records.py tests/invariant/test_litmus_evidence_boundary.py` |
| 7 | `uv run pytest tests/static/integration/test_litmus_elf_recovery.py --litmus-elf-root <corpus-root>` |
| 8 | targeted positive/negative/ambiguous recovery tests plus the selected ELF profile |
| 9 | removal/cycle property tests plus the selected ELF profile |
| 10 | `uv run pytest` followed by the required `litmus-elf` profile |

The optional oracle refresh is a separate explicit evaluation command. The target
input is intentionally an explicit argument: it must already represent the canonical
DBT lowering. The evaluation-only exporter can produce a small target fixture, but it
still requires target-specific outcome text and will not reuse an x86 register
predicate. For example:

```text
uv run python -m bmo_check_evaluation.litmus.oracle export-target \
  --manifest specs/litmus/e2-5-representative.yaml \
  --case-id SB \
  --dbt-contract specs/static/dbt6-mo-off.yaml \
  --output .experiments/SB.riscv.litmus

uv run python -m bmo_check_evaluation.litmus.oracle refresh \
  --source-input <case>.litmus \
  --target-input <contract-lowered-case>.litmus \
  --source-model x86tso-mixed.cat \
  --target-model riscv.cat \
  --contract-version dbt6-mo-off-v2 \
  --contract-sha256 <contract-sha256> \
  --elf-sha256 <elf-sha256> \
  --herd-version <herdtools7-version> \
  --output .experiments/litmus-oracle-refresh.json
```

The real-ELF characterization is likewise an evaluation command, not a new production
input route. The current implementation exposes it as an opt-in pytest profile:

```text
BMO_CHECK_LITMUS_ROOT=<corpus-root> \
  uv run pytest tests/static/integration/test_litmus_elf_recovery.py \
  --litmus-library-root <library-root> \
  --require-litmus-elf
```

After every commit, `uv run pytest`, `git diff --check`, the dependency tests and the
benchmark-name architecture test must pass before the next commit starts. Oracle
refresh and real-ELF characterization are never folded into the default unit suite.

## 14. Per-case acceptance record

Each admitted real ELF must answer all of the following in one reviewable report:

1. What `exists(...)` outcome does the original case ask about?
2. What source-herd result and provenance are recorded?
3. Which binary-bound PCs/operands are the expected critical operations?
4. Which recovered `MemoryEvent`s match them, and are any matches ambiguous?
5. What thread roles and callback targets were recovered?
6. Which abstract objects represent the intended shared locations?
7. Is per-thread program order complete for the critical sites?
8. Are LFENCE/SFENCE/MFENCE or atomic events classified and lowered correctly?
9. Which recovered events belong to harness/runtime structures, by structural evidence?
10. What explicit po/rf/co/fr execution is queried?
11. Does static source legality agree with dynamic source legality and the external
    source oracle on the common subset?
12. Does contract-lowered target legality agree with the external target oracle?
13. What is the unchanged final static verdict and checker conclusion?
14. If the final result is `UNKNOWN`, which recovery/model/resource obligation remains
    open?

## 15. E2.5 exit criteria

E2.5 is complete only when:

- at least one case from each selected dimension—plain PPO, target-only candidate,
  coherence and MFENCE—passes the independent execution-legality comparison;
- selected real ELFs enter through the normal static application pipeline;
- every expected critical operation is correlated by binary-bound identity or reported
  as an explicit ambiguous/missing recovery failure;
- thread roles, objects, program order and Fence recovery are asserted independently
  of the final verdict;
- static and dynamic common semantics have no unclassified drift;
- the static route is bound field-by-field to the canonical DBT contract;
- herd outcome legality, BMoCheck execution legality and final certificate verdict are
  represented as separate types/reports;
- harness reduction, if implemented, is generic and proof-carrying;
- a bounded or incomplete result remains `UNKNOWN`;
- oracle/corpus observations cannot enter proof closure or remove events;
- the correctness profile is reproducible from documented, versioned inputs without
  committing the full generated corpus.

Only after this baseline is green should E3 change affine, loop, alias or provenance
precision.

## 16. Risks and deferred work

Remaining risks and environment-dependent validation:

- generated wrapper/function-pointer patterns may prevent complete pthread role
  recovery;
- loop and call-context reuse may violate the finite “one occurrence per event” support
  assumption;
- generated mbar/barrier code may connect otherwise separate critical events;
- same-address PPO currently differs between static and dynamic implementations;
- the general legacy static CLI still reads only the contract version; the E2.5
  conformance service itself is field-by-field bound to the canonical contract;
- the evaluation-only target exporter models the supported contract, but actual herd
  source/target outcomes still need a local herd7 installation and reviewed inputs;
- generated-code licensing and compiler/runtime reproducibility may rule out vendoring
  ELFs.

Deferred beyond E2.5:

- a unified `bmo_check_core.portability` engine;
- full mixed-size/declarative RVWMO modeling;
- DBT6 machine-code-to-contract conformance checking;
- automatic litmus compilation;
- E3 PHI/induction/canneal precision improvements;
- broad execution of all 2,595 corpus cases.

## 17. This planning pass

The initial planning pass was produced by reading repository source, existing tests,
generated C, `.t` summaries, corpus scripts and current architecture/specification
documents without executing BMoCheck, herd or the generated ELFs. The subsequent
implementation checkpoint ran the opt-in recovery profile against the pinned local
corpus; facts that still require an external herd binary or fresh corpus build remain
explicitly marked as pending above.
