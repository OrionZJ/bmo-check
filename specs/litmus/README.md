# E2.5 litmus fixture schema

This directory contains reviewed metadata for the real ELF correctness profile. It
does not contain the generated `litmus-tests-x86/elf-tests` tree.

The manifest uses `schema`, `corpus_name`, `corpus_revision` and `cases`. Every case
binds the original `.litmus` and generated ELF by SHA-256, records its build recipe,
lists binary-bound critical instruction identities and stores explicit `po/rf/co/fr`
assignments. Plain stores carry their source immediate value so a target exporter
cannot silently replace a `2` with a guessed `1`. The oracle stores source herd
outcome and contract-lowered target outcome as separate values.

Case IDs, source labels and function names are evaluation metadata. They must not
select BMoCheck proof rules, event removal or verdicts. A malformed, stale or
ambiguous record is rejected; it is never treated as `UNKNOWN` or `SAFE` silently.

When a recovered role cannot be identified by manifest order, a critical event may
carry the binary-bound `thread_entry_pc`. The conformance adapter matches that PC
against recovered callback targets; it does not use symbol names or case names to
guess a role. Missing or duplicated entry targets remain an explicit conformance
`UNKNOWN`.

The generated ELF corpus is an external input selected by an explicit corpus-root
option. A manifest record is valid only after the implementation phase has recorded
the corpus revision and final ELF hash.

The first target exporter intentionally rejects an `AtomicRMW` that does not carry
its concrete operation and value. It must not guess `amoadd` for a LOCK/XCHG event;
atomic cases stay in route-local characterization until their lowering is explicit.

An oracle record may include the original `exists` or final-state expression in
`outcome`, and a separately written `target_condition` for the contract-lowered
RISC-V registers. These texts explain what herd evaluates; neither selects BMoCheck
proof rules. The checked-in representative records were refreshed with WSL herd7
7.58 (`x86tso-mixed.cat` and `riscv.cat`); a future refresh must replace the bound
input and raw-output hashes together with the recorded outcomes.

The herd `Test ... Allowed` header is not the selected outcome. The adapter reads the
unique `Positive:` witness count, treating zero as `Forbidden` and missing or
duplicated counts as `Unsupported`.

The current reviewed oracle outcomes are SB `Allowed/Allowed`, MP `Forbidden/Allowed`,
LB `Forbidden/Allowed`, 2+2W `Forbidden/Allowed`, CoWW `Forbidden/Forbidden`, and
MP+mfence+po `Forbidden/Allowed` (source/target order). The CoWW comparison remains
explicitly incomplete because its final-state predicate is not represented by the
relation-only fixed execution; this does not affect the static certificate path.

After installing herdtools7, generate a target input into an ignored experiment
directory with `python -m bmo_check_evaluation.litmus.oracle export-target`; the
command verifies the case's contract version and SHA-256 before writing it. Then use
the separate `refresh` command to run source and target herd models and record their
raw-output digest.

The external profile is opt-in because the generated corpus is kept outside this
repository. From WSL, run the normal static application path with:

```bash
BMO_CHECK_LITMUS_ROOT=/mnt/d/CodeProjects/dbt6_workspace/litmus-tests-x86 \
  uv run pytest tests/static/integration/test_litmus_elf_recovery.py \
  --litmus-library-root /mnt/d/CodeProjects/dbt6_workspace/x86lib \
  --require-litmus-elf
```

This profile checks binary recovery and fixed execution legality. A case with an
unclosed object or lifecycle proof remains `UNKNOWN`; the profile does not turn its
critical-event projection into a static proof.
