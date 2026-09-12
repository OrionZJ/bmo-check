# E2.5 litmus fixture schema

This directory contains reviewed metadata for the real ELF correctness profile. It
does not contain the generated `litmus-tests-x86/elf-tests` tree.

The future manifest uses `schema`, `corpus_name`, `corpus_revision` and `cases`. Every
case binds the original `.litmus` and generated ELF by SHA-256, records its build
recipe, lists binary-bound critical instruction identities and stores explicit
`po/rf/co/fr` assignments. The oracle stores source herd outcome and
contract-lowered target outcome as separate values.

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

An oracle record may include the original `exists` or final-state expression in
`outcome`. This text explains what herd evaluates; it never selects BMoCheck proof
rules. Until herd is refreshed, `source_outcome` and `target_outcome` must remain
`Unsupported` with an explicit not-run provenance rather than guessed results.

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
