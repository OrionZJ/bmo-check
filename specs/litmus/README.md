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

The generated ELF corpus is an external input selected by an explicit corpus-root
option. A manifest record is valid only after the implementation phase has recorded
the corpus revision and final ELF hash.
