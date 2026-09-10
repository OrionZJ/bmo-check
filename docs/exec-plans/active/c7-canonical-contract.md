# C7 — Canonical DBT memory-order contract

Status: implemented on branch `dev`

## Scope

`bmo_check_core.contracts` now owns the typed interpretation of the DBT memory-order
contract. It separates source/target model identity, ordinary load/store lowering,
LOCK/XCHG lowering, explicit x86 fence lowering and syscall ordering. The dynamic
YAML model remains an input adapter; `to_core_contract(...)` converts it once and
`load_supported_contract(...)` uses the canonical support check.

## Safety boundary

- An unknown wire token is rejected; it cannot silently become `relaxed`.
- The checker accepts only the explicitly supported x86-TSO to RVWMO lowering
  contract. A different lowering returns the same unsupported-contract outcome as
  before, preserving dynamic verdict behavior.
- LOCK/XCHG and LFENCE/SFENCE/MFENCE have separate typed fields. A future adapter
  cannot accidentally classify an atomic boundary as an ordinary access.
- The core contract does not parse YAML and does not import either route.

## Migration gate

The static manifest and the dynamic proof model still expose compatibility fields.
The next contract migration must compare both adapters against this value object
before moving source/target relation encoding into `bmo_check_core.portability`.
