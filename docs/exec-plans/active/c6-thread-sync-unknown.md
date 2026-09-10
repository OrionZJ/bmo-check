# C6 — Thread lifecycle and synchronization Unknown producers

Status: implemented on branch `dev`

## Scope

This slice adds an opt-in canonical evidence path to the static thread-role and
pthread/OpenMP synchronization producers. The existing
`discover_pthread_threads(...)` and `analyze_pthread_synchronization(...)` calls
still return the same legacy Pydantic reports; current CLI and proof consumers do
not change behavior.

The new `*_with_evidence(...)` wrappers allocate an `EvidenceLedger`, pass it to the
same producer, and return the old report beside the ledger. Unknowns are emitted at
the point where a callback, parent role, join relation, symbol implementation,
instruction decode, or return path cannot be closed.

## Boundary rules

- The sidecars contain only canonical static `UnknownFact` nodes. They never create
  `ObservedFact` or `DiagnosticHint` and do not import the dynamic route.
- The old report remains the compatibility surface. A caller must explicitly opt in
  to obtain the ledger, so this migration cannot silently change an existing verdict.
- Instruction Unknowns returned by Capstone are mirrored into the synchronization
  ledger instead of being discarded when the summary pass consumes that report.
- API names, module paths, PCs and contract versions stay explanation context until
  their typed subject/provenance identities are migrated; they do not become proof
  premises in this slice.
- `LOCK`/`XCHG` evidence remains a synchronization implementation fact. This slice
  does not rewrite or reinterpret atomic lowering.

## Tests and migration gate

`tests/static/unit/test_thread_sync_evidence.py` compares legacy and sidecar reports,
checks canonical CFG, disassembly and missing-symbol kinds, and verifies that every
sidecar node is a static Unknown. Existing pthread/OpenMP recovery and synchronization
integration tests continue to exercise the legacy API.

The next C6 slice is memory-event recovery. It must retain all instruction/event
origins while adding canonical IDs; no slicing or certificate consumer should be
migrated until that coverage is available.
