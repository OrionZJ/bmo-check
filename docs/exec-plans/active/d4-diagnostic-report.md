# D4 — Diagnostic report and CLI

Status: implemented on branch `dev`

## Scope

`bmo_check_diagnostics` now builds a versioned `DiagnosticReport` from the two
immutable snapshots produced by earlier phases. The report keeps:

- the original static `CertificateVerdict` and a typed identity for both inputs;
- all current blocking static `UnknownFact` obligations, the selected blocker subset,
  proof-discharged historical Unknowns, and every trace-bound `ObservedFact`;
- `Exact`, `Ambiguous` and `Unmatched` correlation records;
- coverage counts, dynamic Unknowns, and a typed `DiagnosticHint` for each selected
  Unknown (using the typed D5 root-cause registry);
- the trace identity/completeness and an explicit static-proof-unchanged statement.

The builder has no API that returns a `ProofFact`, `RemovalDecision`, static lattice
value or discharge. A hint only references existing Unknown/Observed IDs. The report
constructor recomputes coverage and rejects references outside the selected evidence,
so changing a trace cannot alter the static verdict.

## Serialization boundary

`bmo_check_diagnostics.serialization` is the only JSON adapter. It reconstructs
typed identities and evidence nodes before creating a snapshot; an ID/content
mismatch, unknown evidence category, unregistered Unknown kind or cross-category
edge fails closed. Certificate-replayed static snapshots use
`schema_version: static-diagnostic-v2` and carry the unresolved blocker IDs. Legacy
v1 snapshots remain readable, but without a replayed blocker partition the report
conservatively treats every static Unknown as a candidate blocker. Report files use
`schema_version: diagnostic-report-v2` and separately list `blocking_unknowns`,
`selected_unknowns`, and `discharged_unknowns`.

## CLI

```text
bmo-check diagnose STATIC_SNAPSHOT DYNAMIC_SNAPSHOT --output REPORT.json
```

The command also accepts `--static-snapshot`/`--dynamic-snapshot` aliases,
`--static-certificate`/`--trace-certificate` paths for artifact hashes, explicit
certificate IDs, and repeatable `--unknown-id` selection. It returns the unchanged
static verdict (`SAFE=0`, `COUNTEREXAMPLE=1`, `UNKNOWN=2`); malformed input is tool
error `3`. If no certificate path is supplied, the snapshot file is the artifact
whose hash is recorded, and the generated certificate ID is a stable snapshot
identity.

## Deliberate limits

- The D4 report only transports the classification produced by D5; it does not
  infer a new static capability from that classification.
- It does not infer affine bounds, alias/disjointness or lifecycle proofs from a
  runtime address.
- It does not emit a static certificate or upgrade `UNKNOWN`.
- The command accepts a canonical snapshot or a validated dynamic trace through the
  D1 route adapter; it still does not parse legacy analyzer dictionaries.

## Acceptance

- exact, ambiguous and unmatched cases remain visible in JSON;
- a discharged Unknown cannot be selected as a current blocker;
- static Unknowns and dynamic observations remain separate typed categories;
- report construction and CLI round-trip tests pass;
- the full suite retains the static/dynamic import boundary and all prior verdicts.

Commit intent: `Report dynamic-assisted static diagnostics`.
