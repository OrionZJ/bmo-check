# E3-H2 — Expose unresolved static obligations

Status: complete; diagnostic snapshot/report schema update

## Change

`static_snapshot_from_certificate` now emits `static-diagnostic-v2`. It replays the
canonical static certificate and derives the current blocker IDs from:

```text
certificate.relevant_unknowns - verification.discharged_unknowns
```

The adapter checks that this set exactly matches the static evidence ledger's
unresolved Unknowns. It also refuses to export a discharge as historical evidence if
its ProofFact is outside the certificate's replayed proof closure. These checks only
gate snapshot export; they do not change the static analyzer or certificate verdict.

The snapshot keeps all static evidence and adds typed `blocking_unknown_ids`. A v2
snapshot must carry this set, and its IDs must exactly match the unresolved Unknowns
in its evidence. Existing `static-diagnostic-v1` files remain readable, but they
have no replayed partition; diagnostics conservatively treat all their Unknowns as
candidate blockers.

`diagnostic-report-v2` exposes three distinct views:

- `blocking_unknowns`: all unresolved static obligations;
- `selected_unknowns`: the blocker subset correlated in this report;
- `discharged_unknowns`: static Unknowns retained for audit after an evidence
  discharge.

The default selection is every blocker. A caller may select a subset of blockers,
but cannot select a discharged Unknown for active diagnosis. The report includes
separate blocker/discharge counts. Dynamic observations and hints remain outside the
static proof closure, and `static_verdict` is copied unchanged.

## Tests and acceptance

Contract coverage checks an UNKNOWN snapshot with one open and one discharged
Unknown, SAFE certificate conversion with proof-backed discharge, v2 snapshot
round-trip, rejection of an incomplete blocker set, and conservative handling of a
legacy v1 snapshot. Focused tests passed: `26 passed`. The full WSL2 suite passed:
`392 passed, 10 skipped, 0 failed`; skips remain native-capture environment checks
and the opt-in real-ELF profile.

No static analysis, portability checker, DBT contract, E2.5 oracle, corpus baseline,
or verdict rule changed. Next is E3-H3: bind a dynamic certificate to its exact trace
snapshot and execution artifacts.
