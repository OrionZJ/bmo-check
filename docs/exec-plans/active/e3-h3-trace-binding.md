# E3-H3 — Bind dynamic certificate to trace observations

Status: implementation complete; workflow composition is next

## Dynamic certificate-to-trace binding

`bmo_check_dynamic.adapters.bind_dynamic_certificate_to_trace` takes the dynamic
certificate, its trace directory, and the DBT contract file. It reloads the recorded
manifest and checks that the certificate refers to exactly that one launcher trace,
then recomputes and compares:

- trace digest, including manifest, module map, completion/drop markers and event files;
- executable and loaded-library fingerprints;
- command and working directory;
- DBT contract file SHA-256.

Only after those checks pass does it build the `DynamicDiagnosticSnapshot` from the
same trace. The returned `BoundDynamicEvidence` explicitly keeps both the manifest's
string `trace_id` and the snapshot's content-derived typed `TraceId`. They are
different identity namespaces. The adapter rejects multi-trace certificates in this
single-execution bridge; campaign aggregation remains a separate responsibility.

The bridge preserves `DynamicCertificate.verdict`; the diagnostics adapter does not
reanalyze or promote it. The snapshot may contain its own typed Unknowns if site
normalization is incomplete, even when the dynamic checker has a separately recorded
result. Both facts remain visible to the eventual workflow report.

## Cross-route correlation binding

`bmo_check_core.diagnostics.CorrelationBinding` has one `BindingCheck` for each of:

- `binary_closure`;
- `translation_policy` (currently the canonical DBT6 `mo-off` contract);
- `analysis_scope` (`full` or `application`).

Each check is `match`, `mismatch`, or `unverified`, with a human-readable reason.
`correlate_unknowns` accepts this typed assessment. Any mismatch produces
`Unmatched` records with no observation IDs; missing checks downgrade otherwise exact
site matches to `Ambiguous`; only fully verified binding allows `Exact`. The report
serializes the check set under `correlations.binding`. The checker verdict is copied
unchanged in all cases.

The current snapshot-only `diagnose` path does not possess static/dynamic certificates
and therefore does not fabricate a `CorrelationBinding`. Its `Exact` still means
stable site identity under the snapshot-only API, not workload/policy/scope
compatibility. H4 will compute a binding assessment from the two route results in the
one-workload application service.

## Tests and acceptance

Focused tests cover manifest string ID versus content `TraceId`, certificate/trace
input mismatches, trace modification after certificate generation, policy/scope
mismatch, unverified downgrade, contradictory binary closure claims, and serialized
binding reasons. The focused set passed: `38 passed`. The complete WSL2 suite passed:
`403 passed, 10 skipped, 0 failed`; the skips are native-capture environment checks
and the opt-in real-ELF profile.

No memory-order checker, DBT contract, static certificate verdict, dynamic verdict,
E2.5 oracle, or corpus measurement was changed. Next is H4: a neutral application
service that composes the existing static, dynamic and diagnostics routes.
