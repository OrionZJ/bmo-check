# C8 — Typed application services

Status: implemented on branch `dev`

## What changed

- `bmo_check_static.application.StaticRequest` owns the parsed static scope and
  orchestrates manifest, recovery, slicing and portability analysis.
- `bmo_check_dynamic.application` owns typed capture and trace-analysis requests;
  the dynamic CLI no longer calls the launcher or pipeline with an ad-hoc namespace.
- `bmo_check_evaluation.ParsecEvaluationRequest` owns PARSEC suite selection,
  static ablations, native-run policy, report aggregation and isolated workers;
  the static CLI only adapts arguments and renders its report.
- Existing CLI output, exit codes and legacy Pydantic certificates remain the
  compatibility surface.
- The static `analyze` service now returns that compatibility certificate only after
  `analyze_with_evidence` has replayed the canonical static certificate and compared
  the verdicts. A missing DBT revision remains an explicit unbound `UNKNOWN`.

## Boundary

The services receive values, paths and typed configuration. They do not render JSON,
read benchmark names as semantic switches or import the other route. Dynamic
observations still do not enter static proof APIs. Evaluation can depend on static
analysis, but no evaluation module imports a CLI or is imported by core analysis.

The C8 exit condition is now met: isolated workers serialize an explicit request
payload, report hashes remain unchanged, and the legacy static CLI has no PARSEC
analysis policy left to migrate. The legacy evaluation Pydantic models remain under
`bmo_check_static.model` as a deliberate schema adapter; moving those models is a
separate migration and is not required for the Phase C boundary.
