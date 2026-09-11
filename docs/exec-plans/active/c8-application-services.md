# C8 — Typed application services

Status: first slice implemented on branch `dev`

## What changed

- `bmo_check_static.application.StaticRequest` owns the parsed static scope and
  orchestrates manifest, recovery, slicing and portability analysis.
- `bmo_check_dynamic.application` owns typed capture and trace-analysis requests;
  the dynamic CLI no longer calls the launcher or pipeline with an ad-hoc namespace.
- Existing CLI output, exit codes and legacy Pydantic certificates remain the
  compatibility surface.

## Boundary

The services receive values, paths and typed configuration. They do not render JSON,
read benchmark names or import the other route. Dynamic observations still do not
enter static proof APIs.

## Remaining C8 work

The static PARSEC evaluation loop still lives in the legacy static CLI because it
contains ablation and worker-process policy that needs its own typed evaluation
request. Move that loop to `bmo_check_evaluation` only after characterization tests
cover isolated workers, resource limits, native runs and report hashes.
