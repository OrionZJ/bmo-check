# C1 — Evidence and verdict characterization

Status: complete on branch `dev`

This checkpoint records the behavior that the canonical evidence model must preserve.
It deliberately adds no production analyzer or certificate behavior. The tests use
small synthetic inputs so they remain bounded and do not depend on PARSEC artifacts.

## Characterized behavior

### Static route

- an empty cross-thread slice with a complete binary scope produces `SAFE`;
- the checker reports `StructuralSafe` and `bounded=false` for that result;
- a visible `UnknownMemoryEffect` in the same scope produces `UNKNOWN`;
- relevant Unknowns remain serialized in `relevant_unknowns`;
- the certificate JSON round-trips through the current Pydantic model.

### Dynamic route

- a complete single-thread trace with one ordinary load produces `TRACE_SAFE`;
- event and thread counts, trace identity and zero communication edges are retained;
- an incomplete trace produces `UNKNOWN` and keeps its completeness reason;
- the dynamic certificate JSON round-trips through the current model.

## Boundary checks

The contract tests currently enforce these existing boundaries:

- static and dynamic routes do not import one another or a future diagnostics package;
- the static model layer does not import analysis backends or route implementations;
- semantic route code contains no PARSEC benchmark-name branch.

The benchmark scan parses Python rather than searching comments, so explanatory
references in comments do not become false architectural failures. Evaluation code is
outside this scan because it owns benchmark selection and aggregation.

## Test entry points

- `tests/invariant/test_current_verdict_baseline.py`
- `tests/contract/test_repository_boundaries.py`

These tests are characterization guards, not proof that the current open-dictionary
models already satisfy the target evidence design. C2 and C3 must add stable identities
and typed evidence without weakening the assertions above.
