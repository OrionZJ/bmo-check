# E2 — canneal validation

Status: implemented on branch `dev`

## Scope

E2 validates the generic affine diagnostic path against the existing canneal static
artifact and a locally captured native trace. The harness/report code is generic: it
does not branch on the benchmark name, function name, observed stride or observed
bound. canneal is only the validation input selected by the experiment manifest.

The report keeps these quantities separate:

- `exercised`: an affine Unknown has an exact stable-ID/location match;
- `ambiguous`: a dynamic candidate exists but the operand identity is not unique;
- `unmatched`: no acceptable match exists, including a binary-closure mismatch;
- `not_executed`: the subset of unmatched records for which no dynamic candidate was
  observed (a closure mismatch is not mislabeled as unexecuted).

The report also carries the original static verdict and `static_proof_unchanged=true`.
It never turns an observed affine pattern into a static discharge.

## Validation input and expected boundary

The historical `canneal-stable-final2` artifact (created before the latest static
provenance/pruning commit) records:

```text
static verdict = UNKNOWN
relevant UnknownAffineBounds = 8
```

The unchanged analyzer was rerun on the current `dev` tree with the same executable
and the system-library closure used by the trace. It still returns `UNKNOWN`, but the
current static snapshot contains 102 relevant Unknowns, including 15
`UnknownAffineBounds`. The older eight-Unknown artifact is retained as a historical
comparison; the difference is recorded as static-baseline drift, not hidden by the
dynamic report.

The small native trace used for the first validation is complete and has zero dropped
events. Its dynamic portability analysis may still return `UNKNOWN` because a
communication page exceeds the configured active-set limit; that is a dynamic
resource result and is independent of the static affine count. The trace uses the
runtime closure captured by WSL, while the historical static artifact is bound to the
`x86lib` closure, so a closure mismatch is reported explicitly rather than guessed
away.

Experiment outputs remain under `.experiments/` and are not source fixtures.

## Acceptance

- the unchanged static artifact remains `UNKNOWN` (the current replay has 15 affine
  Unknowns; the historical comparison has 8);
- the E2 report lists every current affine pattern, including unmatched/not-observed
  cases;
- the report is reproducible from typed snapshots and trace IDs;
- no dynamic observation changes static evidence, verdict or certificate validity.

This phase intentionally does not implement E3 static precision improvements.
