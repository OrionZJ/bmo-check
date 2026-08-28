# Milestone 10 — Verdict, Certificate, Explain

## Goal

把 frontend、pruning、checker 结果汇总成最终 verdict。

## SAFE 条件

```text
scope complete
no relevant Unknown
checker complete
no target-only execution
```

## CLI

```text
bmo-check analyze
bmo-check explain
bmo-check fingerprint
```

## Tests

- stale binary invalidates certificate
- missing library blocks SAFE
- unresolved indirect blocks SAFE
- explain shows counterexample PCs

## Acceptance

只有本层能产生最终 SAFE。
