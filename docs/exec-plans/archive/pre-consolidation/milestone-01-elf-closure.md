# Milestone 01 — ELF Closure and Fingerprints

## Goal

准确确定本次分析的 binary closure。

## Backend

`pyelftools`

## Output

`ProgramManifest`：

```text
executable SHA-256
Build ID
interpreter
DT_NEEDED
resolved libraries
library hashes/Build IDs
argv/config
DBT contract version
closure_complete
```

## Soundness Hazards

- 漏库；
- 错 SONAME；
- 用 symbol name 代替实现。

## Tests

- simple ELF
- dependency chain
- missing library
- same SONAME different hash
- manifest fingerprint changes

## Acceptance

缺库必须导致 incomplete manifest，并阻止 SAFE。
