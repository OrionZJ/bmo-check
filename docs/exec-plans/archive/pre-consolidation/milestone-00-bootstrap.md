# Milestone 00 — Bootstrap and Core Models

## Goal

建立项目骨架、纯数据模型、显式 Unknown、certificate skeleton 和测试框架。

本阶段不分析真实 ELF。

## Deliverables

```text
pyproject.toml
src/bmo_check_static/model/
src/bmo_check_static/certificate/
tests/unit/
CLI skeleton
```

## Required Models

```text
Verdict
UnknownFact
ProgramManifest
ModuleFingerprint
InstructionFact
IndirectTargetSet
ThreadRole
MemoryEvent
AbstractAddress
AnalysisCoverage
CertificateScope
```

## Soundness Requirement

Unknown 必须和 empty/false 明确区分。

## Tests

- verdict serialization
- UnknownFact serialization
- complete/incomplete target set
- certificate round-trip
- coverage serialization

## Acceptance

- model 层不 import angr/capstone/pyelftools；
- tests 全过；
- 任何命令都还不能输出 SAFE。
