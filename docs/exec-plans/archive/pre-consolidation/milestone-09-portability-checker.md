# Milestone 09 — Source-vs-Target Portability Checker

## Goal

在小型 shared-memory slice 上寻找 target-only execution。

## First Scope

支持：

```text
ordinary Load/Store
atomic AcqRel
explicit fences
fixed alias classes
bounded threads
```

## Models

```text
Source = x86-TSO
Target = RVWMO + DBT6 mo-off
```

## Implementation

先写 decision record 再选：

```text
SMT
herd7
adapted checker
```

## Required Test

message passing：

```text
T0: data=1; flag=1
T1: r1=flag; r2=data
```

必须能暴露 target-only outcome。

## Acceptance

timeout / unsupported -> UNKNOWN。
