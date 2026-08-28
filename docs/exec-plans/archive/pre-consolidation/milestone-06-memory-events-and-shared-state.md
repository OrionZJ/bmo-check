# Milestone 06 — MemoryEvent IR and Shared-State Classification

## Goal

建立 normalized MemoryEvent 和基础 shared-state classification。

## Deliverables

```text
MemoryEvent
AbstractAddress
basic address reasoning
escape analysis
TLS/ThreadLocal
ReadOnlyShared
SharedUnknown
```

## Default

```text
MayAlias
SharedUnknown
```

## Tests

- TLS
- non-escaping stack
- stack pointer passed to thread
- read-only global after create
- opaque call causes UnknownEscape

## Acceptance

分析失败不能产生 empty shared set。
