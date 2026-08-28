# Milestone 12 — Safe DBT Mode Selection

## Goal

用 certificate 决定 DBT6 mode。

## Policy

```text
matching SAFE certificate
    -> mo-off

anything else
    -> mo-fsm
```

## First Design

优先外部 launcher，不改 DBT6。

## Checks

certificate 必须匹配：

```text
executable hash
library hashes
DBT revision
contract version
config
```

不匹配：

```text
fallback mo-fsm
```

## Future

以后可扩展成自动选择多级 memory-order policy，不只是 off/fsm。
