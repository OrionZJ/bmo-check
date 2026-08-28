# Milestone 04 — pthread Thread Discovery

## Goal

恢复 pthread thread roles 和 start routines。

## Scope

先支持：

```text
pthread_create
pthread_join
```

## Recover

```text
create site
parent role
child start routine
child argument origin
join relation
```

## Soundness Hazards

callback unresolved / target-set under-approximation。

## Tests

- direct callback
- callback table
- unresolved callback
- multiple create sites
- join relation

## Acceptance

未知 start routine -> `UnknownThreadEntry`。
