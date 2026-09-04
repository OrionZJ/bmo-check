# 13 — Codex Development Workflow

## 1. 一次只做一个 Milestone

每次：

1. 阅读 `AGENTS.md`；
2. 阅读当前 milestone；
3. 确认 non-goals；
4. 先补测试；
5. 实现；
6. 运行 acceptance tests；
7. 报告 Known limitations。

---

## 2. 每阶段结束必须报告

```text
Implemented
Files changed
Tests added
Tests run
Acceptance criteria
Known limitations
New UNKNOWN categories
Architecture deviations
```

---

## 3. 不要过早优化

在 correctness / Unknown propagation 稳定前不要先做：

```text
multiprocessing
aggressive caching
graph compression
whole-program symbolic execution
custom solver tricks
```

---

## 4. Decision Record

影响 soundness 的设计选择必须建立：

```text
docs/decisions/YYYY-MM-DD-topic.md
```

写：

```text
problem
options
decision
soundness impact
revisit condition
```

---

## 5. Backend failure

backend crash / timeout：

```text
diagnostic
+
UNKNOWN
```

禁止返回空结果后继续。

---

## 6. Commit 建议

一项逻辑功能一个 commit：

```text
<feat> recover ELF dependency closure
<feat> preserve incomplete indirect target sets
<test> reject safe verdict with missing library
```
