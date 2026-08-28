# BMoCheck

[BMoCheck](https://gitee.com/OrionZJ/bmo-check) 是一个面向真实 x86-64 二进制的 DBT 内存序验证器。

它判断：

> 一个具体程序能不能在 DBT6 的 `mo-off` 模式下运行，而不因为 RVWMO 比 x86-TSO 更弱而产生新的错误行为？

---

## 整体流程

```text
Real x86-64 ELF
      +
Concrete .so closure
      +
DBT6 translation contract
      ↓
Binary / Thread / Library analysis
      ↓
MemoryEvent IR
      ↓
删除或摘要：
  - ThreadLocal
  - ReadOnlyShared
  - DisjointPartition
  - 已被 atomic/fence 覆盖的同步
      ↓
Shared-memory slice
      ↓
PORTHOS-style portability check
      ↓
compare:

x86-TSO
   vs
DBT6 mo-off + RVWMO
      ↓
target-only behavior?
  /        |          \
no      unknown       yes
↓          ↓           ↓
SAFE    UNKNOWN   COUNTEREXAMPLE
↓          ↓           ↓
mo-off     └──────→ mo-fsm
```

---

## 与 CrossMapping-like FSM 的关系

Verifier：

```text
这个程序是否需要 TSO 模拟？
```

FSM：

```text
如果需要，Fence 应该放在哪、用什么类型？
```

所以两者是上下层关系，不是竞争方案。

---

## 研究定位

本项目不声称发明：

- weak-memory portability checking；
- FSM fence placement；
- memory-model robustness。

目标贡献是：

> 把已有 portability checking 思路推进到真实 DBT binary 场景，解决 ELF、真实动态库、间接控制流、pthread 实际实现、DBT lowering、通信剪枝和 shared-memory slicing。

---

## 第一阶段 benchmark

- blackscholes
- swaptions
- dedup
- canneal

详见：

```text
docs/12-validation-plan.md
```

---

## 当前实施状态

当前已实施：

```text
Milestone 00 — Foundation and Binary Facts
Milestone 01 — Program Recovery and Synchronization
```

它们负责恢复 executable、实际动态库闭包、x86 原始指令、CFG、pthread 线程角色和
实际动态库同步摘要。当前仍不生成 MemoryEvent，也不进行 SAFE 判定。

WSL 环境使用独立 Python 3.12：

```bash
cd /path/to/bmo-check
~/.local/bin/uv python install 3.12
~/.local/bin/uv sync --python 3.12 --group dev
```

依赖准备完成后可运行：

```bash
~/.local/bin/uv run pytest
```

恢复本地 binary closure：

```bash
~/.local/bin/uv run bmo-check fingerprint \
  --exe /path/to/x86-program \
  --library-root /mnt/d/CodeProjects/dbt6_workspace/x86lib \
  --dbt-contract specs/dbt6-mo-off.yaml \
  --dbt-root /mnt/d/CodeProjects/dbt6_workspace/dbt6
```

输出中的 `closure_complete` 只表示 binary closure 是否完整，不是最终 SAFE verdict。

恢复 Milestone 1 产物：

```bash
~/.local/bin/uv run bmo-check recover \
  --exe /path/to/x86-program \
  --library-root /mnt/d/CodeProjects/dbt6_workspace/x86lib \
  --dbt-contract specs/dbt6-mo-off.yaml \
  --pthread-spec specs/pthread-api.yaml \
  --dbt-root /mnt/d/CodeProjects/dbt6_workspace/dbt6 \
  --output recovery.json
```

`complete=false` 和报告中的 Unknown 表示控制流、线程或同步事实仍有缺口。它们不能被解释为程序不需要 Fence。

Python 包使用 `bmo_check` namespace，命令行入口统一为 `bmo-check`。
