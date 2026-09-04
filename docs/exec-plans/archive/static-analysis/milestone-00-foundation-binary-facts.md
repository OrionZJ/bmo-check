# Milestone 00 — Foundation and Binary Facts

```text
Status: COMPLETE
Completed: 2026-08-28
```

## Goal

建立可运行的 Python 项目、显式 Unknown 数据模型、ELF 依赖闭包和 x86 指令事实层。

本阶段只恢复事实，不进行 CFG、线程、共享状态或可移植性证明。

## Non-goals

- 不运行 angr CFG；
- 不识别 pthread thread role；
- 不生成 MemoryEvent；
- 不输出 SAFE 或 COUNTEREXAMPLE；
- 不修改 DBT6。

## Input

```text
x86-64 ELF executable
library search roots
argv/config
specs/dbt6-mo-off.yaml
```

## Output

```text
ProgramManifest
ModuleFingerprint
InstructionFact
UnknownFact
fingerprint CLI JSON
```

## Implementation

1. 建立 `src/bmo_check_static` 内部包、BMoCheck CLI 和 pytest 测试框架。
2. model 层使用纯 Python 数据结构，不依赖 angr、Capstone、pyelftools 或 Z3。
3. 使用 pyelftools 恢复 ELF 架构、interpreter、Build ID、DT_NEEDED、SONAME 和依赖闭包。
4. 每个 executable/library 记录 SHA-256；缺库和解析失败必须进入 manifest 的 Unknown 列表。
5. 使用 Capstone 恢复 PC、raw bytes、内存操作数、Load/Store、LOCK、内存 XCHG、显式 Fence、call/jump/ret/syscall。
6. 提供 `bmo-check fingerprint`，输出稳定、可复查的 JSON。

## Soundness hazards

- 依赖解析漏掉动态库；
- 把相同 SONAME 当成相同实现；
- LOCK/XCHG 属性在反汇编归一化时丢失；
- backend 异常被错误转换为空结果；
- 把不完整 manifest 当成可证明输入。

## Tests

- Verdict、UnknownFact、manifest 和 coverage 序列化；
- 简单 ELF、依赖链、缺库和同 SONAME 不同哈希；
- MOV Load/Store、LOCK CMPXCHG/XADD/DEC、内存/寄存器 XCHG；
- LFENCE/SFENCE/MFENCE；
- direct/indirect call/jump、RET 和 syscall；
- CLI JSON round-trip。

## Acceptance criteria

- [x] model 层没有 backend import；
- [x] 缺库产生 incomplete manifest，并阻止未来 SAFE；
- [x] 指令事实保留 LOCK、memory XCHG 和原始证据；
- [x] 测试全部通过；
- [x] CLI 只能输出事实和 Unknown，不能输出最终 verdict。

## Completion report

Implemented：

- Python 3.12 项目、显式 Unknown 模型和稳定 JSON 序列化；
- executable、interpreter、递归 DT_NEEDED 闭包及指纹；
- 可执行 section 中的 Capstone 指令事实；
- fingerprint CLI。

Validation：

- 20 项测试全部通过，覆盖率 85%；
- blackscholes 与实际 x86lib closure 完整，Unknown 为 0；
- 实际 libpthread 恢复 296 条 LOCK、18 条 memory XCHG；
- 已核对 mutex/spin lock 是 LOCK RMW，spin unlock 是普通 Store；
- fingerprint 输出不包含 SAFE verdict。

Known limitations：

- 本阶段只反汇编带 SHF_EXECINSTR 的 section，不判断指令是否 CFG 可达；
- RPATH/RUNPATH 只记录，不参与 loader 搜索；实际库必须通过有序 library root 提供；
- 不生成 MemoryEvent，也不解释 pthread API；
- CFG、indirect completeness 和 thread role 留给 Milestone 01。
