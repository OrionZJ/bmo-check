# BMoCheck

[BMoCheck](https://gitee.com/OrionZJ/bmo-check) 是面向 DBT6 `mo-off` 的二进制内存序验证器。项目现在以动态轨迹验证为主线，同时完整保留原来的静态验证器。

## 结论边界

动态验证器输出：

- `TRACE_SAFE`：对证书绑定的已记录事件骨架，RVWMO 没有引入 x86-TSO 不允许的新执行。
- `COUNTEREXAMPLE`：找到并验证了 target-only 执行。
- `UNKNOWN`：轨迹不完整、事件不支持、资源超限，或候选反例无法验证。

`TRACE_SAFE` 不是程序的无条件 `SAFE`。它不覆盖未执行路径、其他输入、不同地址轨迹或未来运行。工具禁止把“程序跑通”直接解释为安全证明。

Trace 1.1 会记录 syscall 编号、六个原始参数和返回值。多线程轨迹只有在用户
缓冲区 effect 能被严格闭合时才继续证明；其余调用返回 `UNKNOWN`，这表示模型
暂不支持，不表示轨迹文件被截断。

## 动态流程

```text
native x86-64 ELF under DynamoRIO
             ↓
complete per-thread binary trace
             ↓
streaming DuckDB normalization
             ↓
exact cross-thread overlapping accesses
             ↓
synchronization/component windows
             ↓
x86-TSO vs DBT6 mo-off + RVWMO
             ↓
TRACE_SAFE / COUNTEREXAMPLE / UNKNOWN
```

动态分析使用实际执行的地址和间接跳转目标，因此不会因本次轨迹里的间接控制流无法静态恢复而变成 `UNKNOWN`。未执行目标仍然不在证书范围内。

## 使用

先在 Linux 或 WSL2 安装 DynamoRIO，并构建追踪 client：

```bash
cmake -S src/bmo_check_dynamic/native \
      -B src/bmo_check_dynamic/native/build \
      -DDynamoRIO_DIR="$DYNAMORIO_HOME/cmake"
cmake --build src/bmo_check_dynamic/native/build -j
```

采集并分析：

```bash
bmo-check capture --output trace/run-1 -- ./program arg
bmo-check analyze trace/run-1 --output trace/run-1/certificate.json
bmo-check analyze trace/run-1 --output trace/run-1/application-certificate.json \
  --application-only
bmo-check run --trace trace/run-2 --output trace/run-2/certificate.json -- ./program arg
bmo-check explain trace/run-1/certificate.json
bmo-check locate trace/run-1 --module /path/to/module --offset 0x1234
```

大型程序可在 capture/run/campaign 中使用 `--max-thread-events N`
限制轨迹大小。触顶会显式返回 `UNKNOWN`，不会在截断轨迹上继续证明。

`--application-only` 是一个显式的分区作用域：只有在主 ELF 的 worker 输出互不
重叠、且 worker 存活期间主线程没有冲突写入时，工具才会过滤纯外部运行库通信边。
证书保留原始边数量和被过滤数量；运行库的 LOCK/XCHG 与 Fence 仍由 DBT contract
承担。这个选项不能把结果解释成整个 libc 或所有输入的无条件安全。

`locate` 按模块内偏移汇总某条指令的实际事件、线程、宽度和 flags。它用于复核
发布点或原子分类，不参与 verdict，也不能单独证明 `TRACE_SAFE`。

多轮实验使用 `bmo-check campaign manifest.yaml --output results`。总体 `TRACE_SAFE` 只表示清单中的每条轨迹都为 `TRACE_SAFE`。

旧静态分析入口保持为：

```bash
bmo-check-static analyze ...
```

## 开发

```bash
uv sync
uv run pytest
```

开始修改分析器前，先阅读仓库级 [soundness contract](docs/spec/soundness.md) 和
[target architecture](docs/architecture/target-architecture.md)。当前实现的架构缺口记录在
[repository audit](docs/architecture/repository-audit.md)，分阶段迁移顺序记录在
[migration plan](docs/architecture/migration-plan.md)。

动态路线文档位于 `docs/dynamic/`，原静态研究位于 `docs/static/`。
D1/D2 首个严格闭环的逐项证据位于
`docs/exec-plans/active/d1-d2-acceptance.md`。
PARSEC 3.0 全程序实验位于 `docs/dynamic/08-parsec-all-programs.md`。
syscall 参数/effect 的严格闭合规则位于 `docs/dynamic/09-syscall-effects.md`。
