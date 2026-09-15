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
bmo-check diagnose static-snapshot.json dynamic-snapshot.json \
  --output diagnostic-report.json
bmo-check diagnose static-snapshot.json --trace trace/run-1 \
  --output diagnostic-report.json
bmo-check diagnose static-snapshot.json --trace trace/run-1 \
  --output diagnostic-report.json --affine-output affine-report.json
```

大型程序可在 capture/run/campaign 中使用 `--max-thread-events N`
限制轨迹大小。触顶会显式返回 `UNKNOWN`，不会在截断轨迹上继续证明。

`--application-only` 是一个显式的分区作用域：只有在主 ELF 的 worker 输出互不
重叠、且 worker 存活期间主线程没有冲突写入时，工具才会过滤纯外部运行库通信边。
证书保留原始边数量和被过滤数量；运行库的 LOCK/XCHG 与 Fence 仍由 DBT contract
承担。这个选项不能把结果解释成整个 libc 或所有输入的无条件安全。

`locate` 按模块内偏移汇总某条指令的实际事件、线程、宽度和 flags。它用于复核
发布点或原子分类，不参与 verdict，也不能单独证明 `TRACE_SAFE`。

`diagnose` 读取由 canonical snapshot API 生成的静态 JSON 和动态 JSON，或直接用
`--trace` 流式适配一个已验证的动态轨迹，输出 `diagnostic-report-v1`。报告只
定位静态 Unknown：它保留原始静态 verdict、Exact/Ambiguous/Unmatched 结果、
观察覆盖和 D5 `DiagnosticRootCause`，绝不会把动态事实写入静态 proof 或把
`UNKNOWN` 升级为 `SAFE`。它不解析旧的无类型字典；静态快照请使用
`bmo_check_diagnostics.serialization.save_snapshot` 生成。

`--affine-output` 是 E1/E2 的附加诊断输出：它汇总 `UnknownAffineBounds` 的
动态样本、步长候选和线程覆盖，但仍保留原始静态 verdict；观察到的模式不能
关闭 Unknown 或进入静态证书。若静态 Unknown 带有明确的模块/PC provenance，
命令会只保留这些站点的观察，避免为一次回查展开大型 trace 的全部站点。

## 动静结合工作流 API

E3-H4 提供 `bmo_check_workflow.analyze_workload`，让同一份 workload 依次经过
静态分析、动态采集/分析和只读诊断；E3-H5 的
`build_hybrid_workflow_report` 可把结果整理成 `hybrid-workflow-report-v2`，并由
`save_hybrid_workflow_report` 写成单份 JSON。报告分别保留 static verdict、trace-bound
dynamic verdict、仍未闭合的 static Unknown、D4 `Exact/Ambiguous/Unmatched` 关联、
E1 affine observations 和 D5 root-cause 候选。报告也核对静态/动态 argv 与环境摘要，
记录动态 checker 预算和 trace 目录。D4/E1 子报告仍保留各自 schema。
报告还保留静态分析前后的 DBT contract 摘要，并与动态证书中的 digest 核对。

报告没有合并 verdict：dynamic observation 和 `DiagnosticHint` 不能进入 static
proof closure、消除 Unknown 或把 static `UNKNOWN` 升成 `SAFE`。D5 候选的
`causal_relation_unresolved` 表示当前没有可证明的因果边。报告保留启动命令与工作目录，
环境变量只记录名称和值的摘要；原始环境仍留在 trace manifest，大型 trace 仍留在
独立 trace 目录。

H6 提供普通 workload 的单命令入口：

```bash
bmo-check hybrid --workload workload.yaml --output-dir /mnt/e/bmo-check/run-001
```

清单是 `hybrid-workload-v1` YAML；相对输入路径以清单文件所在目录为基准，
相对 DuckDB 路径以 `--output-dir` 为基准。清单不经 shell 展开，也不会把
程序名用于分析分支。例如：

```yaml
schema_version: hybrid-workload-v1
workload:
  executable: ./app
  argv: [--input, ./case.dat]
  working_directory: .
  environment:
    WORKERS: "4"
static:
  dbt_contract: ./dbt6-mo-off.yaml
  pthread_spec: ./pthread-api.yaml
  function_effects: ./library-effects.yaml
  dbt_revision: 0123456789abcdef0123456789abcdef01234567
  scope: full
dynamic:
  dynamorio_home: /home/user/.local/opt/dynamorio
  client_path: /path/to/libbmo_trace.so
  analysis:
    database_path: dynamic-analysis.duckdb
```

命令先检查输入和输出布局，再独占创建输出目录；已有输出目录不会被覆盖。
成功运行会分别保存 `static-certificate.json`、`dynamic-certificate.json` 和
`hybrid-workflow-report.json`，trace 保存在 `trace/`。退出码 `0` 表示两条路线
和报告生成完成，不代表任一 verdict 为 SAFE；输入、工具或 I/O 错误返回 `3`。
static 和 dynamic verdict 只看各自的证书，workflow 不定义 combined verdict。

多轮实验使用 `bmo-check campaign manifest.yaml --output results`。总体 `TRACE_SAFE` 只表示清单中的每条轨迹都为 `TRACE_SAFE`。

旧静态分析入口保持为：

```bash
bmo-check-static analyze ...
```

静态 `analyze` 仍输出旧版 JSON，便于已有脚本继续使用；在返回这个兼容结果前，
应用服务会把同一次报告转换成 canonical `ProofFact`/`UnknownFact` ledger，检查
每个删除事件的 `RemovalDecision`，并调用静态证书 replay。缺少 DBT revision 或
canonical replay 失败不会被占位值掩盖，结果保持 `UNKNOWN` 或 fail closed。
动态观察和诊断提示始终不能进入静态 `SAFE`。

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
动态诊断快照和静态缺口回查规则位于 `docs/dynamic/11-diagnostic-snapshots.md`。
