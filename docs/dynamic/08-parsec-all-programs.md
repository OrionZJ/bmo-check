# PARSEC 3.0 全程序动态验证

验证日期：2026-09-06。使用本地 PARSEC 3.0 x86-64 ELF、DynamoRIO
client 0.3 和 DBT6 `mo-off` contract。本轮发现的采集预算缺口已在后续
client 0.4 中补齐。除 facesim 使用 simsmall 外，其他
程序使用官方 test 输入；线程数为 2。swaptions 的 test 默认
`-ns 1` 不允许两个线程，因此仅将它调整为 `-ns 2`。

`TRACE_SAFE` 不能从“程序跑通”推导。下表只记录当次轨迹证书：

| 程序 | 事件 | 线程 | 采集 | verdict | 直接原因 |
|---|---:|---:|---|---|---|
| blackscholes | 234,060 | 3 | 完整、零丢失 | UNKNOWN | 60 个 opaque syscall |
| swaptions | 1,110,328 | 3 | 完整、零丢失 | UNKNOWN | 78 个 opaque syscall |
| ferret | 10,512,638 | 11 | 达到每线程事件预算 | UNKNOWN | 3 个 resource-limit drop；177 个 syscall |
| facesim | 3,000,461 | 2 | 240 秒未正常退出 | UNKNOWN | 轨迹未完成；77 个 syscall |
| freqmine | 8,901,346 | 2 | WSL ext4 上完整、零丢失 | UNKNOWN | 83 个 opaque syscall |
| fluidanimate | 111,781,139 | 3 | 完整、零丢失 | UNKNOWN | 160 个 opaque syscall |
| streamcluster | 1,999,131 | 5 | 单独重跑后完整、零丢失 | UNKNOWN | 92 个 opaque syscall |
| canneal | 1,007,982 | 3 | 完整、零丢失 | UNKNOWN | 89 个 opaque syscall |
| bodytrack | 12,000,000 | 4 | 达到每线程事件预算 | UNKNOWN | 4 个 resource-limit drop；1,330 个 syscall |
| raytrace | 4,734,913 | 3 | 打印 `Done` 后未退出 | UNKNOWN | 轨迹未完成；201 个 syscall |
| dedup | 5,901,146 | 9 | 完整、零丢失 | UNKNOWN | 169 个 opaque syscall |
| vips | 9,003,495 | 5 | 达到预算，另有不支持映射 | UNKNOWN | 3 个 resource-limit、2 个 unsupported drop；134 个 syscall |

## 可以得出的结论

- 12 个程序均没有得到 `TRACE_SAFE`，也没有得到经复核的
  `COUNTEREXAMPLE`。当前数据不能证明它们可以使用 `mo-off`，也不能证明
  它们必然出错。
- blackscholes、swaptions、freqmine、fluidanimate、streamcluster、canneal
  和 dedup 已得到完整、零丢失轨迹。它们的首要阻塞点是同一个：
  syscall 只有编号，没有参数、返回值和用户缓冲区 effect。
- 证明器在预检发现 opaque syscall 后不构建通信边，因此表中的
  `communication_edge_count=0` 不表示程序没有共享内存。
- freqmine 在 `/mnt/d` 重复出现 4,096 条整块写入缺口，改到 WSL ext4
  后零丢失。大型采集应先写 WSL ext4，分析后再复制证书。
- fluidanimate 的 test 输入产生约 5.97 GiB、1.1178 亿事件。批量
  结构校验用 216.77 秒完成，峰值 RSS 约 45 MiB；分析内存已有界，
  但原始轨迹仍需要采集预算。

## 后续突破进展

全套轨迹的 syscall 集合只包含 0、1、3、9、10、11、12、13、14、20、25、60、
158、202、231、257、302、334 和 435。analyzer 0.4.0 与 client 0.5
已经记录 syscall 的六个原始参数和返回值，并完成第一版严格 effect 分类：

- 串行阶段的 effect 折叠进固定轨迹的初态或末态。
- 并发期只闭合能由参数、返回值和对象生命周期复核的
  `mmap/mprotect/munmap`、线程本地 signal mask、`rseq` 与 `clone3` 等调用。
- `futex`、I/O、`brk`、`mremap` 等尚未建模的并发 effect 继续返回
  `UNKNOWN`，不能凭 syscall 名称放行。

代表性重跑表明 blackscholes 已从 60 个笼统边界缩小到 1 个具体 futex；
swaptions 和 canneal 已通过 syscall 预检并进入通信边分析。当前主要阻塞点
已经变成具体的并发 syscall effect 和过大的通信窗口，详见
`docs/dynamic/09-syscall-effects.md`。

本轮证书保存在 `.bmo-check/parsec-all-test/results/`。该目录是本地实验
产物，不纳入 Git。

## 2026-09-08：client 0.6 与应用范围复核

上一节是历史基线，不能和下面的结果混为一谈。本轮使用当前 client 0.6、
标准 futex wait/wake effect 和显式 `--application-only` 作用域。应用范围只把
主 ELF 的普通访存交给求解器；外部运行库边仍计入原始数量，并由 DBT 的
LOCK/XCHG/Fence contract 承担。它不是整个进程的 `mo-off` 证明。

| 真实 PARSEC 运行 | 事件 | 线程 | 原始边/排除边 | verdict | 分区结果 |
|---|---:|---:|---:|---|---|
| blackscholes，`in_4.txt`，1 worker | 232,627 | 2 | 6 / 6 | `TRACE_SAFE` | safe，0 冲突 |
| blackscholes，`in_4.txt`，2 workers | 234,434 | 3 | 12 / 12 | `TRACE_SAFE` | safe，0 冲突 |
| swaptions，`-ns 1 -sm 5 -nt 1` | 888,875 | 2 | 6 / 6 | `TRACE_SAFE` | safe，0 冲突 |
| swaptions，`-ns 2 -sm 5 -nt 2` | 1,110,828 | 3 | 67 / 67 | `TRACE_SAFE` | safe，0 冲突 |
| canneal，`1 5 100 10.nets 1` | 970,949 | 2 | 6 / 6 | `TRACE_SAFE` | safe，0 冲突 |
| streamcluster，单 worker小输入 | 973,339 | 3 | 0 / 0（未枚举） | `TRACE_SAFE` | safe 分区 + 完整线程交接；外部边由 contract 承担 |

因此当前已经有 6 条完整、零丢失的 `TRACE_SAFE` 运行证书，覆盖
4 个不同的 PARSEC 程序。每条证书仍绑定自己的 trace ID、二进制哈希和实际
命令；它们只能说明这些具体运行的主 ELF 普通通信没有发现 RVWMO 独有执行。

### 资源与失败样本

- streamcluster 的两个 worker 生命周期不重叠时，地址复用不再被误算成并发
  输出冲突；create/start/end/join 交接也完整，因此应用分区充分条件直接给出
  `TRACE_SAFE`。证书将 `communication_edges_complete=false` 写明，运行库边
  没有被枚举，不能把这个结果外推成 full scope 安全。
- fluidanimate（test、1 worker）达到 300 万事件预算并记录 2 个
  `resource_limit` drop；freqmine（1 OpenMP worker）达到 500 万预算并记录
  1 个 drop；dedup（1 worker）在 500 万预算下仍记录 1 个 drop。它们都必须是
  `UNKNOWN`，不能因程序正常退出而放行。
- bodytrack 的一帧串行输入在 1,000 万事件预算下仍有 `resource_limit` drop，
  因此没有把不完整轨迹纳入 SAFE。
- facesim 使用官方 `-lastframe 1 -threads 1` 仍在 180 秒采集预算内未结束；
  默认 `-lastframe 300` 的历史实验已停止，避免写出百 GB 级轨迹。
- ferret 小输入未在采集时间预算内结束，vips 轨迹有不支持 syscall/drop，
  raytrace 的最小一帧运行在 1,000 万事件预算下仍有 `resource_limit` drop，
  均不计入 SAFE。

本节的证书和轨迹仍是本地 `.bmo-check`/WSL 实验产物，不纳入 Git；表中的
统计可由对应 manifest、trace 哈希和 `bmo-check explain` 重新核对。
