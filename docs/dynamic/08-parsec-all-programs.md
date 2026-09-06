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

## 下一个突破点

全套轨迹的 syscall 集合只包含 0、1、3、9、10、11、12、13、14、20、25、60、
158、202、231、257、302、334 和 435。下一阶段应在采集端记录这些
syscall 的必要参数与返回值，然后分三类闭合：

1. 把 `read/write/writev` 的用户缓冲区记为内核读或写的精确字节范围。
2. 把 `futex` 的 `uaddr`、operation 和返回值记入同步事件，不凭
   syscall 名称自动添加排序边。
3. 把 `mmap/mprotect/munmap/mremap/brk`、`clone3/rseq`、signal 和其他进程
   状态 syscall 分别对应到 object generation、线程生命周期或无共享用户内存
   effect。只有参数和返回值匹配支持表时才能移除 `UNKNOWN`。

本轮证书保存在 `.bmo-check/parsec-all-test/results/`。该目录是本地实验
产物，不纳入 Git。
